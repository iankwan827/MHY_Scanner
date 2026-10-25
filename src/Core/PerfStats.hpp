#pragma once

#include <atomic>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <cstdlib>
#include <mutex>
#include <thread>

// ---------------------------------------------------------------------------
// 轻量耗时统计（2026-10-11 DSH 添加；10-24 无锁化；10-26 增加退出补写）
//
// 目的：把直播抢码整条链路的耗时写进 MHY_Scanner_perf.log，用于定位瓶颈。
// 索引：0=打开流  1=DNN识别  2=缩放  3=scan接口  4=confirm接口
//
// 设计要点：
//   1) Add() 处于扫码热路径（每帧识别、每帧缩放都会调用），所以只做原子累加，
//      无锁、无 I/O。旧版在 Add() 里直接 fprintf+fflush，让 8 个识别线程抢锁
//      并频繁写盘，测速度的代码反而拖慢了被测对象。
//   2) 写盘由后台线程每 2 秒做一次，且统计量无变化就不写。
//   3) 「扫码成功后自动退出」时程序会在两秒内 exit(0)，后台线程来不及写，
//      最关键的抢码瞬间数据会丢。进程退出会终止所有线程，所以不能指望后台
//      线程"晚点退"；改为注册 atexit，在退出钩子里同步补写最终汇总。
//   4) 抢码命中（scan/confirm 返回）时主动补写一次，即使被强杀也已落盘。
// ---------------------------------------------------------------------------
struct ScanPerfStats
{
    static constexpr int kSlots = 8;
    static constexpr int kReportIntervalSec = 2;

    std::atomic<long long> totalUs[kSlots];
    std::atomic<long long> counts[kSlots];
    std::atomic<long long> worstUs[kSlots];

    const char* names[kSlots]{
        "open-stream", "decode-DNN", "sws_scale", "api-scan", "api-confirm", "", "", ""
    };

    std::atomic<bool> writerStarted{ false };
    std::atomic<bool> stopping{ false };

    std::mutex writeMtx;          // 后台线程与退出补写之间的互斥
    long long lastWrittenTotal{ 0 };

    ScanPerfStats()
    {
        for (int i = 0; i < kSlots; ++i)
        {
            totalUs[i].store(0, std::memory_order_relaxed);
            counts[i].store(0, std::memory_order_relaxed);
            worstUs[i].store(0, std::memory_order_relaxed);
        }
        // exit(0) 会执行 atexit 钩子：在这里同步补写最终汇总
        std::atexit([]() { ScanPerfStats::Get().FlushNow("程序退出，补写最终汇总"); });
    }

    // 故意堆分配且不释放：后台线程与 atexit 钩子可能在静态析构之后仍访问，
    // 用堆对象避免"访问已析构单例"的未定义行为。
    static ScanPerfStats& Get()
    {
        static ScanPerfStats* inst = new ScanPerfStats();
        return *inst;
    }

    // ---- 热路径 ----------------------------------------------------------
    void Add(const int idx, const long long us) noexcept
    {
        if (idx < 0 || idx >= kSlots)
        {
            return;
        }
        totalUs[idx].fetch_add(us, std::memory_order_relaxed);
        counts[idx].fetch_add(1, std::memory_order_relaxed);

        long long cur = worstUs[idx].load(std::memory_order_relaxed);
        while (us > cur &&
               !worstUs[idx].compare_exchange_weak(cur, us,
                                                   std::memory_order_relaxed,
                                                   std::memory_order_relaxed))
        {
        }

        EnsureWriter();
    }

    void EnsureWriter() noexcept
    {
        bool expected = false;
        if (writerStarted.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        {
            try
            {
                std::thread([this]() { WriterLoop(); }).detach();
            }
            catch (...)
            {
                writerStarted.store(false, std::memory_order_relaxed);
            }
        }
    }

    // ---- 后台线程 --------------------------------------------------------
    void WriterLoop() noexcept
    {
        while (!stopping.load(std::memory_order_relaxed))
        {
            std::this_thread::sleep_for(std::chrono::seconds(kReportIntervalSec));
            ReportIfChanged();
        }
    }

    void ReportIfChanged() noexcept
    {
        std::lock_guard<std::mutex> lk(writeMtx);
        if (CurrentTotal() == lastWrittenTotal)
        {
            return;
        }
        ReportLocked(nullptr);
    }

    // 立即补写一次（忽略"有没有变化"），用于抢码命中与退出前
    void FlushNow(const char* reason = nullptr) noexcept
    {
        std::lock_guard<std::mutex> lk(writeMtx);
        if (CurrentTotal() == 0)
        {
            return;
        }
        ReportLocked(reason);
    }

    long long CurrentTotal() const noexcept
    {
        long long total = 0;
        for (int i = 0; i < kSlots; ++i)
        {
            total += counts[i].load(std::memory_order_relaxed);
        }
        return total;
    }

    void ReportLocked(const char* reason) noexcept
    {
        lastWrittenTotal = CurrentTotal();

        FILE* fp = nullptr;
        if (fopen_s(&fp, "MHY_Scanner_perf.log", "a") != 0 || fp == nullptr)
        {
            return;
        }

        const std::time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        char ts[32]{};
        struct tm tmBuf {};
#ifdef _WIN32
        localtime_s(&tmBuf, &t);
#else
        localtime_r(&t, &tmBuf);
#endif
        std::strftime(ts, sizeof(ts), "%H:%M:%S", &tmBuf);

        std::fprintf(fp, "\n[%s] ---- 耗时汇总 (avg / max / n, 单位 ms) ----%s%s\n", ts,
                     (reason && *reason) ? "  << " : "",
                     (reason && *reason) ? reason : "");
        for (int i = 0; i < kSlots; ++i)
        {
            const long long n = counts[i].load(std::memory_order_relaxed);
            if (n == 0 || names[i][0] == '\0')
            {
                continue;
            }
            const long long tot = totalUs[i].load(std::memory_order_relaxed);
            const long long worst = worstUs[i].load(std::memory_order_relaxed);
            std::fprintf(fp, "  %-14s avg=%.1f  max=%.1f  n=%lld\n", names[i],
                         static_cast<double>(tot) / static_cast<double>(n) / 1000.0,
                         static_cast<double>(worst) / 1000.0, n);
        }
        std::fflush(fp);
        std::fclose(fp);
    }
};

struct ScanPerfTimer
{
    int idx;
    std::chrono::steady_clock::time_point t0;
    explicit ScanPerfTimer(const int i) noexcept :
        idx(i), t0(std::chrono::steady_clock::now())
    {
    }
    ~ScanPerfTimer()
    {
        const auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::steady_clock::now() - t0)
                            .count();
        ScanPerfStats::Get().Add(idx, us);
    }
    ScanPerfTimer(const ScanPerfTimer&) = delete;
    ScanPerfTimer& operator=(const ScanPerfTimer&) = delete;
};
