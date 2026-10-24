#pragma once

#include <atomic>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <thread>

// ---------------------------------------------------------------------------
// 轻量耗时统计（2026-10-11 DSH 添加；2026-10-24 改为无锁 + 后台线程写盘）
//
// 目的：把直播抢码整条链路的耗时写进 MHY_Scanner_perf.log，用于定位瓶颈。
// 索引：0=打开流  1=DNN识别  2=缩放  3=scan接口  4=confirm接口
//
// 设计要点（原实现的问题与修正）：
//   旧版在 Add() 里直接 fprintf + fflush，而 Add() 处于扫码热路径
//   （每帧识别、每帧缩放都会调用），导致每帧两次磁盘 I/O 并争抢互斥锁，
//   8 个识别线程互相等待 —— 为"测速度"加的代码反过来拖慢被测对象。
//
//   现在：Add() 只做三次原子累加（无锁、无 I/O、纳秒级），
//   另起一个后台线程每 2 秒快照一次写盘；只有统计量发生变化才写，
//   因此扫码期间热路径开销可以忽略，日志也不会无意义地膨胀。
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
    long long lastWrittenTotal{ 0 };   // 仅后台线程访问

    ScanPerfStats()
    {
        for (int i = 0; i < kSlots; ++i)
        {
            totalUs[i].store(0, std::memory_order_relaxed);
            counts[i].store(0, std::memory_order_relaxed);
            worstUs[i].store(0, std::memory_order_relaxed);
        }
    }

    // 故意用堆分配且不释放：后台线程的生命周期不受静态析构影响，
    // 避免"程序退出时线程仍持有已析构的单例"这类未定义行为。
    static ScanPerfStats& Get()
    {
        static ScanPerfStats* inst = new ScanPerfStats();
        return *inst;
    }

    // ---- 热路径 ----------------------------------------------------------
    // 只有原子操作：无锁、无系统调用。8 线程并发也只是一些缓存行竞争。
    void Add(const int idx, const long long us) noexcept
    {
        if (idx < 0 || idx >= kSlots)
        {
            return;
        }
        totalUs[idx].fetch_add(us, std::memory_order_relaxed);
        counts[idx].fetch_add(1, std::memory_order_relaxed);

        // 记录最大值：CAS 循环，通常一次成功
        long long cur = worstUs[idx].load(std::memory_order_relaxed);
        while (us > cur &&
               !worstUs[idx].compare_exchange_weak(cur, us,
                                                   std::memory_order_relaxed,
                                                   std::memory_order_relaxed))
        {
        }

        EnsureWriter();
    }

    // 首次采样时启动后台写盘线程（call_once 语义由原子标志实现）
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
                // 线程创建失败：退化为不统计，绝不影响主功能
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

    // 只有后台线程调用，天然互斥，不需要锁
    void ReportIfChanged() noexcept
    {
        long long total = 0;
        for (int i = 0; i < kSlots; ++i)
        {
            total += counts[i].load(std::memory_order_relaxed);
        }
        if (total == lastWrittenTotal)
        {
            return;   // 这段时间没有任何采样，不写
        }
        lastWrittenTotal = total;
        Report();
    }

    void Report() noexcept
    {
        FILE* fp = nullptr;
        // 用 fopen_s：项目在 MSVC 下启用 /sdl，C4996 会被当作错误
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

        std::fprintf(fp, "\n[%s] ---- 耗时汇总 (avg / max / n, 单位 ms) ----\n", ts);
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
