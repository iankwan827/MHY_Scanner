#pragma once

#include <chrono>
#include <cstdio>
#include <ctime>
#include <mutex>

// ---------------------------------------------------------------------------
// 轻量耗时统计（2026-10-11 DSH 添加）
//
// 目的：把直播抢码整条链路的耗时写进 MHY_Scanner_perf.log，用于定位瓶颈。
// 用法：PERF_SCOPE(索引) —— 作用域结束自动累计；每 200 次采样输出一行汇总。
// 索引：0=打开流  1=DNN识别  2=缩放  3=scan接口  4=confirm接口
// ---------------------------------------------------------------------------
struct ScanPerfStats
{
    struct Item
    {
        long long totalUs{ 0 };
        long long count{ 0 };
        long long worstUs{ 0 };
    };

    std::mutex mtx;
    Item items[8]{};
    const char* names[8]{ "open-stream", "decode-DNN", "sws_scale", "api-scan", "api-confirm", "", "", "" };
    long long reported{ 0 };
    FILE* fp{ nullptr };

    static ScanPerfStats& Get()
    {
        static ScanPerfStats inst;
        return inst;
    }

    void Report()
    {
        if (fp == nullptr)
        {
            fp = std::fopen("MHY_Scanner_perf.log", "a");
            if (fp == nullptr)
            {
                return;
            }
        }
        const std::time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        char ts[32]{};
        std::strftime(ts, sizeof(ts), "%H:%M:%S", std::localtime(&t));
        std::fprintf(fp, "\n[%s] ---- 耗时汇总 (avg / max / n, 单位 ms) ----\n", ts);
        for (int i = 0; i < 8; ++i)
        {
            if (items[i].count == 0 || names[i][0] == '\0')
            {
                continue;
            }
            std::fprintf(fp, "  %-14s avg=%.1f  max=%.1f  n=%lld\n", names[i],
                         static_cast<double>(items[i].totalUs) / static_cast<double>(items[i].count) / 1000.0,
                         static_cast<double>(items[i].worstUs) / 1000.0, items[i].count);
        }
        std::fflush(fp);
    }

    void Add(const int idx, const long long us)
    {
        std::lock_guard<std::mutex> lk(mtx);
        if (idx < 0 || idx >= 8)
        {
            return;
        }
        items[idx].totalUs += us;
        items[idx].count += 1;
        if (us > items[idx].worstUs)
        {
            items[idx].worstUs = us;
        }
        long long total = 0;
        for (const auto& it : items)
        {
            total += it.count;
        }
        if (total - reported >= 200)
        {
            reported = total;
            Report();
        }
    }
};

struct ScanPerfTimer
{
    int idx;
    std::chrono::steady_clock::time_point t0;
    explicit ScanPerfTimer(const int i) :
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
