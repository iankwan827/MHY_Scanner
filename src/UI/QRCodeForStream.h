#pragma once

#include <atomic>
#include <string_view>
#include <thread>   // std::thread::hardware_concurrency（2026-10-11 DSH 修改）
#include <mutex>    // std::mutex（2026-10-11 DSH 修改）

extern "C"
{
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavutil/imgutils.h>
#include <libavutil/time.h>
#include <libswscale/swscale.h>
};

#include <QThread>
#include <QMutex>
#include <QtConcurrent/QtConcurrent>
#include <QFuture>
#include <QThreadPool>

#include "ApiDefs.hpp"
#include "ConfigDate.h"
#include "ScannerBase.hpp"

class QRCodeForStream final :
    public QThread,
    public ScannerBase
{
    Q_OBJECT
public:
    QRCodeForStream(QObject* parent = nullptr);
    ~QRCodeForStream();
    Q_DISABLE_COPY_MOVE(QRCodeForStream)

    void setLoginInfo(const std::string_view uid, const std::string_view gameToken);
    void setLoginInfo(const std::string_view uid, const std::string_view gameToken, const std::string& name);
    // 官服新版三段式登录所需（2026-10-26 DSH 添加）
    void setPassportInfo(const std::string_view stoken, const std::string_view mid);
    void setServerType(const ServerType servertype);
    void setUrl(const std::string& url, const std::map<std::string, std::string> heard = {});
    auto init() -> bool;
    void run();
    void stop();
    void continueLastLogin();

Q_SIGNALS:
    void loginResults(const ScanRet ret);
    void loginConfirm(const GameType gameType, bool b);

private:
    std::mutex mtx;
    void LoginOfficial();
    void LoginBH3BiliBili();
    void setStreamHW();
    std::string streamUrl{};
    std::string m_name;
    ConfigDate* m_config;
    ServerType servertype;
    ScanRet ret = ScanRet::UNKNOW;
    AVDictionary* pAvdictionary;
    AVFormatContext* pAVFormatContext;
    AVCodecContext* pAVCodecContext;
    SwsContext* pSwsContext;
    AVFrame* pAVFrame;
    AVPacket* pAVPacket;
    int videoStreamIndex{ 0 };
    int videoStreamWidth{};
    int videoStreamHeight{};
    // 原值为固定 2 线程。直播流常为 1080p/60~70fps，每帧需 sws_scale + WeChatQRCode
    // DNN 推理，2 个线程远跟不上，配合 tryStart（队列满即丢帧）会导致画面严重滞后，
    // 抢码时"看到二维码"的时刻远晚于竞品。
    // 改为按 CPU 核心数动态设置，上限 8，避免过多线程导致推理互相抢占。
    // 2026-10-11 DSH 修改
    const int threadNumber{ []() {
        const unsigned hw = std::thread::hardware_concurrency();
        const int n = (hw == 0) ? 4 : static_cast<int>(hw);
        return (n < 4) ? 4 : ((n > 8) ? 8 : n);
    }() };
    QThreadPool threadPool;
    std::atomic<bool> m_stop;
};