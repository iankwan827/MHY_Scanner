#include "QRCodeForStream.h"

#include <string>
#include <string_view>
#include <chrono>   // std::chrono::milliseconds（2026-10-11 DSH 修改）
#include <thread>   // std::this_thread::sleep_for（2026-10-11 DSH 修改）

#include "QRScanner.h"
#include "MhyApi.hpp"

QRCodeForStream::QRCodeForStream(QObject* parent) :
    QThread(parent),
    pAvdictionary(nullptr),
    pAVFormatContext(nullptr),
    pSwsContext(nullptr),
    pAVFrame(nullptr),
    pAVPacket(nullptr),
    pAVCodecContext(nullptr),
    m_stop(false),
    servertype(ServerType::Official)

{
    av_log_set_level(AV_LOG_FATAL);
    m_config = &(ConfigDate::getInstance());
}

QRCodeForStream::~QRCodeForStream()
{
    if (!this->isInterruptionRequested())
    {
        m_stop.store(false);
    }
    this->requestInterruption();
    this->wait();
}

void QRCodeForStream::setLoginInfo(const std::string_view uid, const std::string_view gameToken)
{
    this->uid = uid;
    this->gameToken = gameToken;
}

void QRCodeForStream::setLoginInfo(const std::string_view uid, const std::string_view gameToken, const std::string& name)
{
    this->uid = uid;
    this->gameToken = gameToken;
    this->m_name = name;
}

void QRCodeForStream::setServerType(const ServerType servertype)
{
    this->servertype = servertype;
}

// 官服新版登录需要 stoken + mid（passport-api 的 Cookie 认证）
// 2026-10-26 DSH 添加
void QRCodeForStream::setPassportInfo(const std::string_view stoken, const std::string_view mid)
{
    this->stoken = stoken;
    this->mid = mid;
}

void QRCodeForStream::LoginOfficial()
{
    while (m_stop.load())
    {
        if (av_read_frame(pAVFormatContext, pAVPacket) < 0)
        {
            ret = ScanRet::LIVESTOP;
            break;
        }
        if (pAVPacket->stream_index != videoStreamIndex)
        {
            continue;
        }
        avcodec_send_packet(pAVCodecContext, pAVPacket);
        if (pAVFrame == nullptr)
        {
            std::cerr << "Error allocating frame" << std::endl;
            ret = ScanRet::LIVESTOP;
            break;
        }
        while (avcodec_receive_frame(pAVCodecContext, pAVFrame) == 0)
        {
            cv::Mat img(videoStreamHeight, videoStreamWidth, CV_8UC3);
            uint8_t* dstData[1] = { img.data };
            const int dstLinesize[1] = { static_cast<int>(img.step) };
            {
                // 计时：色彩转换 + 缩放（2026-10-11 DSH 修改）
                const ScanPerfTimer _tScale(2);
                sws_scale(pSwsContext, pAVFrame->data, pAVFrame->linesize, 0, pAVFrame->height,
                          dstData, dstLinesize);
            }
#ifndef SHOW
            cv::imshow("Video_Stream", img);
            cv::waitKey(1);
#endif
            threadPool.tryStart([&, img = std::move(img)]() {
                thread_local QRScanner qrScanners;
                std::string str;
                qrScanners.decodeSingle(img, str);
                if (str.size() < 85)
                {
                    // 还没看到码：趁等待期预热扫码接口的连接（每线程 40 秒一次）。
                    // 真码出现时 DNS+TCP+TLS 已经建好，可直接发请求。
                    // 2026-10-25 DSH 添加
                    WarmupScanConnectionThrottled();
                    return;
                }
                std::string_view view(str.c_str() + 79, 3);
                if (!setGameType.contains(view))
                {
                    return;
                }
                const std::string_view ticket(str.data() + str.size() - 24, 24);
                setGameType[view]();
                // 流程日志起点（2026-10-26 DSH 添加）
                LogFlow("[detect] game=" + std::string(view) +
                        " ticket=" + std::string(ticket.substr(0, 8)) + "…");
                if (lastTicket == ticket)
                {
                    return;
                }
                if (mtx.try_lock())
                {
                    if (!m_stop.load())
                    {
                        mtx.unlock();
                        return;
                    }
                    if (lastTicket == ticket)
                    {
                        mtx.unlock();
                        return;
                    }
                    // 新版三段式登录（2026-10-26 DSH 改造）：
                    //   Step 1 游戏 API scan（带 passport_app_id）→ 拿到 passport_qr_url
                    //   Step 2 passport scanQRLogin → 确认目标账号
                    //   Step 3 passport confirmQRLogin（在 continueLastLogin 里）
                    // 旧的"游戏 API confirm"虽然返回 retcode=0，但无法让游戏真正登录。
                    std::string passportQrUrl = PandaScanQRCode(scanUrl, ticket, gameType);
                    for (int attempt = 1; attempt < 3 && passportQrUrl.empty(); ++attempt)
                    {
                        std::this_thread::sleep_for(std::chrono::milliseconds(80));
                        passportQrUrl = PandaScanQRCode(scanUrl, ticket, gameType);
                    }
                    bool ok = !passportQrUrl.empty();
                    if (ok)
                    {
                        lastTicket = ticket;
                        m_passportQrUrl = passportQrUrl;
                        // Step 2：passport 扫描，确认要登录哪个账号
                        if (!ScanPassportQRLogin(m_passportQrUrl, stoken, mid))
                        {
                            Q_EMIT loginResults(ScanRet::FAILURE_1);
                            stop();
                            mtx.unlock();
                            return;
                        }
                        nlohmann::json config = nlohmann::json::parse(m_config->getConfig(), nullptr, false);
                        if (config.is_discarded())
                        {
                            Q_EMIT loginResults(ScanRet::FAILURE_1);
                        }
                        else if (config.value("auto_login", false))
                        {
                            continueLastLogin();
                        }
                        else
                        {
                            Q_EMIT loginConfirm(gameType, false);
                        }
                    }
                    else
                    {
                        Q_EMIT loginResults(ScanRet::FAILURE_1);
                    }
                    stop();
                    mtx.unlock();
                }
            });
        }
        av_frame_unref(pAVFrame);
        av_packet_unref(pAVPacket);
    }
}

void QRCodeForStream::LoginBH3BiliBili()
{
    while (m_stop.load())
    {
        if (av_read_frame(pAVFormatContext, pAVPacket) < 0)
        {
            ret = ScanRet::LIVESTOP;
            break;
        }
        if (pAVPacket->stream_index != videoStreamIndex)
        {
            continue;
        }
        avcodec_send_packet(pAVCodecContext, pAVPacket);
        if (pAVFrame == nullptr)
        {
            std::cerr << "Error allocating frame" << std::endl;
            ret = ScanRet::LIVESTOP;
            break;
        }

        while (avcodec_receive_frame(pAVCodecContext, pAVFrame) == 0)
        {
            cv::Mat img(videoStreamHeight, videoStreamWidth, CV_8UC3);
            uint8_t* dstData[1] = { img.data };
            const int dstLinesize[1] = { static_cast<int>(img.step) };
            {
                // 计时：色彩转换 + 缩放（2026-10-11 DSH 修改）
                const ScanPerfTimer _tScale(2);
                sws_scale(pSwsContext, pAVFrame->data, pAVFrame->linesize, 0, pAVFrame->height,
                          dstData, dstLinesize);
            }
#ifndef SHOW
            cv::imshow("Video_Stream", img);
            cv::waitKey(1);
#endif
            threadPool.tryStart([&, img = std::move(img)]() {
                thread_local QRScanner qrScanners;
                std::string str;
                qrScanners.decodeSingle(img, str);
                if (str.size() < 85)
                {
                    // 还没看到码：趁等待期预热扫码接口的连接（每线程 40 秒一次）。
                    // 真码出现时 DNS+TCP+TLS 已经建好，可直接发请求。
                    // 2026-10-25 DSH 添加
                    WarmupScanConnectionThrottled();
                    return;
                }
                if (std::string_view view(str.c_str() + 79, 3); view != "8F3")
                {
                    return;
                }
                const std::string& ticket = str.substr(str.length() - 24);
                if (lastTicket == ticket)
                {
                    return;
                }
                if (mtx.try_lock())
                {
                    if (!m_stop.load())
                    {
                        mtx.unlock();
                        return;
                    }
                    if (lastTicket == ticket)
                    {
                        mtx.unlock();
                        return;
                    }
                    // 同 LoginOfficial：B服抢码失败也允许一次快速重试，避免偶发失败即放弃。
                    // 2026-10-11 DSH 修改
                    ret = scanCheck(ticket);
                    if (ret != ScanRet::SUCCESS)
                    {
                        for (int attempt = 1; attempt < 5 && ret != ScanRet::SUCCESS; ++attempt)
                        {
                            std::this_thread::sleep_for(std::chrono::milliseconds(80));
                            ret = scanCheck(ticket);
                        }
                    }
                    if (ret == ScanRet::SUCCESS)
                    {
                        lastTicket = ticket;
                        nlohmann::json config = nlohmann::json::parse(m_config->getConfig(), nullptr, false);
                        if (config.is_discarded())
                        {
                            Q_EMIT loginResults(ScanRet::FAILURE_1);
                        }
                        else if (config.value("auto_login", false))
                        {
                            continueLastLogin();
                        }
                        else
                        {
                            Q_EMIT loginConfirm(GameType::Honkai3_BiliBili, false);
                        }
                    }
                    else
                    {
                        Q_EMIT loginResults(ret);
                    }
                    stop();
                    mtx.unlock();
                }
            });
        }
        av_frame_unref(pAVFrame);
        av_packet_unref(pAVPacket);
    }
}

void QRCodeForStream::setStreamHW()
{
    if (pAVCodecContext->width < pAVCodecContext->height ||
        pAVCodecContext->height == 480 ||
        pAVCodecContext->height == 720)
    {
        videoStreamWidth = pAVCodecContext->width;
        videoStreamHeight = pAVCodecContext->height;
    }
    else
    {
        videoStreamWidth = pAVCodecContext->width / 1.5;
        videoStreamHeight = pAVCodecContext->height / 1.5;
    }
}

void QRCodeForStream::stop()
{
    m_stop.store(false);
}

void QRCodeForStream::setUrl(const std::string& url, const std::map<std::string, std::string> heard)
{
    streamUrl = url;
    for (const auto& it : heard)
    {
        av_dict_set(&pAvdictionary, it.first.c_str(), it.second.c_str(), 0);
    }
    av_dict_set(&pAvdictionary, "max_delay", "0", 0);
    av_dict_set(&pAvdictionary, "probesize", "1024", 0);
    av_dict_set(&pAvdictionary, "packetsize", "128", 0);
    av_dict_set(&pAvdictionary, "rtbufsize", "0", 0);
    av_dict_set(&pAvdictionary, "delay", "0", 0);
    av_dict_set(&pAvdictionary, "buffer_size", "1000", 0);
}

auto QRCodeForStream::init() -> bool
{
    // 计时：打开直播流 + 探测流信息的耗时（2026-10-11 DSH 修改）
    const ScanPerfTimer _tOpenStream(0);
    pAVFormatContext = avformat_alloc_context();
    if (avformat_open_input(&pAVFormatContext, streamUrl.c_str(), NULL, &pAvdictionary) != 0)
    {
        std::cerr << "Error opening input file" << std::endl;
        return false;
    }
    if (avformat_find_stream_info(pAVFormatContext, NULL) < 0)
    {
        std::cerr << "Error finding stream information" << std::endl;
        return false;
    }
    AVStream* videoStream = nullptr;
    for (int i = 0; i < pAVFormatContext->nb_streams; i++)
    {
        if (pAVFormatContext->streams[i]->codecpar->codec_type == AVMEDIA_TYPE_VIDEO)
        {
            videoStream = pAVFormatContext->streams[i];
            break;
        }
    }
    if (videoStream == nullptr)
    {
        std::cerr << "No video stream found" << std::endl;
        return false;
    }
    videoStreamIndex = videoStream->index;
    const AVCodec* decoder{ avcodec_find_decoder(videoStream->codecpar->codec_id) };
    if (decoder == nullptr)
    {
        std::cerr << "Codec not found" << std::endl;
        return false;
    }
    pAVCodecContext = avcodec_alloc_context3(decoder);
    avcodec_parameters_to_context(pAVCodecContext, videoStream->codecpar);
    if (avcodec_open2(pAVCodecContext, decoder, NULL) < 0)
    {
        std::cerr << "Error opening codec" << std::endl;
        return false;
    }
    setStreamHW();
    pSwsContext = sws_getContext(
        pAVCodecContext->width, pAVCodecContext->height, pAVCodecContext->pix_fmt,
        videoStreamWidth, videoStreamHeight, AV_PIX_FMT_BGR24, SWS_BILINEAR, NULL, NULL, NULL);
    pAVPacket = av_packet_alloc();
    pAVFrame = av_frame_alloc();
    return true;
}

void QRCodeForStream::continueLastLogin()
{
    switch (servertype)
    {
        using enum ServerType;
    case Official:
    {
        // Step 3：passport 确认 —— 这一步才真正让游戏端登录成功。
        // 旧的 ConfirmQRLogin(游戏 API) 返回 0 但无效，已弃用。
        // 2026-10-26 DSH 修改
        bool b = ConfirmPassportQRLogin(m_passportQrUrl, stoken, mid);
        if (b)
        {
            Q_EMIT loginResults(ScanRet::SUCCESS);
        }
        else
        {
            Q_EMIT loginResults(ScanRet::FAILURE_2);
        }
    }
    break;
    case BH3_BiliBili:
    {
        ret = scanConfirm(lastTicket, uid, gameToken, m_name);
        Q_EMIT loginResults(ret);
    }
    break;
    default:
        break;
    }
}

void QRCodeForStream::run()
{
    threadPool.setMaxThreadCount(threadNumber);
    m_stop.store(true);
    ret = ScanRet::UNKNOW;
    //TODO 获取直播流地址放在这里
    if (init())
    {
#ifndef SHOW
        cv::namedWindow("Video_Stream", cv::WINDOW_AUTOSIZE);
        cv::resizeWindow("Video_Stream", videoStreamWidth / 2, videoStreamHeight / 2);
#endif
        switch (servertype)
        {
            using enum ServerType;
        case Official:
            LoginOfficial();
            break;
        case BH3_BiliBili:
            LoginBH3BiliBili();
            break;
        default:
            break;
        }
    }
    if (ret == ScanRet::LIVESTOP)
    {
        emit loginResults(ret);
    }
#ifndef SHOW
    cv::destroyWindow("Video_Stream");
#endif
    avformat_close_input(&pAVFormatContext);
    avcodec_free_context(&pAVCodecContext);
    sws_freeContext(pSwsContext);
    av_dict_free(&pAvdictionary);
    av_frame_free(&pAVFrame);
    av_packet_free(&pAVPacket);
    pAVFormatContext = nullptr;
    pAVCodecContext = nullptr;
    pSwsContext = nullptr;
    pAvdictionary = nullptr;
    pAVFrame = nullptr;
    pAVPacket = nullptr;
}