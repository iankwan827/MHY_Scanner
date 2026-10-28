#pragma once

#include <string>
#include <string_view>
#include <format>
#include <random>
#include <sstream>
#include <optional>
#include <iostream>
#include <chrono>   // cpr::Timeout 需要（2026-10-11 DSH 修改）
#include <cstdio>   // fopen_s/fprintf 诊断日志（2026-10-14 DSH 修改）
#include <vector>   // Cookie 候选列表（2026-10-26 DSH 修改)
#include <mutex>   // LogDetectOnce 去重（2026-10-28 DSH 修改）
#include <ctime>    // 流程日志时间戳（2026-10-26 DSH 修改）

#include <nlohmann/json.hpp>
#include <cpr/cpr.h>

#include "ApiDefs.hpp"
#include "CreateUUID.hpp"
#include "CryptoKit.h"
#include "UtilString.hpp"
#include "TimeStamp.hpp"
#include "PerfStats.hpp"   // 耗时统计（2026-10-11 DSH 修改）

static const std::string device_id{ CreateUUID::CreateUUID4() };
static GameType loginType{ GameType::TearsOfThemis };

[[nodiscard]] inline std::string DataSignAlgorithmVersionGen1()
{
    return "";
}

[[nodiscard]] inline std::string DataSignAlgorithmVersionGen2(const std::string_view body, const std::string_view query)
{
    const std::string time_now{ std::to_string(GetUnixTimeStampSeconds()) };
    std::random_device rd{};
    std::mt19937 gen{ rd() };
    int lower_bound{ 100001 };
    int upper_bound{ 200000 };
    std::uniform_int_distribution<int> dist(lower_bound, upper_bound);
    const std::string rand{ std::to_string(dist(gen)) };
    std::string m{ "salt=" + std::string(mihoyobbs_salt_x6) + "&t=" + time_now + "&r=" + rand + "&b=" + std::string(body) + "&q=" + std::string(query) };
    return time_now + "," + rand + "," + Md5(m);
}

inline std::string Encrypt(const std::string_view source)
{
    static constinit const char* PublicKey{
        "-----BEGIN PUBLIC KEY-----\n"
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDDvekdPMHN3AYhm/vktJT+YJr7"
        "cI5DcsNKqdsx5DZX0gDuWFuIjzdwButrIYPNmRJ1G8ybDIF7oDW2eEpm5sMbL9zs"
        "9ExXCdvqrn51qELbqj0XxtMTIpaCHFSI50PfPpTFV9Xt/hmyVwokoOXFlAEgCn+Q"
        "CgGs52bFoYMtyi+xEQIDAQAB\n"
        "-----END PUBLIC KEY-----"
    };
    return rsaEncrypt(source.data(), PublicKey);
}

inline cpr::Header GetRequestHeader()
{
    static cpr::Header headers{
        { "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) miHoYoBBS/2.76.1" },
        { "Accept", "application/json" },
        { "x-rpc-app_id", "bll8iq97cem8" },
        { "x-rpc-app_version", "2.76.1" },
        { "x-rpc-client_type", "2" },
        { "x-rpc-device_id", device_id },
        { "x-rpc-device_name", "" },
        { "x-rpc-game_biz", "bbs_cn" },
        { "x-rpc-sdk_version", "2.16.0" }
    };
    return headers;
}

inline std::string GetLoginQrcodeUrl(const GameType type = loginType)
{
    auto res = cpr::Post(
        cpr::Url{ api::mhy::hk4e::qrcode_fetch },
        cpr::Body{ nlohmann::json{
            { "app_id", static_cast<int>(type) },
            { "device", device_id } }
                       .dump() },
        cpr::Header{ { "Content-Type", "application/json" } });

    auto data = nlohmann::json::parse(res.text);
    std::string qrcodeUrl = data["data"]["url"].get<std::string>();
    return qrcodeUrl;
}

inline std::tuple<LoginQRCodeState, std::string, std::string> GetQRCodeState(
    const std::string_view ticket,
    const GameType type = loginType)
{
    const auto response = cpr::Post(
        cpr::Url{ api::mhy::hk4e::qrcode_query },
        cpr::Body{ nlohmann::json{
            { "app_id", static_cast<int>(type) },
            { "device", device_id },
            { "ticket", ticket } }
                       .dump() },
        cpr::Header{ { "Content-Type", "application/json" } });

    const auto data = nlohmann::json::parse(response.text);

    if (data.value("retcode", -1) != 0)
        return { LoginQRCodeState::Expired, {}, {} };

    static const std::unordered_map<std::string, LoginQRCodeState> stateMap{
        { "Init", LoginQRCodeState::Init },
        { "Scanned", LoginQRCodeState::Scanned },
        { "Confirmed", LoginQRCodeState::Confirmed },
    };

    const auto stat = data["data"]["stat"].get<std::string>();
    const auto it = stateMap.find(stat);

    if (it == stateMap.end())
        return { LoginQRCodeState::Expired, {}, {} };

    if (it->second == LoginQRCodeState::Confirmed)
    {
        const auto payload = nlohmann::json::parse(
            data["data"]["payload"]["raw"].get<std::string>());
        return { LoginQRCodeState::Confirmed,
                 payload["uid"].get<std::string>(),
                 payload["token"].get<std::string>() };
    }

    return { it->second, {}, {} };
}

inline std::string getMysUserName(const std::string_view uid)
{
    static constexpr std::string_view url = api::mhy::mys::userinfo;
    const auto response = cpr::Get(
        cpr::Url{ std::format("{}?uid={}", url, uid) });

    const auto data = nlohmann::json::parse(response.text);
    return data["data"]["user_info"]["nickname"].get<std::string>();
}

inline std::tuple<int, std::string, std::string> GetStokenByGameToken(
    const std::string_view uid,
    const std::string_view game_token)
{
    const auto response = cpr::Post(
        cpr::Url{ api::mhy::takumi::game_token_stoken },
        cpr::Body{ nlohmann::json{ { "account_id", std::stoi(uid.data()) }, { "game_token", game_token } }.dump() },
        GetRequestHeader());

    const auto j = nlohmann::json::parse(response.text);
    const int retcode = j.value("retcode", -1);

    if (retcode != 0)
        return { retcode, {}, {} };

    return { 0,
             j["data"]["user_info"]["mid"].get<std::string>(),
             j["data"]["token"]["token"].get<std::string>() };
}

// SToken -> Cookie Token
//
// 2026-10-14 DSH 修正：原实现用 GET /auth/api/getGameToken 传 stoken+mid，
// 该接口对 v2 SToken（形如 v2_xxx.CAE=）返回 retcode=-1
// "decode err response body error: unexpected end of JSON input"，
// 导致「点开启监控 → 弹登录状态失效」，真实原因被掩盖。
//
// 正确接口：GET /auth/api/getCookieAccountInfoBySToken
//   参数 stoken(str) + mid(str)     ← 实测必须用 mid
//   返回 data{ uid, cookie_token }
//
// 实测（2026-10-14，两个真实账号）：
//   cookie_by_stoken + stoken+mid -> retcode=0  data=[uid, cookie_token]  ✅
//   cookie_by_stoken + stoken+uid -> retcode=-100 登录状态失效            ❌
//   game_token       + stoken+mid -> retcode=-1   decode err              ❌
// 注意：官方文档写的是 uid，但实测传 uid 会被判定登录失效，必须以 mid 传参。
inline std::tuple<int, std::string> GetCookieTokenByStoken(
    const std::string_view stoken,
    const std::string_view mid)
{
    const auto response = cpr::Get(
        cpr::Url{ api::mhy::takumi::cookie_by_stoken },
        cpr::Parameters{
            { "stoken", stoken.data() },
            { "mid", mid.data() } },
        cpr::Header{ { "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) miHoYoBBS/2.76.1" } },
        cpr::Timeout{ std::chrono::milliseconds(15000) },
        cpr::ConnectTimeout{ std::chrono::milliseconds(5000) });

    // 诊断日志（2026-10-14 DSH）：把服务器的真实返回写进文件。
    {
        FILE* fp = nullptr;
        if (fopen_s(&fp, "MHY_token_error.log", "a") == 0 && fp != nullptr)
        {
            std::fprintf(fp,
                         "status=%ld  curl_code=%d  text_len=%zu\n  text=[%s]\n  stoken_len=%zu  mid=[%s]\n\n",
                         static_cast<long>(response.status_code),
                         static_cast<int>(response.error.code),
                         response.text.size(),
                         response.text.substr(0, 500).c_str(),
                         stoken.size(),
                         mid.data());
            std::fclose(fp);
        }
    }

    const auto j = nlohmann::json::parse(response.text, nullptr, false);
    if (j.is_discarded())
    {
        return { -999, {} };   // 响应不是 JSON（空响应/超时/被拦），单独标记
    }
    const int retcode = j.value("retcode", -1);

    if (retcode != 0)
        return { retcode, {} };

    if (!j.contains("data") || !j["data"].is_object() || !j["data"].contains("cookie_token"))
    {
        return { -998, {} };   // 结构不符
    }
    return { 0, j["data"]["cookie_token"].get<std::string>() };
}

// 兼容旧调用名（新代码请用 GetCookieTokenByStoken）
inline std::tuple<int, std::string> GetGameTokenByStoken(
    const std::string_view stoken,
    const std::string_view mid)
{
    return GetCookieTokenByStoken(stoken, mid);
}

inline std::tuple<int, GeetestData> CreateLoginCaptcha(
    const std::string_view mobile,
    const std::string_view aigis = "")
{
    const std::string body{ nlohmann::json{
        { "area_code", Encrypt("+86") },
        { "mobile", Encrypt(mobile) } }
                                .dump() };
    cpr::Header reqHeaders{ GetRequestHeader() };
    reqHeaders["DS"] = DataSignAlgorithmVersionGen2(body, "");
    if (!aigis.empty())
        reqHeaders["X-Rpc-Aigis"] = aigis;
    const auto response = cpr::Post(
        cpr::Url{ api::mhy::passport::login_by_mobile_captcha },
        cpr::Body{ body },
        cpr::Header{ reqHeaders });

    const auto j = nlohmann::json::parse(response.text);
    const int retcode = j.value("retcode", -1);
    GeetestData result{};
    if (retcode == 0)
    {
        result.action_type = j["data"]["action_type"].get<std::string>();
        return { retcode, result };
    }
    if (retcode == -3101)
    {
        const auto it = response.header.find("X-Rpc-Aigis");
        if (it != response.header.end())
        {
            const auto aigisJson = nlohmann::json::parse(it->second);
            const auto captchaJson = nlohmann::json::parse(aigisJson["data"].get<std::string>());

            result.session_id = aigisJson["session_id"].get<std::string>();
            result.mmt_type = aigisJson["mmt_type"].get<int>();
            result.gt = captchaJson["gt"].get<std::string>();
            result.challenge = captchaJson["challenge"].get<std::string>();
            result.GeeTestType = ServerType::Official;
        }
    }
    return { retcode, result };
}

inline auto LoginByMobileCaptcha(const std::string_view actionType, const std::string_view mobile, const std::string_view captcha, const std::string_view aigis = "")
{
    struct
    {
        int retcode{};
        struct
        {
            std::string V2Token{};
            std::string aid{};
            std::string mid{};
        } data;
    } result;
#if 0
	const std::string RequestBody{ std::format(R"({{"area_code":"{}","action_type":"{}","captcha":"{}","mobile":"{}"}})", Encrypt("+86"), actionType, captcha, Encrypt(mobile)) };
    std::map<std::string, std::string> headers{ GetRequestHeader() };
    headers["DS"] = DataSignAlgorithmVersionGen2(RequestBody, "");
    if (!aigis.empty())
    {
        headers["X-Rpc-Aigis"] = aigis;
    }
    HttpClient h;
    std::string s;
    h.PostRequest(s, URL_LoginByMobileCaptcha, RequestBody, headers);
    //std::cout << s << std::endl;
    json::Json j{};
    j.parse(s);
    result.retcode = j["retcode"];
    if (result.retcode == -3205)
    {
        return result;
    }
    else if (result.retcode == 0)
    {
        result.data.V2Token = j["data"]["token"]["token"];
        result.data.aid = j["data"]["user_info"]["aid"];
        result.data.mid = j["data"]["user_info"]["mid"];
    }
#endif
    return result;
}

// ---- 扫码接口连接复用（2026-10-25 DSH 添加）-------------------------------
//
// 实测每次抢码调用都是全新连接，分段耗时：
//   DNS ~180ms + TCP ~35ms + TLS ~155ms + 真正请求 ~100ms
// 其中约 370ms 纯粹是建连开销，而抢码是毫秒级竞争，这段必须省掉。
//
// 做法：每个工作线程持有一个 cpr::Session（thread_local），
// curl 会在会话内复用已建立的 TCP+TLS 连接；再在"还没看到码"的空闲期
// 周期性预热，让码出现的那一刻连接已经就绪。
//
// 注：连接复用按 scheme+host+port 匹配，与路径无关，所以预热用主机根地址
// 即可（scanUrl 要等首次识别出码才被赋值，不能依赖它）。
constexpr std::string_view kScanWarmupUrl{ "https://api-sdk.mihoyo.com/" };
// 三段式流程第 2、3 步走 passport-api，同样需要预热
constexpr std::string_view kPassportWarmupUrl{ "https://passport-api.mihoyo.com/" };

inline cpr::Session& ThreadScanSession()
{
    thread_local cpr::Session session;
    return session;
}

// 按主机分配 curl 句柄（2026-10-28 DSH 添加）
//
// curl 会在【同一个 easy handle】内对属于同一证书域（*.mihoyo.com）的主机做
// HTTP/2 连接合并：把 passport-api 的请求搭到 api-sdk 已经建立的 TLS 连接上。
// 实测这会令 passport 接口判定会话无效，step2 恒定返回 retcode=-100；
// 而用独立连接的测试脚本却能成功 —— 这是"软件里失败、脚本里成功"的真正原因。
// 因此 api-sdk 与 passport-api 必须各自持有独立句柄。
inline cpr::Session& ThreadSessionFor(const std::string_view host)
{
    thread_local cpr::Session sdkSession;
    thread_local cpr::Session passportSession;
    return (host.find("passport-api") != std::string_view::npos) ? passportSession : sdkSession;
}

// 预热：发一个无害请求，建立并缓存 TCP+TLS 连接（丢弃返回内容）
inline void WarmupScanConnection(const std::string_view url)
{
    auto& session = ThreadSessionFor(url);
    session.SetUrl(cpr::Url{ std::string(url) });
    session.SetTimeout(cpr::Timeout{ std::chrono::milliseconds(4000) });
    session.SetConnectTimeout(cpr::ConnectTimeout{ std::chrono::milliseconds(3000) });
    session.Get();
}

// 两个主机都预热（抢码链路同时用到 api-sdk 与 passport-api）
inline void WarmupAllConnections()
{
    WarmupScanConnection(kScanWarmupUrl);
    WarmupScanConnection(kPassportWarmupUrl);
}

// 带节流的预热：同一线程默认 40 秒最多一次。
// 实测服务端空闲约 90 秒后关闭连接，40 秒留足余量。
// 两个主机（api-sdk / passport-api）都预热，覆盖三段式的全部请求。
inline void WarmupScanConnectionThrottled(
    const std::chrono::seconds period = std::chrono::seconds(40))
{
    thread_local std::chrono::steady_clock::time_point last{};
    const auto now = std::chrono::steady_clock::now();
    if (last.time_since_epoch().count() != 0 && (now - last) < period)
    {
        return;
    }
    last = now;
    WarmupScanConnection(kScanWarmupUrl);
    WarmupScanConnection(kPassportWarmupUrl);
}

// 抢码诊断日志（2026-10-25 DSH 添加）
//
// 目的：把 api-scan / api-confirm 的真实响应写进 MHY_scan_error.log。
// 之前只记录耗时（avg=718ms），但不知道失败原因是"网络慢"还是"服务器拒绝"
// （例如二维码已被其他设备扫描、ticket 失效、app_id 不匹配），
// 这两种情况修法完全不同。
//
// 这两个接口只在抢码命中时调用（每次最多 3 次），同步写盘的开销可以忽略，
// 与 PerfStats 不同，它不在每帧的热路径上，因此不做无锁改造。
inline void LogScanDiag(const char* tag,
                        const std::string_view url,
                        const cpr::Response& response,
                        const double ms)
{
    FILE* fp = nullptr;
    if (fopen_s(&fp, "MHY_scan_error.log", "a") != 0 || fp == nullptr)
    {
        return;
    }
    const std::string u(url);
    std::fprintf(fp,
                 "[%s] elapsed=%.1fms  status=%ld  curl_code=%d  len=%zu\n  url=%s\n  resp=[%s]\n\n",
                 tag, ms,
                 static_cast<long>(response.status_code),
                 static_cast<int>(response.error.code),
                 response.text.size(),
                 u.c_str(),
                 response.text.substr(0, 800).c_str());
    std::fclose(fp);
}

// ===========================================================================
// 游戏二维码登录：新版三段式（2026-10-26 DSH 添加）
//
// 依据：MHY_Scanner 逆向文档 docs/GAME_QR_LOGIN_FLOW.md 与开源实现
// loqwe/ErYouScanner。
//
// 为什么必须走三段：
//   旧流程 = 游戏API scan + 游戏API confirm（payload 用 uid + cookie_token）。
//   实测该 confirm 返回 retcode=0，但主播端游戏显示"登录失败" ——
//   cookie_token 无法用于游戏登录确认，这个 confirm 实际上不生效。
//
// 正确流程：
//   Step 1  POST api-sdk/{game}/combo/panda/qrcode/scan
//           body 必须含 passport_app_id = "bll8iq97cem8"
//           响应 data.passport_qr_url 里带 tk=<uuid>&token_types=1
//   Step 2  POST passport-api/account/ma-cn-passport/app/scanQRLogin
//           Cookie: stoken=<账号 stoken>; mid=<账号 mid>
//           body: { ticket: <tk>, token_types: ["1"] }
//   Step 3  POST passport-api/account/ma-cn-passport/app/confirmQRLogin
//           同样 Cookie 与 body —— 这一步才真正让游戏端登录成功
// ===========================================================================

constexpr std::string_view kPassportAppId{ "bll8iq97cem8" };

// 端到端流程日志（2026-10-26 DSH 添加）
//
// 教训：之前只记录"单次请求"的 HTTP 状态与 retcode。可 scan 明明返回
// retcode=0，真正的故障是 data.passport_qr_url 为空（流程断在第 1 步）。
// 那条响应原文就躺在日志里，却因为没有"整条链路"的摘要而被当成成功。
// 现在每抢一次码，MHY_flow.log 里就是一条可读的叙事：
//   [detect] ticket=... → [step1] ... passport_url=EMPTY → [step2] ... → [step3] ...
inline void LogFlow(const std::string& msg)
{
    FILE* fp = nullptr;
    if (fopen_s(&fp, "MHY_flow.log", "a") != 0 || fp == nullptr)
    {
        return;
    }
    const std::time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    char ts[32]{};
    struct tm tb {};
#ifdef _WIN32
    localtime_s(&tb, &t);
#else
    localtime_r(&t, &tb);
#endif
    std::strftime(ts, sizeof(ts), "%H:%M:%S", &tb);
    std::fprintf(fp, "[%s] %s\n", ts, msg.c_str());
    std::fclose(fp);
}

// 识别到二维码时只记录一次：同一张码每帧都会识别到，逐帧写会把日志刷爆，
// 反而让真正有用的 step1/2/3 淹没在噪声里。2026-10-28 DSH 添加
inline void LogDetectOnce(const std::string& game, const std::string& ticket)
{
    static std::mutex mtx;
    static std::string last;
    std::lock_guard<std::mutex> lk(mtx);
    if (last == ticket)
    {
        return;
    }
    last = ticket;
    LogFlow("[detect] game=" + game + " ticket=" + ticket.substr(0, 8) + "…");
}

inline std::string GetPassportQRParam(const std::string_view qrCode,
                                      const std::string_view key,
                                      const std::string_view terminators);

// Step 1：游戏接口扫描，返回 passport_qr_url（失败返回空串）
inline std::string PandaScanQRCode(const std::string_view url,
                                  const std::string_view ticket,
                                  GameType gameType)
{
    if (url.empty() || ticket.empty())
    {
        return {};
    }

    const std::string body{ nlohmann::json{
        { "passport_app_id", std::string(kPassportAppId) },
        { "ticket", ticket },
        { "app_id", static_cast<int>(gameType) },
        { "device", device_id },
        { "ts", GetUnixTimeStampSeconds() } }
                                .dump() };

    auto& session = ThreadSessionFor("api-sdk");
    session.SetUrl(cpr::Url{ std::string(url) });
    session.SetHeader(cpr::Header{
        { "Content-Type", "application/json" },
        // 必须带高仿客户端 UA：不带时 cpr 会发 curl/x.y，风控可能直接拒
        //（2026-10-28 DSH 补充）
        { "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) miHoYoBBS/2.76.1" },
        { "x-rpc-app_id", std::string(kPassportAppId) },
        { "x-rpc-device_id", device_id } });
    session.SetBody(cpr::Body{ body });
    session.SetTimeout(cpr::Timeout{ std::chrono::milliseconds(10000) });
    session.SetConnectTimeout(cpr::ConnectTimeout{ std::chrono::milliseconds(5000) });

    const auto t0 = std::chrono::steady_clock::now();
    const auto response = session.Post();
    const auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::steady_clock::now() - t0)
                        .count();
    ScanPerfStats::Get().Add(3, us);
    LogScanDiag("panda-scan", url, response, static_cast<double>(us) / 1000.0);
    ScanPerfStats::Get().FlushNow("抢码 panda-scan 完成");

    const auto j = nlohmann::json::parse(response.text, nullptr, false);
    if (j.is_discarded())
    {
        LogFlow("[step1] 响应非 JSON，流程中断");
        return {};
    }
    const int retcode = j.value("retcode", -1);
    const auto passportUrl = (j.contains("data") && j["data"].is_object() &&
                              j["data"].contains("passport_qr_url"))
                                 ? j["data"]["passport_qr_url"].get<std::string>()
                                 : std::string{};
    {
        const std::string tk = GetPassportQRParam(passportUrl, "tk", "&");
        LogFlow("[step1] game-scan app_id=" + std::to_string(static_cast<int>(gameType)) +
                " retcode=" + std::to_string(retcode) +
                " passport_url=" + (passportUrl.empty() ? "EMPTY <-- 流程断在这里" : "OK") +
                " tk=" + (tk.empty() ? std::string("-") : tk.substr(0, 8)));
    }
    if (retcode != 0)
    {
        return {};
    }
    return passportUrl;
}

// 从 QR URL / 查询串里取参数，例如 getPassportQRParam(url, "tk", "&")
inline std::string GetPassportQRParam(const std::string_view qrCode,
                                      const std::string_view key,
                                      const std::string_view terminators)
{
    const std::string needle = std::string(key) + "=";
    const auto begin = qrCode.find(needle);
    if (begin == std::string_view::npos)
    {
        return {};
    }
    const auto valueBegin = begin + needle.size();
    auto valueEnd = qrCode.find_first_of(terminators, valueBegin);
    if (valueEnd == std::string_view::npos)
    {
        valueEnd = qrCode.size();
    }
    return std::string(qrCode.substr(valueBegin, valueEnd - valueBegin));
}

// Step 2 / Step 3：passport 扫码与确认（confirm=false 为扫描，true 为确认）
inline bool PassportQRCall(const std::string_view passportQrUrl,
                          const std::string_view cookie,
                          const bool confirm)
{
    const std::string ticket = GetPassportQRParam(passportQrUrl, "tk", "&");
    std::string tokenTypes = GetPassportQRParam(passportQrUrl, "token_types", "#");
    if (tokenTypes.empty())
    {
        tokenTypes = "1";
    }
    if (ticket.empty())
    {
        LogScanDiag(confirm ? "passport-confirm" : "passport-scan", passportQrUrl, cpr::Response{}, 0.0);
        return false;
    }

    const std::string body{ nlohmann::json{
        { "ticket", ticket },
        { "token_types", nlohmann::json::array({ tokenTypes }) } }
                                .dump() };
    const std::string url = confirm ?
        std::string(std::string_view(api::mhy::passport::confirm_qr_login)) :
        std::string(std::string_view(api::mhy::passport::scan_qr_login));

    const cpr::Header hdr{
        { "Content-Type", "application/json" },
        { "Accept", "application/json" },
        // 必须带高仿客户端 UA（2026-10-28 DSH 补充）：
        // 缺 UA 时 cpr 会发 curl/x.y，passport 侧风控会判会话无效（-100）。
        { "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) miHoYoBBS/2.76.1" },
        { "x-rpc-app_id", std::string(kPassportAppId) },
        { "x-rpc-app_version", "2.76.1" },
        { "x-rpc-client_type", "2" },
        { "x-rpc-game_biz", "bbs_cn" },
        { "x-rpc-sdk_version", "2.16.0" },
        { "x-rpc-device_id", device_id },
        { "Cookie", std::string(cookie) } };

    // 关键：passport-api 必须用【独立于 api-sdk 的 curl 句柄】。
    // curl 会对同一 easy handle 上属于 *.mihoyo.com 的主机做 HTTP/2 连接合并，
    // 把 passport 的请求搭到 api-sdk 的 TLS 连接上，实测被后端判为无效会话，
    // 表现为 step2 恒返回 retcode=-100（而用独立连接的脚本却能成功）。
    // 2026-10-28 DSH 修正
    auto& session = ThreadSessionFor("passport-api");
    session.SetUrl(cpr::Url{ url });
    session.SetHeader(hdr);
    session.SetBody(cpr::Body{ body });
    session.SetTimeout(cpr::Timeout{ std::chrono::milliseconds(15000) });
    session.SetConnectTimeout(cpr::ConnectTimeout{ std::chrono::milliseconds(5000) });

    const auto t0 = std::chrono::steady_clock::now();
    const auto response = session.Post();
    const auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::steady_clock::now() - t0)
                        .count();
    ScanPerfStats::Get().Add(confirm ? 4 : 3, us);
    LogScanDiag(confirm ? "passport-confirm" : "passport-scan", url, response,
                static_cast<double>(us) / 1000.0);
    ScanPerfStats::Get().FlushNow(confirm ? "抢码 passport-confirm 完成"
                                          : "抢码 passport-scan 完成");

    const auto j = nlohmann::json::parse(response.text, nullptr, false);
    const std::string phase = confirm ? "step3" : "step2";
    const std::string who = confirm ? "passport-confirm" : "passport-scan";
    if (j.is_discarded())
    {
        LogFlow("[" + phase + "] " + who + " 响应非 JSON，流程中断");
        return false;
    }
    const int retcode = j.value("retcode", -1);
    {
        std::string extra;
        if (!confirm && j.contains("data") && j["data"].is_object())
        {
            if (j["data"].contains("app_name"))
            {
                extra += " app_name=" + j["data"]["app_name"].get<std::string>();
            }
            if (j["data"].contains("account_disp_name"))
            {
                extra += " account=" + j["data"]["account_disp_name"].get<std::string>();
            }
        }
        LogFlow("[" + phase + "] " + who + " retcode=" + std::to_string(retcode) +
                " message=" + j.value("message", std::string{}) + extra);
    }
    if (retcode == 0)
    {
        return true;
    }

    // 兜底：复用会话失败时，用【全新句柄】（cpr::Post 会新建 easy handle，
    // 不参与任何连接合并）重试一次。这一步既能在异常情况下救回本次抢码，
    // 也把"复用会话 vs 独立连接"的差异直接写进日志，便于以后定位。
    // 2026-10-28 DSH 添加
    {
        const auto f0 = std::chrono::steady_clock::now();
        const auto fresh = cpr::Post(cpr::Url{ url }, hdr, cpr::Body{ body },
                                     cpr::Timeout{ std::chrono::milliseconds(15000) },
                                     cpr::ConnectTimeout{ std::chrono::milliseconds(5000) });
        const auto fus = std::chrono::duration_cast<std::chrono::microseconds>(
                             std::chrono::steady_clock::now() - f0)
                             .count();
        LogScanDiag(confirm ? "passport-confirm(fresh)" : "passport-scan(fresh)",
                    url, fresh, static_cast<double>(fus) / 1000.0);
        const auto fj = nlohmann::json::parse(fresh.text, nullptr, false);
        const int frc = fj.is_discarded() ? -999 : fj.value("retcode", -1);
        LogFlow("[" + phase + "] " + who + " 独立连接重试 retcode=" + std::to_string(frc) +
                " message=" +
                (fj.is_discarded() ? std::string("<非JSON>") : fj.value("message", std::string{})));
        return frc == 0;
    }
}

// 候选 Cookie 列表（2026-10-26 DSH 添加）
//
// 实测：passport-api 先校验 ticket 再校验认证，所以"哪种 Cookie 才对"只能
// 在拿到新鲜 tk 的那一刻试出来。与其一次次等人放码，不如在一次抢码里把
// 候选全部试完，谁成功用谁，并把结果写进 MHY_flow.log。
//
// 依据：ErYouScanner 的注释「Current SToken v2 credentials are verified from
// Cookie」—— v2 令牌在 Cookie 里的键名是 stoken_v2，而不是 stoken。
inline std::vector<std::string> BuildPassportCookieCandidates(
    const std::string_view stoken,
    const std::string_view mid,
    const std::string_view uid,
    const std::string_view cookieToken)
{
    std::vector<std::string> list;
    const std::string s{ stoken };
    const std::string m{ mid };
    const std::string u{ uid };
    const std::string ct{ cookieToken };

    if (s.rfind("v2_", 0) == 0)
    {
        // 2026-10-26 本地端到端实测（自己造码 → scan → passport → confirm）：
        //   仅 stoken_v2 + mid          → retcode=-100 被拒
        //   stoken_v2 + stoken + mid    → retcode=0  成功（app_name=原神）
        // 两个键名必须同时带，所以这个组合放第一位，省一次往返。
        list.push_back("stoken_v2=" + s + "; stoken=" + s + "; mid=" + m);
        list.push_back("stoken_v2=" + s + "; mid=" + m);
    }
    list.push_back("stoken=" + s + "; mid=" + m);
    if (!ct.empty())
    {
        list.push_back("cookie_token=" + ct + "; account_id=" + u + "; ltuid=" + u);
        list.push_back("stoken=" + s + "; mid=" + m + "; cookie_token=" + ct +
                       "; account_id=" + u + "; ltuid=" + u);
    }
    return list;
}

// Step 2：依次尝试候选 Cookie，成功则把该 Cookie 交给 outCookie 供 Step 3 复用
inline bool ScanPassportQRLoginAuto(const std::string_view passportQrUrl,
                                    const std::string_view stoken,
                                    const std::string_view mid,
                                    const std::string_view uid,
                                    const std::string_view cookieToken,
                                    std::string& outCookie)
{
    const auto candidates = BuildPassportCookieCandidates(stoken, mid, uid, cookieToken);
    int idx = 0;
    for (const auto& cookie : candidates)
    {
        ++idx;
        // 日志必须标明用的是哪个账号（mid），否则事后无法判断是"Cookie 写法不对"
        // 还是"这个账号的令牌 passport 不认"。2026-10-28 DSH 修改
        LogFlow("[step2] 尝试 Cookie#" + std::to_string(idx) +
                " mid=" + std::string(mid) +
                " [" + cookie.substr(0, 24) + "…]");
        if (PassportQRCall(passportQrUrl, cookie, false))
        {
            outCookie = cookie;
            LogFlow("[step2] Cookie#" + std::to_string(idx) + " 成功（mid=" +
                    std::string(mid) + "），Step3 将复用");
            return true;
        }
    }
    LogFlow("[step2] mid=" + std::string(mid) + " 全部 " + std::to_string(idx) +
            " 种 Cookie 均失败");
    return false;
}

// Step 3：用 Step 2 确认过的那套 Cookie 完成确认
inline bool ConfirmPassportQRLogin(const std::string_view passportQrUrl,
                                   const std::string_view cookie)
{
    return PassportQRCall(passportQrUrl, cookie, true);
}

// 抢码场景接口超时：设成「防死等」而不是「逼失败」。
// 2026-10-11 初版设为 1500ms/2500ms —— 太激进，网络稍慢就超时，
// 超时后 response.text 为空 → 解析丢弃 → 直接返回 false → 扫码失败。
// 2026-10-14 放宽到 10s/15s，保留防死等能力但不会误杀正常请求。
inline bool ScanQRLogin(const std::string_view url, const std::string_view ticket, GameType gameType)
{
    const std::string body{ nlohmann::json{
        { "app_id", static_cast<int>(gameType) },
        { "device", device_id },
        { "ticket", ticket } }
                                .dump() };

    auto& session = ThreadSessionFor("api-sdk");
    session.SetUrl(cpr::Url{ std::string(url) });
    session.SetHeader(cpr::Header{ { "Content-Type", "application/json" } });
    session.SetBody(cpr::Body{ body });
    session.SetTimeout(cpr::Timeout{ std::chrono::milliseconds(10000) });
    session.SetConnectTimeout(cpr::ConnectTimeout{ std::chrono::milliseconds(5000) });

    const auto t0 = std::chrono::steady_clock::now();
    const auto response = session.Post();
    const auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::steady_clock::now() - t0)
                        .count();
    const double ms = static_cast<double>(us) / 1000.0;

    // 显式记录 + 立即落盘：不能依赖 ScanPerfTimer 的析构，
    // 否则"扫码成功后自动退出"会在数据写盘前就结束进程。
    // 2026-10-26 DSH 修改
    ScanPerfStats::Get().Add(3, us);
    LogScanDiag("scan", url, response, ms);
    ScanPerfStats::Get().FlushNow("抢码 scan 完成");

    const auto j = nlohmann::json::parse(response.text, nullptr, false);
    if (j.is_discarded())
    {
        return false;
    }
    return j.value("retcode", -1) == 0;
}

inline bool ConfirmQRLogin(const std::string_view url, const std::string_view uid, const std::string_view gameToken, const std::string_view ticket, GameType gameType)
{
    const std::string body{ nlohmann::json{
        { "app_id", static_cast<int>(gameType) },
        { "device", device_id },
        { "ticket", ticket },
        { "payload", { { "proto", "Account" }, { "raw", nlohmann::json{ { "uid", uid }, { "token", gameToken } }.dump() } } } }
                                .dump() };

    auto& session = ThreadSessionFor("api-sdk");
    session.SetUrl(cpr::Url{ std::string(url) });
    session.SetHeader(cpr::Header{ { "Content-Type", "application/json" } });
    session.SetBody(cpr::Body{ body });
    session.SetTimeout(cpr::Timeout{ std::chrono::milliseconds(15000) });
    session.SetConnectTimeout(cpr::ConnectTimeout{ std::chrono::milliseconds(5000) });

    const auto t0 = std::chrono::steady_clock::now();
    const auto response = session.Post();
    const auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::steady_clock::now() - t0)
                        .count();
    const double ms = static_cast<double>(us) / 1000.0;

    ScanPerfStats::Get().Add(4, us);
    LogScanDiag("confirm", url, response, ms);
    ScanPerfStats::Get().FlushNow("抢码 confirm 完成");

    const auto j = nlohmann::json::parse(response.text, nullptr, false);
    if (j.is_discarded())
    {
        return false;
    }
    return j.value("retcode", -1) == 0;
}

inline std::string makeSign(const nlohmann::json& data)
{
    std::string param;
    for (auto& [key, value] : data.items())
    {
        if (key == "sign")
            continue;
        const std::string strVal = value.is_string() ? value.get<std::string>() : value.dump();

        param += key + "=" + strVal + "&";
    }
    if (!param.empty())
        param.pop_back();
#ifdef _DEBUG
    std::cout << "make_param = " << param << std::endl;
#endif
    constexpr std::string_view key = "0ebc517adb1b62c6b408df153331f9aa";
    return HmacSha256(param, std::string(key));
}

inline std::string& getOAString()
{
    static std::string value = []() {
        const auto response = cpr::Get(cpr::Url{ "https://api.v6qbb.cloud/get_bh3_bilibili_oa" });
        if (response.text.empty())
            throw std::runtime_error("");
        return response.text;
    }();
    return value;
}

inline std::tuple<int, std::string, std::string, std::string> GetBH3ExternalLoginInfo(const std::string& uid, const std::string& access_key)
{
    const std::string bodyData = std::format(R"({{"access_key":"{}","uid":{}}})", access_key, uid);

    nlohmann::json body{
        { "device", "0000000000000000" },
        { "app_id", 1 },
        { "channel_id", 14 },
        { "data", bodyData }
    };
    body["sign"] = makeSign(body);
    const auto response = cpr::Post(
        cpr::Url{ api::mhy::bh3::v2_login },
        cpr::Header{ { "Content-Type", "application/json" } },
        cpr::Body{ body.dump() });

    const auto j = nlohmann::json::parse(response.text);
    const int retcode = j.value("retcode", -1);

#ifdef _DEBUG
    std::cout << "崩坏3验证完成 : " << response.text << std::endl;
#endif

    if (retcode != 0)
    {
        return { retcode, {}, {}, {} };
    }

    return { 0,
             j["data"]["open_id"].get<std::string>(),
             j["data"]["combo_token"].get<std::string>(),
             j["data"]["combo_id"].get<std::string>() };
}

inline ScanRet scanCheck(const std::string& ticket)
{
    const std::string body = nlohmann::json{
        { "app_id", "1" },
        { "device", "0000000000000000" },
        { "ticket", ticket },
        { "ts", GetUnixTimeStampSeconds() }
    }.dump();

    const auto response = cpr::Post(
        cpr::Url{ api::mhy::bh3::qrcode_scan },
        cpr::Body{ body },
        cpr::Header{ { "Content-Type", "application/json" } });

    const auto j = nlohmann::json::parse(response.text);
    return j.value("retcode", -1) == 0 ? ScanRet::SUCCESS : ScanRet::FAILURE_1;
}

inline ScanRet scanConfirm(const std::string& ticket, const std::string& uid, const std::string& access_key, const std::string& name)
{
    auto [code, open_id, combo_token, combo_id] = GetBH3ExternalLoginInfo(uid, access_key);
    if (code != 0)
        return ScanRet::FAILURE_2;

    const auto raw =
        nlohmann::json{
            { "heartbeat", false },
            { "open_id", open_id },
            { "device_id", "0000000000000000" },
            { "app_id", "1" },
            { "channel_id", "14" },
            { "combo_token", combo_token },
            { "asterisk_name", name },
            { "combo_id", combo_id },
            { "account_type", "2" }
        };

    const auto ext =
        nlohmann::json{
            { "data", nlohmann::json{
                          { "accountType", "2" },
                          { "accountID", "" },
                          { "c", open_id },
                          { "accountToken", combo_token },
                          { "dispatch", getOAString() } } }
        };

    const nlohmann::json postBody{
        { "device", "0000000000000000" },
        { "app_id", 1 },
        { "ts", GetUnixTimeStampSeconds() },
        { "ticket", ticket },
        { "payload", nlohmann::json{
                         { "proto", "Combo" },
                         { "raw", raw.dump() },
                         { "ext", ext.dump() } } }
    };

#ifdef _DEBUG
    std::cout << postBody.dump() << std::endl;
#endif

    const auto response = cpr::Post(
        cpr::Url{ api::mhy::bh3::qrcode_confirm },
        cpr::Header{ { "Content-Type", "application/json" } },
        cpr::Body{ postBody.dump() });

    const auto j = nlohmann::json::parse(response.text);
    return j.value("retcode", -1) == 0 ? ScanRet::SUCCESS : ScanRet::FAILURE_2;
}