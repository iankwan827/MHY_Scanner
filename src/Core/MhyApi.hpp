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

inline cpr::Session& ThreadScanSession()
{
    thread_local cpr::Session session;
    return session;
}

// 预热：发一个无害请求，建立并缓存 TCP+TLS 连接（丢弃返回内容）
inline void WarmupScanConnection(const std::string_view url)
{
    auto& session = ThreadScanSession();
    session.SetUrl(cpr::Url{ std::string(url) });
    session.SetTimeout(cpr::Timeout{ std::chrono::milliseconds(4000) });
    session.SetConnectTimeout(cpr::ConnectTimeout{ std::chrono::milliseconds(3000) });
    session.Get();
}

// 带节流的预热：同一线程默认 40 秒最多一次（各游戏扫码接口同主机，共用连接）
inline void WarmupScanConnectionThrottled(
    const std::string_view url = kScanWarmupUrl,
    const std::chrono::seconds period = std::chrono::seconds(40))
{
    thread_local std::chrono::steady_clock::time_point last{};
    const auto now = std::chrono::steady_clock::now();
    if (last.time_since_epoch().count() != 0 && (now - last) < period)
    {
        return;
    }
    last = now;
    WarmupScanConnection(url);
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

// 抢码场景接口超时：设成「防死等」而不是「逼失败」。
// 2026-10-11 初版设为 1500ms/2500ms —— 太激进，网络稍慢就超时，
// 超时后 response.text 为空 → 解析丢弃 → 直接返回 false → 扫码失败。
// 2026-10-14 放宽到 10s/15s，保留防死等能力但不会误杀正常请求。
inline bool ScanQRLogin(const std::string_view url, const std::string_view ticket, GameType gameType)
{
    // 计时：scan 接口耗时（2026-10-11 DSH 修改）
    const ScanPerfTimer _tScan(3);
    const std::string body{ nlohmann::json{
        { "app_id", static_cast<int>(gameType) },
        { "device", device_id },
        { "ticket", ticket } }
                                .dump() };

    auto& session = ThreadScanSession();
    session.SetUrl(cpr::Url{ std::string(url) });
    session.SetHeader(cpr::Header{ { "Content-Type", "application/json" } });
    session.SetBody(cpr::Body{ body });
    session.SetTimeout(cpr::Timeout{ std::chrono::milliseconds(10000) });
    session.SetConnectTimeout(cpr::ConnectTimeout{ std::chrono::milliseconds(5000) });

    const auto t0 = std::chrono::steady_clock::now();
    const auto response = session.Post();
    const double ms = std::chrono::duration<double, std::milli>(
                          std::chrono::steady_clock::now() - t0)
                          .count();
    LogScanDiag("scan", url, response, ms);

    const auto j = nlohmann::json::parse(response.text, nullptr, false);
    if (j.is_discarded())
    {
        return false;
    }
    return j.value("retcode", -1) == 0;
}

inline bool ConfirmQRLogin(const std::string_view url, const std::string_view uid, const std::string_view gameToken, const std::string_view ticket, GameType gameType)
{
    // 计时：confirm 接口耗时（2026-10-11 DSH 修改）
    const ScanPerfTimer _tConfirm(4);
    const std::string body{ nlohmann::json{
        { "app_id", static_cast<int>(gameType) },
        { "device", device_id },
        { "ticket", ticket },
        { "payload", { { "proto", "Account" }, { "raw", nlohmann::json{ { "uid", uid }, { "token", gameToken } }.dump() } } } }
                                .dump() };

    auto& session = ThreadScanSession();
    session.SetUrl(cpr::Url{ std::string(url) });
    session.SetHeader(cpr::Header{ { "Content-Type", "application/json" } });
    session.SetBody(cpr::Body{ body });
    session.SetTimeout(cpr::Timeout{ std::chrono::milliseconds(15000) });
    session.SetConnectTimeout(cpr::ConnectTimeout{ std::chrono::milliseconds(5000) });

    const auto t0 = std::chrono::steady_clock::now();
    const auto response = session.Post();
    const double ms = std::chrono::duration<double, std::milli>(
                          std::chrono::steady_clock::now() - t0)
                          .count();
    LogScanDiag("confirm", url, response, ms);

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