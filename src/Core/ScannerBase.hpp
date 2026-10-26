#pragma once

#include <string>
#include <string_view>

#include "ApiDefs.hpp"

class ScannerBase
{
public:
    GameType gameType;
    std::string_view scanUrl{};
    std::string_view confirmUrl{};
    std::string lastTicket;
    std::string uid;
    std::string gameToken{};
    // 新版三段式登录所需（2026-10-26 DSH 添加）：
    //   stoken/mid 用于 passport-api 的 Cookie 认证
    //   m_tk 保存 Step 1 返回的 passport_qr_url（内含 tk），供 Step 3 使用
    std::string stoken{};
    std::string mid{};
    std::string m_passportQrUrl{};
    std::string m_passportCookie{};   // Step2 试出的可用 Cookie
    std::map<std::string_view, std::function<void()>> setGameType{
        { "8F3", [this]() {
             gameType = GameType::Honkai3;
             scanUrl = api::mhy::bh3::qrcode_scan;
             confirmUrl = api::mhy::bh3::qrcode_confirm;
         } },
        { "9E&", [this]() {
             gameType = GameType::Genshin;
             scanUrl = api::mhy::hk4e::qrcode_scan;
             confirmUrl = api::mhy::hk4e::qrcode_confirm;
         } },
        { "8F%", [this]() {
             gameType = GameType::HonkaiStarRail;
             scanUrl = api::mhy::hkrpg::qrcode_scan;
             confirmUrl = api::mhy::hkrpg::qrcode_confirm;
         } },
        { "%BA", [this]() {
             gameType = GameType::ZenlessZoneZero;
             scanUrl = api::mhy::nap::qrcode_scan;
             confirmUrl = api::mhy::nap::qrcode_confirm;
         } },
    };
};