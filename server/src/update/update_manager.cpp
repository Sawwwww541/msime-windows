#include "update_manager.h"

#include "config/ime_config.h"
#include "ime_version.h"
#include "settings/settings_launcher.h"
#include "utils/common_utils.h"
#include "utils/network_proxy.h"

#include <Windows.h>
#include <bcrypt.h>
#include <shellapi.h>
#include <winhttp.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <ctime>
#include <deque>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

namespace update
{

namespace
{

// ---- 常量 ----

constexpr wchar_t kManifestHost[] = L"msime.app";
constexpr wchar_t kManifestPath[] = L"/update.json";
constexpr wchar_t kApiHost[] = L"api.github.com";
constexpr wchar_t kApiPath[] = L"/repos/metasequoiaime/MSIME-Windows/releases?per_page=15";
constexpr wchar_t kUserAgent[] = L"MetasequoiaImeServer/1.0";
// 发布页前缀。清单里的 releaseUrl 必须落在这里，防止清单被塞进任意下载地址。
constexpr char kReleasesPageUrl[] = "https://github.com/metasequoiaime/MSIME-Windows/releases";
// msime.app 的下载镜像（Cloudflare，香港节点）。GitHub 直链在国内常常只有几十 KB/s。
constexpr char kMirrorPrefix[] = "https://dl.msime.app/gh/";

// 启动检测的延迟：Server 随登录拉起，此刻 Wi-Fi 往往还没连上，立刻检测只会白跑一次。
constexpr DWORD kStartupCheckDelayMs = 30 * 1000;
// 下载进度的最小推送间隔，避免把 90MB 的下载刷成洪水。
constexpr DWORD kProgressPushIntervalMs = 500;

// ---- 基础工具 ----

std::int64_t NowUnixSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
}

std::string LocalIsoTimestamp(std::int64_t unix_seconds)
{
    const std::time_t value = static_cast<std::time_t>(unix_seconds);
    std::tm local{};
    localtime_s(&local, &value);
    char buffer[32]{};
    std::snprintf(buffer, sizeof(buffer), "%04d-%02d-%02dT%02d:%02d:%02d", local.tm_year + 1900, local.tm_mon + 1,
                  local.tm_mday, local.tm_hour, local.tm_min, local.tm_sec);
    return std::string(buffer);
}

std::string LowerAscii(std::string value)
{
    for (char &c : value)
    {
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    }
    return value;
}

bool IsLowerHex(const std::string &value, std::size_t length)
{
    if (value.size() != length)
        return false;
    for (const char c : value)
    {
        const bool digit = c >= '0' && c <= '9';
        const bool lower = c >= 'a' && c <= 'f';
        if (!digit && !lower)
            return false;
    }
    return true;
}

std::string Sha256Hex(const std::filesystem::path &file)
{
    std::ifstream input(file, std::ios::binary);
    if (!input)
        return {};
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
        return {};
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::string hex;
    if (BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) == 0)
    {
        bool ok = true;
        std::vector<char> buffer(1 << 20);
        while (ok && input)
        {
            input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
            const std::streamsize read = input.gcount();
            if (read > 0)
                ok = BCryptHashData(hash, reinterpret_cast<PUCHAR>(buffer.data()), static_cast<ULONG>(read), 0) == 0;
        }
        unsigned char digest[32]{};
        if (ok && input.eof() && BCryptFinishHash(hash, digest, sizeof(digest), 0) == 0)
        {
            static constexpr char kDigits[] = "0123456789abcdef";
            for (const unsigned char byte : digest)
            {
                hex.push_back(kDigits[byte >> 4]);
                hex.push_back(kDigits[byte & 0x0f]);
            }
        }
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return hex;
}

// ---- 版本号 ----

// "v0.10.1" / "0.10.1" → [0,10,1]；不可解析返回 false。与设置页 update-manifest.ts 同一套规则。
bool ParseVersionParts(const std::string &value, std::vector<int> &parts)
{
    std::string text = value;
    if (!text.empty() && (text.front() == 'v' || text.front() == 'V'))
        text.erase(text.begin());
    if (text.empty())
        return false;
    parts.clear();
    std::size_t index = 0;
    for (;;)
    {
        const std::size_t dot = text.find('.', index);
        const std::string component = text.substr(index, dot == std::string::npos ? std::string::npos : dot - index);
        if (component.empty() || component.size() > 9 ||
            !std::all_of(component.begin(), component.end(), [](char c) { return c >= '0' && c <= '9'; }))
            return false;
        try
        {
            parts.push_back(std::stoi(component));
        }
        catch (...)
        {
            return false;
        }
        if (dot == std::string::npos)
            break;
        index = dot + 1;
    }
    return !parts.empty();
}

int CompareVersions(const std::string &left, const std::string &right)
{
    std::vector<int> left_parts;
    std::vector<int> right_parts;
    if (!ParseVersionParts(left, left_parts) || !ParseVersionParts(right, right_parts))
        return 0; // 不可比时视为同版本，调用方不会据此提示更新
    const std::size_t length = std::max(left_parts.size(), right_parts.size());
    for (std::size_t index = 0; index < length; ++index)
    {
        const int difference =
            (index < left_parts.size() ? left_parts[index] : 0) - (index < right_parts.size() ? right_parts[index] : 0);
        if (difference != 0)
            return difference < 0 ? -1 : 1;
    }
    return 0;
}

// ---- 清单与目录校验 ----

// 发布流水线产出的安装包名：MetasequoiaIME_Setup_v<版本>.exe（未签名构建带 -unsigned 后缀）。
bool IsInstallerAssetName(const std::string &name, const std::string &version)
{
    const std::string prefix = "MetasequoiaIME_Setup_v" + version;
    if (name.size() <= prefix.size() || name.compare(0, prefix.size(), prefix) != 0)
        return false;
    const std::string suffix = name.substr(prefix.size());
    return suffix == ".exe" ||
           (suffix.rfind("-", 0) == 0 && suffix.size() > 4 && suffix.compare(suffix.size() - 4, 4, ".exe") == 0);
}

bool IsReleasesUrl(const std::string &url)
{
    const std::string prefix(kReleasesPageUrl);
    return url.rfind(prefix, 0) == 0 && (url.size() == prefix.size() || url[prefix.size()] == '/');
}

std::string MirrorUrl(const std::string &installer_url)
{
    if (installer_url.rfind("https://github.com/", 0) != 0)
        return {};
    return std::string(kMirrorPrefix) + installer_url;
}

// ---- 状态文件 ----
// Server 启动检测和设置页手动检测是两个进程，靠这个文件共享「最新版是谁、自动更新
// 进行到哪一步」。auto_update_version / auto_update_result 记录启动自动更新最近一次
// 尝试的结果：安装已启动（installing）则同一个版本不再重复下载安装；下载或拉起失败
// 则留着记录，下次启动重试。

struct PersistedState
{
    bool valid = false;
    std::string last_checked_at;
    std::string latest_version;
    VersionEntry latest_entry; // 最新版的完整信息：设置页据此直接展示与下载，不必再联网
    std::string auto_update_version;
    std::string auto_update_result; // "installing" | "downloadFailed" | "launchFailed"，空 = 没尝试过

    // 实时进度快照（live 对象）：Server 进程自动更新期间由 PushStatus 节流写入，
    // 设置页经 GetAutoUpdateProgress / GetMergedStatus 读取。
    std::string live_state;
    std::string live_version;
    std::string live_message;
    std::int64_t live_received = 0;
    std::int64_t live_total = 0;
    int live_percent = 0;
    std::int64_t live_at = 0; // unix 秒；0 = 没有
};

std::filesystem::path UpdateStateDirectory()
{
    return std::filesystem::path(CommonUtils::get_ime_data_path_w()) / L"update";
}

std::filesystem::path StateFilePath()
{
    return UpdateStateDirectory() / L"state.json";
}

nlohmann::json VersionEntryToJson(const VersionEntry &entry)
{
    return nlohmann::json{
        {"version", entry.version},   {"prerelease", entry.prerelease},      {"publishedAt", entry.published_at},
        {"size", entry.size},         {"installerUrl", entry.installer_url}, {"mirrorUrl", entry.mirror_url},
        {"sha256", entry.sha256},     {"releaseUrl", entry.release_url},     {"signedKnown", entry.signed_known},
        {"isSigned", entry.is_signed}};
}

bool VersionEntryFromJson(const nlohmann::json &object, VersionEntry &entry)
{
    if (!object.is_object() || !object.contains("version") || !object["version"].is_string())
        return false;
    entry.version = object["version"].get<std::string>();
    entry.prerelease = object.value("prerelease", false);
    entry.published_at = object.value("publishedAt", std::string());
    entry.size = object.value("size", static_cast<std::int64_t>(0));
    entry.installer_url = object.value("installerUrl", std::string());
    entry.mirror_url = object.value("mirrorUrl", std::string());
    entry.sha256 = object.value("sha256", std::string());
    entry.release_url = object.value("releaseUrl", std::string());
    entry.signed_known = object.value("signedKnown", false);
    entry.is_signed = object.value("isSigned", false);
    return !entry.installer_url.empty();
}

nlohmann::json LoadStateJson()
{
    std::ifstream input(StateFilePath(), std::ios::binary);
    if (!input)
        return nlohmann::json::object();
    std::ostringstream buffer;
    buffer << input.rdbuf();
    try
    {
        return nlohmann::json::parse(buffer.str());
    }
    catch (...)
    {
        return nlohmann::json::object();
    }
}

PersistedState LoadPersistedState()
{
    PersistedState state;
    const nlohmann::json root = LoadStateJson();
    if (!root.is_object())
        return state;
    try
    {
        state.last_checked_at = root.value("lastCheckedAt", std::string());
        state.latest_version = root.value("latestVersion", std::string());
        if (root.contains("latestEntry"))
            (void)VersionEntryFromJson(root["latestEntry"], state.latest_entry);
        state.auto_update_version = root.value("autoUpdateVersion", std::string());
        state.auto_update_result = root.value("autoUpdateResult", std::string());
        if (root.contains("live") && root["live"].is_object())
        {
            const auto &live = root["live"];
            state.live_state = live.value("state", std::string());
            state.live_version = live.value("version", std::string());
            state.live_message = live.value("message", std::string());
            state.live_received = live.value("received", static_cast<std::int64_t>(0));
            state.live_total = live.value("total", static_cast<std::int64_t>(0));
            state.live_percent = live.value("percent", 0);
            state.live_at = live.value("at", static_cast<std::int64_t>(0));
        }
        state.valid = !state.latest_version.empty();
    }
    catch (...)
    {
        return PersistedState{};
    }
    return state;
}

void SavePersistedState(const std::string &last_checked_at, const std::string &latest_version,
                        const VersionEntry &latest_entry, const std::string &auto_update_version,
                        const std::string &auto_update_result)
{
    const std::filesystem::path path = StateFilePath();
    std::error_code error;
    std::filesystem::create_directories(path.parent_path(), error);
    if (error)
        return;
    nlohmann::json root = {{"lastCheckedAt", last_checked_at},
                           {"latestVersion", latest_version},
                           {"latestEntry", VersionEntryToJson(latest_entry)},
                           {"autoUpdateVersion", auto_update_version},
                           {"autoUpdateResult", auto_update_result}};
    // 保留实时进度对象：里程碑写入（检测结果、尝试记录）不该把设置页正在看的
    // 进度擦掉（见 SaveLiveSnapshot）。
    const nlohmann::json existing = LoadStateJson();
    if (existing.is_object() && existing.contains("live"))
        root["live"] = existing["live"];
    // 临时文件 + 换名：Server 启动检测和设置页手动检测都会写它，不能让读者看到半份 JSON。
    const std::filesystem::path temporary = path.wstring() + L".tmp";
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    if (!output)
        return;
    output << root.dump();
    output.close();
    if (!output)
        return;
    MoveFileExW(temporary.wstring().c_str(), path.wstring().c_str(), MOVEFILE_REPLACE_EXISTING);
}

// ---- HTTP ----

// 拆 https://host[:port]/path。返回 false 表示不是可用的 https URL。
bool SplitHttpsUrl(const std::string &url, std::wstring &host, std::wstring &path, INTERNET_PORT &port)
{
    const std::string scheme = "https://";
    if (url.rfind(scheme, 0) != 0)
        return false;
    const std::size_t authority = url.find('/', scheme.size());
    if (authority == std::string::npos)
        return false;
    std::string host_part = url.substr(scheme.size(), authority - scheme.size());
    path = string_to_wstring(url.substr(authority));
    port = INTERNET_DEFAULT_HTTPS_PORT;
    const std::size_t colon = host_part.rfind(':');
    if (colon != std::string::npos)
    {
        const std::string port_text = host_part.substr(colon + 1);
        host_part = host_part.substr(0, colon);
        try
        {
            const int parsed = std::stoi(port_text);
            if (parsed <= 0 || parsed > 65535)
                return false;
            port = static_cast<INTERNET_PORT>(parsed);
        }
        catch (...)
        {
            return false;
        }
    }
    if (host_part.empty())
        return false;
    host = string_to_wstring(host_part);
    return true;
}

struct HttpResponse
{
    bool ok = false;
    std::string body;
    std::string error;
};

HttpResponse HttpGetText(const std::string &url, const std::wstring &headers)
{
    HttpResponse result;
    std::wstring host;
    std::wstring path;
    INTERNET_PORT port = 0;
    if (!SplitHttpsUrl(url, host, path, port))
    {
        result.error = "更新服务器地址无效";
        return result;
    }
    HINTERNET session = NetworkProxy::OpenWinHttpSession(kUserAgent);
    if (session == nullptr)
    {
        result.error = "无法初始化网络";
        return result;
    }
    WinHttpSetTimeouts(session, 30000, 30000, 30000, 0);
    HINTERNET connection = WinHttpConnect(session, host.c_str(), port, 0);
    HINTERNET request = nullptr;
    if (connection != nullptr)
    {
        request = WinHttpOpenRequest(connection, L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER,
                                     WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    }
    const bool sent = request != nullptr &&
                      WinHttpSendRequest(request, headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str(),
                                         static_cast<DWORD>(-1), WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
                      WinHttpReceiveResponse(request, nullptr);
    if (sent)
    {
        DWORD status = 0;
        DWORD status_size = sizeof(status);
        WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX);
        if (status == 200)
        {
            std::string body;
            std::vector<char> buffer(1 << 16);
            for (;;)
            {
                DWORD available = 0;
                if (!WinHttpQueryDataAvailable(request, &available))
                    break;
                if (available == 0)
                {
                    result.ok = true;
                    result.body = std::move(body);
                    break;
                }
                buffer.resize(available);
                DWORD read = 0;
                if (!WinHttpReadData(request, buffer.data(), available, &read) || read == 0)
                    break;
                body.append(buffer.data(), read);
            }
            if (!result.ok)
                result.error = "读取更新信息失败";
        }
        else
        {
            result.error = "更新服务器返回 " + std::to_string(status);
        }
    }
    else
    {
        result.error = "无法连接更新服务器";
    }
    if (request != nullptr)
        WinHttpCloseHandle(request);
    if (connection != nullptr)
        WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    return result;
}

// ---- 模块状态 ----

std::mutex g_mutex;
Status g_status;
StatusCallback g_callback;
std::string g_ready_path; // Ready 态安装包路径
std::string g_ready_sha256;

std::atomic<bool> g_cancel_download{false};
std::atomic<bool> g_busy{false};

std::mutex g_queue_mutex;
std::condition_variable g_queue_cv;
std::deque<std::function<void()>> g_jobs;
std::thread g_worker_thread;

// 实时进度落盘：自动更新跑在 Server 进程里，设置页（另一个进程）靠状态文件的
// live 对象拿到进度（见 GetAutoUpdateProgress / GetMergedStatus）。
void SaveLiveSnapshot(const Status &snapshot)
{
    const std::filesystem::path path = StateFilePath();
    std::error_code error;
    std::filesystem::create_directories(path.parent_path(), error);
    if (error)
        return;
    nlohmann::json root = LoadStateJson();
    if (!root.is_object())
        root = nlohmann::json::object();
    root["live"] = {{"state", StateName(snapshot.state)},
                    {"version", snapshot.version},
                    {"message", snapshot.message},
                    {"received", snapshot.received_bytes},
                    {"total", snapshot.total_bytes},
                    {"percent", snapshot.percent},
                    {"at", static_cast<std::int64_t>(NowUnixSeconds())}};
    const std::filesystem::path temporary = path.wstring() + L".tmp";
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    if (!output)
        return;
    output << root.dump();
    output.close();
    if (!output)
        return;
    MoveFileExW(temporary.wstring().c_str(), path.wstring().c_str(), MOVEFILE_REPLACE_EXISTING);
}

// 写盘按「状态或百分比变化」+「至少 1 秒一次」节流，避免下载期间频繁命中磁盘。
void MaybeSaveLiveSnapshot(const Status &snapshot)
{
    static std::mutex write_mutex;
    static std::string last_state;
    static int last_percent = -1;
    static ULONGLONG last_write_tick = 0;

    const std::string state_name = StateName(snapshot.state);
    const ULONGLONG now_tick = GetTickCount64();
    {
        std::lock_guard<std::mutex> lock(write_mutex);
        const bool changed = state_name != last_state || snapshot.percent != last_percent;
        if (!changed && now_tick - last_write_tick < 1000)
            return;
        last_state = state_name;
        last_percent = snapshot.percent;
        last_write_tick = now_tick;
    }
    SaveLiveSnapshot(snapshot);
}

// 快照 + 推送。调用方不得持有 g_mutex（本函数内部要取它拷贝回调）。
void PushStatus()
{
    Status snapshot;
    StatusCallback callback;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        snapshot = g_status;
        callback = g_callback;
    }
    // 进度也要落盘：设置页展示自动更新的进度就靠它。
    MaybeSaveLiveSnapshot(snapshot);
    if (callback)
        callback(snapshot);
}

Status Snapshot()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_status;
}

void SetState(State state, const std::string &message)
{
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_status.state = state;
        g_status.message = message;
    }
    PushStatus();
}

// 内存状态 + 状态文件合并。Server 启动检测的结果写在文件里，设置页首次打开时要看得到。
Status BuildStatus()
{
    Status status = Snapshot();
    status.current_version = MSIME_VERSION;
    if (status.state == State::Idle || status.state == State::Error)
    {
        const PersistedState persisted = LoadPersistedState();
        if (persisted.valid && CompareVersions(persisted.latest_version, MSIME_VERSION) > 0 &&
            !persisted.latest_entry.installer_url.empty())
        {
            status.state = State::UpdateAvailable;
            status.message = "发现新版本 v" + persisted.latest_version;
            // 启动自动更新没能自己完成时，把原因带上：用户知道该自己点了。
            if (persisted.auto_update_result == "downloadFailed")
                status.message += "（启动时自动下载失败）";
            else if (persisted.auto_update_result == "launchFailed")
                status.message += "（启动时自动安装未启动）";
            status.versions = {persisted.latest_entry};
            status.last_checked_at = persisted.last_checked_at;
        }
    }
    return status;
}

void WorkerLoop();

void EnsureWorkerThread()
{
    static std::once_flag once;
    std::call_once(once, [] {
        g_worker_thread = std::thread(WorkerLoop);
        g_worker_thread.detach();
    });
}

void SubmitJob(std::function<void()> job)
{
    EnsureWorkerThread();
    {
        std::lock_guard<std::mutex> lock(g_queue_mutex);
        g_jobs.push_back(std::move(job));
    }
    g_queue_cv.notify_one();
}

// ---- 发布清单 ----

struct ManifestResult
{
    bool ok = false;
    VersionEntry entry;
    std::string error;
};

std::string CacheBustedManifestUrl()
{
    return std::string("https://") + wstring_to_string(kManifestHost) + wstring_to_string(kManifestPath) +
           "?t=" + std::to_string(NowUnixSeconds());
}

ManifestResult FetchManifest()
{
    ManifestResult result;
    const HttpResponse response = HttpGetText(CacheBustedManifestUrl(), L"");
    if (!response.ok)
    {
        result.error = response.error;
        return result;
    }
    try
    {
        const auto root = nlohmann::json::parse(response.body);
        if (!root.is_object())
            throw std::runtime_error("manifest is not an object");
        const std::string version = root.value("version", std::string());
        const std::string release_url = root.value("releaseUrl", std::string());
        if (!IsReleasesUrl(release_url))
            throw std::runtime_error("releaseUrl is not the project releases page");
        std::vector<int> parts;
        if (!ParseVersionParts(version, parts))
            throw std::runtime_error("version is not orderable");
        result.entry.version = version;
        result.entry.release_url = release_url;
        const std::string installer_name = root.value("installerName", std::string());
        if (!installer_name.empty() && !IsInstallerAssetName(installer_name, version))
            throw std::runtime_error("installerName has an unexpected shape");
        std::string installer_url = root.value("installerUrl", std::string());
        if (installer_url.empty() && !installer_name.empty())
        {
            // 清单缺 installerUrl 时按发布页的固定形态拼出来，老清单仍然可用。
            installer_url = std::string(kReleasesPageUrl) + "/tag/v" + version + "/download/" + installer_name;
        }
        if (installer_url.rfind("https://", 0) != 0)
            throw std::runtime_error("installerUrl is not https");
        result.entry.installer_url = installer_url;
        result.entry.mirror_url = MirrorUrl(installer_url);
        const std::string sha256 = LowerAscii(root.value("installerSha256", std::string()));
        if (!sha256.empty() && IsLowerHex(sha256, 64))
            result.entry.sha256 = sha256;
        if (root.contains("signed") && root["signed"].is_boolean())
        {
            result.entry.signed_known = true;
            result.entry.is_signed = root["signed"].get<bool>();
        }
        result.ok = true;
    }
    catch (const std::exception &)
    {
        result.error = "更新清单无效，请稍后重试";
    }
    return result;
}

// ---- GitHub 版本目录 ----

std::vector<VersionEntry> FetchCatalog()
{
    std::vector<VersionEntry> catalog;
    const HttpResponse response =
        HttpGetText(std::string("https://") + wstring_to_string(kApiHost) + wstring_to_string(kApiPath),
                    L"Accept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\n");
    if (!response.ok)
        return catalog; // 目录拉取失败不退化为错误：最新版仍然可更新，只是不能选旧版本
    try
    {
        const auto root = nlohmann::json::parse(response.body);
        if (!root.is_array())
            return catalog;
        for (const auto &release : root)
        {
            if (!release.is_object() || release.value("draft", false))
                continue;
            const std::string tag = release.value("tag_name", std::string());
            std::vector<int> parts;
            if (!ParseVersionParts(tag, parts))
                continue;
            VersionEntry entry;
            entry.version = tag;
            if (!entry.version.empty() && (entry.version.front() == 'v' || entry.version.front() == 'V'))
                entry.version.erase(entry.version.begin());
            entry.prerelease = release.value("prerelease", false);
            entry.published_at = release.value("published_at", std::string());
            entry.release_url = release.value("html_url", std::string());
            const auto assets = release.find("assets");
            if (assets == release.end() || !assets->is_array())
                continue;
            for (const auto &asset : *assets)
            {
                if (!asset.is_object())
                    continue;
                const std::string name = asset.value("name", std::string());
                if (!IsInstallerAssetName(name, entry.version))
                    continue;
                entry.size = asset.value("size", static_cast<std::int64_t>(0));
                entry.installer_url = asset.value("browser_download_url", std::string());
                // asset 的 digest 形如 "sha256:<hex>"；缺失时该版本没有可校验的下载。
                const std::string digest = LowerAscii(asset.value("digest", std::string()));
                const std::string prefix = "sha256:";
                if (digest.rfind(prefix, 0) == 0)
                {
                    const std::string hex = digest.substr(prefix.size());
                    if (IsLowerHex(hex, 64))
                        entry.sha256 = hex;
                }
                break;
            }
            if (entry.installer_url.rfind("https://", 0) != 0)
                continue;
            entry.mirror_url = MirrorUrl(entry.installer_url);
            catalog.push_back(std::move(entry));
        }
    }
    catch (...)
    {
        catalog.clear();
    }
    std::sort(catalog.begin(), catalog.end(), [](const VersionEntry &left, const VersionEntry &right) {
        return CompareVersions(left.version, right.version) > 0;
    });
    return catalog;
}

// 清单里的最新版与目录合并：目录提供体积与直链，清单提供最新版的校验和与签名标记。
std::vector<VersionEntry> MergeCatalog(std::vector<VersionEntry> catalog, const VersionEntry &manifest_entry)
{
    bool found = false;
    for (VersionEntry &entry : catalog)
    {
        if (entry.version != manifest_entry.version)
            continue;
        found = true;
        if (manifest_entry.size > 0)
            entry.size = manifest_entry.size;
        if (!manifest_entry.installer_url.empty())
            entry.installer_url = manifest_entry.installer_url;
        if (!manifest_entry.mirror_url.empty())
            entry.mirror_url = manifest_entry.mirror_url;
        if (entry.sha256.empty())
            entry.sha256 = manifest_entry.sha256;
        if (manifest_entry.signed_known)
        {
            entry.signed_known = true;
            entry.is_signed = manifest_entry.is_signed;
        }
        if (entry.release_url.empty())
            entry.release_url = manifest_entry.release_url;
        break;
    }
    if (!found)
        catalog.push_back(manifest_entry);
    std::sort(catalog.begin(), catalog.end(), [](const VersionEntry &left, const VersionEntry &right) {
        return CompareVersions(left.version, right.version) > 0;
    });
    return catalog;
}

// ---- 下载 ----

std::filesystem::path UpdateDirectory()
{
    std::error_code error;
    std::filesystem::path path = std::filesystem::temp_directory_path(error);
    if (error)
        path = UpdateStateDirectory(); // 取不到临时目录时退回数据目录，功能不因此消失
    else
        path = path / L"MetasequoiaImeUpdate";
    return path;
}

void RemovePartFiles()
{
    std::error_code error;
    const std::filesystem::path directory = UpdateDirectory();
    if (!std::filesystem::exists(directory, error) || error)
        return;
    for (std::filesystem::directory_iterator iterator(directory, error);
         !error && iterator != std::filesystem::directory_iterator(); iterator.increment(error))
    {
        if (iterator->is_regular_file(error) && !error && iterator->path().extension() == L".part")
            std::filesystem::remove(iterator->path(), error);
    }
}

struct DownloadOutcome
{
    enum class Kind
    {
        Completed,
        Cancelled,
        Failed,
    };
    Kind kind = Kind::Failed;
    std::string error;
    std::int64_t received = 0;
};

// 单次尝试。进度节流由本函数负责（kProgressPushIntervalMs），最终态由调用方补推。
DownloadOutcome DownloadOnce(const std::string &url, const std::filesystem::path &destination,
                             const std::atomic<bool> &cancel, const std::function<void(std::int64_t)> &progress)
{
    DownloadOutcome outcome;
    std::wstring host;
    std::wstring path;
    INTERNET_PORT port = 0;
    if (!SplitHttpsUrl(url, host, path, port))
    {
        outcome.error = "下载地址无效";
        return outcome;
    }
    HINTERNET session = NetworkProxy::OpenWinHttpSession(kUserAgent);
    if (session == nullptr)
    {
        outcome.error = "无法初始化网络";
        return outcome;
    }
    WinHttpSetTimeouts(session, 30000, 30000, 30000, 0);
    HINTERNET connection = WinHttpConnect(session, host.c_str(), port, 0);
    HINTERNET request = nullptr;
    if (connection != nullptr)
    {
        request = WinHttpOpenRequest(connection, L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER,
                                     WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (request != nullptr)
        {
            // release 资产经 302 跳到 CDN；镜像同样可能跳。
            DWORD policy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
            WinHttpSetOption(request, WINHTTP_OPTION_REDIRECT_POLICY, &policy, sizeof(policy));
        }
    }
    const bool sent = request != nullptr &&
                      WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
                      WinHttpReceiveResponse(request, nullptr);
    if (!sent)
    {
        outcome.error = "无法连接下载服务器";
        if (request != nullptr)
            WinHttpCloseHandle(request);
        if (connection != nullptr)
            WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return outcome;
    }
    DWORD status = 0;
    DWORD status_size = sizeof(status);
    WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
                        &status, &status_size, WINHTTP_NO_HEADER_INDEX);
    if (status != 200)
    {
        outcome.error = "下载服务器返回 " + std::to_string(status);
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return outcome;
    }
    std::wstring length_header(64, L'\0');
    DWORD length_size = static_cast<DWORD>(length_header.size());
    std::int64_t total = 0;
    if (WinHttpQueryHeaders(request, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX, length_header.data(),
                            &length_size, WINHTTP_NO_HEADER_INDEX))
    {
        try
        {
            total = std::stoll(length_header.c_str());
        }
        catch (...)
        {
            total = 0;
        }
    }
    if (total > 0)
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_status.total_bytes = total;
    }
    std::ofstream output(destination, std::ios::binary | std::ios::trunc);
    if (!output)
    {
        outcome.error = "无法写入临时目录";
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return outcome;
    }
    std::vector<char> buffer(1 << 18);
    bool ok = true;
    std::int64_t received = 0;
    DWORD last_push = GetTickCount();
    while (ok)
    {
        if (cancel.load())
        {
            outcome.kind = DownloadOutcome::Kind::Cancelled;
            break;
        }
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request, &available))
        {
            ok = false;
            break;
        }
        if (available == 0)
        {
            outcome.kind = DownloadOutcome::Kind::Completed;
            break;
        }
        buffer.resize(available);
        DWORD read = 0;
        if (!WinHttpReadData(request, buffer.data(), available, &read) || read == 0)
        {
            ok = false;
            break;
        }
        output.write(buffer.data(), static_cast<std::streamsize>(read));
        if (!output)
        {
            ok = false;
            break;
        }
        received += read;
        outcome.received = received;
        const DWORD now = GetTickCount();
        if (now - last_push >= kProgressPushIntervalMs)
        {
            last_push = now;
            progress(received);
        }
    }
    output.close();
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    if (!ok && outcome.kind != DownloadOutcome::Kind::Cancelled)
        outcome.error = "下载中断";
    return outcome;
}

// 镜像优先，失败回落直链。两者是同一份字节，任一连上即可。
DownloadOutcome DownloadWithFallback(const VersionEntry &entry, const std::filesystem::path &destination,
                                     const std::atomic<bool> &cancel, const std::function<void(std::int64_t)> &progress)
{
    std::vector<std::string> urls;
    if (!entry.mirror_url.empty())
        urls.push_back(entry.mirror_url);
    if (!entry.installer_url.empty() && (entry.mirror_url.empty() || entry.mirror_url != entry.installer_url))
        urls.push_back(entry.installer_url);
    DownloadOutcome outcome;
    for (const std::string &url : urls)
    {
        outcome = DownloadOnce(url, destination, cancel, progress);
        if (outcome.kind != DownloadOutcome::Kind::Failed)
            return outcome;
    }
    return outcome;
}

// 从当前状态里解析要下载的版本。requested 为空表示检测到的最新版。
bool ResolveVersion(const std::string &requested_version, VersionEntry &entry, std::string &error)
{
    const Status status = BuildStatus();

    const VersionEntry *selected = nullptr;
    if (requested_version.empty())
    {
        if (!status.versions.empty())
            selected = &status.versions.front();
    }
    else
    {
        for (const VersionEntry &item : status.versions)
        {
            if (item.version == requested_version)
            {
                selected = &item;
                break;
            }
        }
    }
    if (selected == nullptr)
    {
        error = "没有找到该版本的安装包，请重新检查更新";
        return false;
    }
    if (selected->sha256.empty())
    {
        // 没有公布校验和的版本不能在应用内更新：用户拿不到任何完整性信号。
        error = "该版本未公布校验和，不能在应用内更新，请前往发布页下载";
        return false;
    }
    entry = *selected;
    return true;
}

// 下载 + 校验 + 落位，成功时状态进入 Ready。手动更新与启动自动更新共用这一条路。
bool RunDownload(const VersionEntry &entry)
{
    const std::filesystem::path directory = UpdateDirectory();
    std::error_code error;
    std::filesystem::create_directories(directory, error);
    if (error)
    {
        SetState(State::Error, "无法创建下载目录");
        return false;
    }
    const std::filesystem::path final_path =
        directory / (std::string("MetasequoiaIME_Setup_v") + entry.version + ".exe");
    const std::filesystem::path part_path = final_path.wstring() + L".part";
    RemovePartFiles();

    // 已经下过并校验通过的同一版本直接进入就绪态：重下 90MB 没有意义。
    if (std::filesystem::exists(final_path, error) && !error)
    {
        SetState(State::Verifying, "正在校验已下载的安装包…");
        if (Sha256Hex(final_path) == entry.sha256)
        {
            {
                std::lock_guard<std::mutex> lock(g_mutex);
                g_ready_path = final_path.string();
                g_ready_sha256 = entry.sha256;
                g_status.state = State::Ready;
                g_status.message = "安装包已就绪";
                g_status.version = entry.version;
                g_status.received_bytes = entry.size;
                g_status.total_bytes = entry.size;
                g_status.percent = 100;
            }
            PushStatus();
            return true;
        }
        std::filesystem::remove(final_path, error);
    }

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_status.state = State::Downloading;
        g_status.message = "正在准备下载…";
        g_status.version = entry.version;
        g_status.received_bytes = 0;
        g_status.total_bytes = entry.size;
        g_status.percent = 0;
    }
    PushStatus();

    g_cancel_download.store(false);
    const std::int64_t expected = entry.size;
    const auto progress = [expected](std::int64_t received) {
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_status.state = State::Downloading;
            g_status.received_bytes = received;
            if (expected > 0)
            {
                g_status.total_bytes = expected;
                g_status.percent = static_cast<int>((std::min<std::int64_t>)(100, received * 100 / expected));
                g_status.message = "正在下载 " + std::to_string(g_status.percent) + "%";
            }
            else
            {
                g_status.message = "正在下载…";
            }
        }
        PushStatus();
    };

    const DownloadOutcome outcome = DownloadWithFallback(entry, part_path, g_cancel_download, progress);
    if (outcome.kind == DownloadOutcome::Kind::Cancelled)
    {
        std::filesystem::remove(part_path, error);
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_status.state = State::Idle;
            g_status.message = "下载已取消";
            g_status.version.clear();
            g_status.received_bytes = 0;
            g_status.total_bytes = 0;
            g_status.percent = 0;
        }
        PushStatus();
        return false;
    }
    if (outcome.kind == DownloadOutcome::Kind::Failed)
    {
        std::filesystem::remove(part_path, error);
        SetState(State::Error, outcome.error);
        return false;
    }

    SetState(State::Verifying, "正在校验安装包…");
    if (Sha256Hex(part_path) != entry.sha256)
    {
        std::filesystem::remove(part_path, error);
        SetState(State::Error, "安装包校验和与发布清单不符，已丢弃下载文件");
        return false;
    }
    std::filesystem::rename(part_path, final_path, error);
    if (error)
    {
        std::filesystem::remove(part_path, error);
        SetState(State::Error, "安装包落位失败");
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_ready_path = final_path.string();
        g_ready_sha256 = entry.sha256;
        g_status.state = State::Ready;
        g_status.message = "安装包已就绪，可以安装";
        g_status.version = entry.version;
        g_status.received_bytes = entry.size > 0 ? entry.size : outcome.received;
        g_status.total_bytes = entry.size;
        g_status.percent = 100;
    }
    PushStatus();
    return true;
}

void DoDownload(const std::string &requested_version)
{
    VersionEntry entry;
    std::string error;
    if (!ResolveVersion(requested_version, entry, error))
    {
        SetState(State::Error, error);
        return;
    }
    RunDownload(entry);
}

// ---- 检测 ----

// 手动检测（设置页「检查更新」）：拉清单 + 版本目录，结果经回调推给页面。
void DoCheck()
{
    SetState(State::Checking, "正在检查更新…");
    const ManifestResult manifest = FetchManifest();
    if (!manifest.ok)
    {
        SetState(State::Error, manifest.error);
        return;
    }
    const std::string current = MSIME_VERSION;
    const bool has_update = CompareVersions(manifest.entry.version, current) > 0;
    std::vector<VersionEntry> versions;
    if (has_update)
        versions = MergeCatalog(FetchCatalog(), manifest.entry);
    const std::string checked_at = LocalIsoTimestamp(NowUnixSeconds());

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_status.current_version = current;
        g_status.state = has_update ? State::UpdateAvailable : State::UpToDate;
        g_status.message = has_update ? "发现新版本 v" + manifest.entry.version : "已是最新版本";
        g_status.versions = std::move(versions);
        g_status.last_checked_at = checked_at;
        g_status.version.clear();
        g_status.received_bytes = 0;
        g_status.total_bytes = 0;
        g_status.percent = 0;
    }
    PushStatus();

    // 自动更新的进度记录不动：它描述的是启动路径上一次尝试，与手动检测无关。
    const PersistedState previous = LoadPersistedState();
    SavePersistedState(checked_at, manifest.entry.version, manifest.entry, previous.auto_update_version,
                       previous.auto_update_result);
}

// 启动自动更新（general.auto_update 开启时）：检测 → 直接下载 → 直接拉起安装程序。
// 全程没有界面：UAC 确认就是用户的决策点，拒绝（或下载失败）则留着记录，下次启动重试；
// 安装已启动的版本不再重复，避免每次开机都下一个新版本来临前的同一个包。
void DoAutoUpdate()
{
    const ManifestResult manifest = FetchManifest();
    if (!manifest.ok)
    {
        // 启动路径没有界面可推，失败只落一条时间戳，关于页的「发现新版本」仍来自上次成功检测。
        const PersistedState previous = LoadPersistedState();
        SavePersistedState(previous.last_checked_at, previous.latest_version, previous.latest_entry,
                           previous.auto_update_version, previous.auto_update_result);
        return;
    }
    const std::string current = MSIME_VERSION;
    const std::string checked_at = LocalIsoTimestamp(NowUnixSeconds());
    if (CompareVersions(manifest.entry.version, current) <= 0)
    {
        // 已是最新：记录检测时间即可，自动更新字段清零（装完了或从来没有待装的）。
        SavePersistedState(checked_at, manifest.entry.version, manifest.entry, std::string(), std::string());
        return;
    }

    const PersistedState previous = LoadPersistedState();
    if (previous.auto_update_version == manifest.entry.version && previous.auto_update_result == "installing")
        return; // 这个版本已经下载并启动过安装，不重复

    // 自动更新的进度可见：把设置窗口切到「关于」并进入自动更新模式。下载、校验、
    // 安装的进度都会出现在那里（Server 写状态文件的 live 对象，设置进程来读）。
    OpenSettingsUpdateProgressApplication();

    const std::string latest = manifest.entry.version;
    if (!RunDownload(manifest.entry))
    {
        SavePersistedState(checked_at, latest, manifest.entry, latest, "downloadFailed");
        return;
    }
    std::string install_error;
    if (!StartInstall(install_error))
    {
        SavePersistedState(checked_at, latest, manifest.entry, latest, "launchFailed");
        return;
    }
    // 走到这里安装器已经拉起（UAC 已确认）：Server 和设置进程随后会被它结束。
    SavePersistedState(checked_at, latest, manifest.entry, latest, "installing");
}

void WorkerLoop()
{
    for (;;)
    {
        std::function<void()> job;
        {
            std::unique_lock<std::mutex> lock(g_queue_mutex);
            g_queue_cv.wait(lock, [] { return !g_jobs.empty(); });
            job = std::move(g_jobs.front());
            g_jobs.pop_front();
        }
        try
        {
            job();
        }
        catch (...)
        {
            // 任务里任何未预期异常都不能把工作线程带走，否则模块此后再也无法响应。
        }
        g_busy.store(false);
    }
}

} // namespace

// ---- 公共接口 ----

const char *StateName(State state)
{
    switch (state)
    {
    case State::Idle:
        return "idle";
    case State::Checking:
        return "checking";
    case State::UpToDate:
        return "upToDate";
    case State::UpdateAvailable:
        return "updateAvailable";
    case State::Downloading:
        return "downloading";
    case State::Verifying:
        return "verifying";
    case State::Ready:
        return "ready";
    case State::Installing:
        return "installing";
    case State::Error:
        break;
    }
    return "error";
}

Status GetStatus()
{
    return BuildStatus();
}

bool StartCheck(StatusCallback callback)
{
    bool expected = false;
    if (!g_busy.compare_exchange_strong(expected, true))
        return false;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_callback = std::move(callback);
    }
    SubmitJob([] { DoCheck(); });
    return true;
}

bool StartDownload(const std::string &version, StatusCallback callback)
{
    bool expected = false;
    if (!g_busy.compare_exchange_strong(expected, true))
        return false;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_callback = std::move(callback);
    }
    SubmitJob([version] { DoDownload(version); });
    return true;
}

bool StartInstall(std::string &error)
{
    std::filesystem::path installer;
    std::string expected_sha256;
    std::string install_version;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_status.state != State::Ready || g_ready_path.empty())
        {
            error = "安装包尚未就绪";
            return false;
        }
        installer = g_ready_path;
        expected_sha256 = g_ready_sha256;
        install_version = g_status.version;
    }
    std::error_code exists_error;
    if (!std::filesystem::exists(installer, exists_error) || exists_error)
    {
        SetState(State::Error, "安装包已丢失，请重新下载");
        error = "安装包已丢失，请重新下载";
        return false;
    }
    // 安装包在临时目录躺了整个对话框的交互时间，拉起提升权限的安装程序之前再校验一次。
    if (Sha256Hex(installer) != expected_sha256)
    {
        SetState(State::Error, "安装包校验和与发布清单不符，已取消安装");
        error = "安装包校验和与发布清单不符，已取消安装";
        return false;
    }
    // /SILENT 只显示进度窗口：这是一个约 90MB 的安装，用户应该看得见它在动。
    // 安装器自己会停掉 Watchdog、Server、设置进程和各面板，装完（含静默安装，走
    // [Code] 的 ssDone）再把它们拉起来。
    //
    // 安装器会先把输入法进程（包括本进程）结束掉再替换文件，所以这里不可能等到它
    // 的退出码、也无法在中途更新界面——安装结果由下一个启动的进程在
    // ReconcileAfterInstall 里核对：运行版本 == 在装版本 → 成功（弹设置页「关于」），
    // 否则清掉记录、下次检测重试。
    SHELLEXECUTEINFOW execute_info{sizeof(execute_info)};
    execute_info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    execute_info.lpVerb = L"runas";
    execute_info.lpFile = installer.wstring().c_str();
    execute_info.lpParameters = L"/SILENT /SUPPRESSMSGBOXES /NORESTART";
    execute_info.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&execute_info) || !execute_info.hProcess)
    {
        error = "安装程序启动失败（可能取消了 UAC 授权），请重试";
        return false;
    }
    CloseHandle(execute_info.hProcess);
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_status.state = State::Installing;
        g_status.message = "正在启动安装程序…";
    }
    PushStatus();
    // 记录「正在安装这个版本」：手动与自动两条路共用，供 ReconcileAfterInstall 核对。
    const PersistedState previous = LoadPersistedState();
    SavePersistedState(previous.last_checked_at, previous.latest_version, previous.latest_entry, install_version,
                       "installing");
    return true;
}

void CancelDownload()
{
    g_cancel_download.store(true);
}

void RunAutoUpdate()
{
    if (!GetConfiguredAutoUpdateEnabled())
        return;
    std::thread([] {
        // 等网络就绪：Server 随登录拉起时 Wi-Fi 常常还没连上。
        Sleep(kStartupCheckDelayMs);
        bool expected = false;
        if (!g_busy.compare_exchange_strong(expected, true))
            return;
        SubmitJob([] { DoAutoUpdate(); });
    }).detach();
}

// 状态名 → 枚举（StateName 的逆）。设置页读取 Server 进程写在状态文件里的进度时用。
State StateFromName(const std::string &name)
{
    const State candidates[] = {State::Idle,        State::Checking,  State::UpToDate, State::UpdateAvailable,
                                State::Downloading, State::Verifying, State::Ready,    State::Installing,
                                State::Error};
    for (const State candidate : candidates)
    {
        if (name == StateName(candidate))
            return candidate;
    }
    return State::Idle;
}

bool GetAutoUpdateProgress(Status &out)
{
    const PersistedState persisted = LoadPersistedState();
    if (persisted.live_at <= 0)
        return false;
    const std::int64_t age = NowUnixSeconds() - persisted.live_at;
    // 3 分钟没有刷新视为陈旧：进程在安装前被结束是正常路径，之后进度就该停了。
    if (age < 0 || age > 180)
        return false;
    Status status;
    status.current_version = MSIME_VERSION;
    status.state = StateFromName(persisted.live_state);
    status.message = persisted.live_message;
    status.version = persisted.live_version;
    status.received_bytes = persisted.live_received;
    status.total_bytes = persisted.live_total;
    status.percent = persisted.live_percent;
    out = status;
    return true;
}

Status GetMergedStatus()
{
    const Status status = GetStatus();
    Status live;
    if ((status.state == State::Idle || status.state == State::UpToDate || status.state == State::UpdateAvailable) &&
        GetAutoUpdateProgress(live))
    {
        // 本进程没有自己的活动，而 Server 正在自动更新：展示 Server 的进度。
        return live;
    }
    return status;
}

void ReconcileAfterInstall()
{
    const PersistedState persisted = LoadPersistedState();
    if (persisted.auto_update_result != "installing" || persisted.auto_update_version.empty())
        return;

    const std::string checked_at = LocalIsoTimestamp(NowUnixSeconds());
    if (CompareVersions(persisted.auto_update_version, MSIME_VERSION) <= 0)
    {
        // 正在运行的版本就是（或新于）上次在装的版本：安装成功。清掉尝试记录，
        // 并把设置页拉到「关于」，用户能看到新版本号。
        SavePersistedState(checked_at, persisted.latest_version, persisted.latest_entry, std::string(), std::string());
        OpenSettingsAboutApplication();
        return;
    }
    // 没装上（中止、回滚）：清掉尝试记录，下次自动/手动检测重新尝试。
    SavePersistedState(checked_at, persisted.latest_version, persisted.latest_entry, std::string(), std::string());
}

} // namespace update
