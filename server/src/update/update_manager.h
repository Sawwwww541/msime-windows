#pragma once

// 应用内更新：发布清单检测、版本目录、安装包下载与校验、安装程序拉起。
//
// 数据源分工：
// - https://msime.app/update.json 是「有没有新版」的唯一权威（发布流水线在把安装包挂上
//   Release 的同时更新它），携带最新版的安装包名、SHA256 和签名标记。启动时的自动检测
//   只依赖它，轻量、不经过 GitHub API。
// - GitHub releases API 提供版本目录（可回退的旧版本）。每个 asset 自带 digest 字段，
//   与清单里最新版的 SHA256 同源，所以任意版本都能在下载后校验完整性。
// - 下载走 dl.msime.app 镜像（GitHub 直链在国内常常只有几十 KB/s），失败自动回落直链。
//
// 状态以本进程内存为准，检测/下载结果另落一份状态文件到 <数据目录>/update/state.json：
// Server 启动检测和设置页手动检测是两个进程，靠它共享「这个版本已经提示过用户」，
// 同一个版本不会每次开机都弹一次。
//
// 设置进程（MetasequoiaImeSettings.exe）持有全部用户操作：检测、选版本、下载、安装；
// Server 进程只在启动时按 [general] auto_update 检测一次，发现新版本就打开设置窗口的
// 「关于」页。两边共用本模块，互不依赖。

#include <Windows.h>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace update
{

// 一个可安装的版本。size 为 0 表示未知；sha256 为空表示该版本没有公布校验和
// （此时拒绝应用内下载，引导到发布页）。
struct VersionEntry
{
    std::string version; // "0.10.1"
    bool prerelease = false;
    std::string published_at; // ISO 8601，可能为空
    std::int64_t size = 0;
    std::string installer_url; // GitHub 直链
    std::string mirror_url;    // dl.msime.app 镜像，空 = 没有可镜像的直链
    std::string sha256;        // 小写十六进制
    std::string release_url;   // 发布页
    bool signed_known = false; // 发布清单是否声明了签名状态
    bool is_signed = false;
};

// 运行期状态机。页面只读快照，不在网页侧复制状态机。
enum class State
{
    Idle,            // 本进程还没检测过
    Checking,        // 正在拉发布清单
    UpToDate,        // 已是最新
    UpdateAvailable, // 有新版本（versions 已填好）
    Downloading,     // 正在下载（version / received_bytes / total_bytes 有效）
    Verifying,       // 已下完，正在校验 SHA256
    Ready,           // 已校验通过，安装包就绪
    Installing,      // 安装程序已拉起
    Error,
};

// 状态枚举 → 设置页契约里的字符串（engine/contracts/webview/messages.json）。
const char *StateName(State state);

struct Status
{
    State state = State::Idle;
    std::string current_version; // 编译自 version.txt
    std::string message;         // 状态说明或失败原因
    std::string version;         // 正在下载 / 已就绪的版本
    std::int64_t received_bytes = 0;
    std::int64_t total_bytes = 0;
    int percent = 0;
    std::string last_checked_at;        // 本地时间 ISO 8601，空 = 从未检测成功
    std::vector<VersionEntry> versions; // 检测成功后填充，按版本号降序
};

// 状态推送。从模块的工作线程调用（下载进度有节流），设置进程负责 marshal 到 UI 线程。
using StatusCallback = std::function<void(const Status &)>;

// 当前状态快照，无网络、无阻塞。
Status GetStatus();

// 后台检测：发布清单 + 版本目录，完成后经 callback 推送。前一次检测还在进行时返回 false。
bool StartCheck(StatusCallback callback);

// 后台下载指定版本的安装包并校验 SHA256。下载 / 校验进行中、或该版本没有公布校验和时
// 返回 false（原因见 GetStatus().message）。version 为空表示下载检测到的最新版。
bool StartDownload(const std::string &version, StatusCallback callback);

// 启动安装程序（UAC 提升，静默安装）。仅 Ready 态可调；error 为非空表示失败原因。
bool StartInstall(std::string &error);

// 取消进行中的下载，删除临时文件，状态回 Idle。
void CancelDownload();

// 读取状态文件的实时快照：Server 进程自动更新期间，设置页用它展示进度。
// 返回 false = 文件里没有新鲜的进度记录（从未写过或已过期）。
bool GetAutoUpdateProgress(Status &out);

// 设置页的状态查询用：本进程空闲、而状态文件里有新鲜的自动更新进度时，返回
// Server 的进度状态；否则返回本进程状态。
Status GetMergedStatus();

// Server 启动时调用：核对上次安装的结果——正在运行的版本就是（或新于）上次在装的
// 版本 → 安装成功，清掉尝试记录并弹出设置页「关于」；否则说明没装上（中止、回滚），
// 同样清掉记录，下次自动/手动检测重新尝试。
void ReconcileAfterInstall();

// Server 进程启动时调用：开关关着直接返回；开着则延迟 30 秒（等网络就绪）在后台
// **检测并直接完成下载和安装**：发现新版本就下载安装包、校验 SHA256、拉起安装程序
// （安装器要管理员确认，拒绝则下次启动重试）。同一个版本安装已启动过就不再重复。
void RunAutoUpdate();

} // namespace update
