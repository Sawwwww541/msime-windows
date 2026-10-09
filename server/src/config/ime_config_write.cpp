// 把设置写回 config.toml（批量、保留格式、先校验再原子替换），并通知 Server 重新加载配置或切换输入方案。
#include "config/ime_config_internal.h"
#include <Windows.h>
#include <cwchar>
#include <filesystem>
#include <string>
#include <system_error>
#include <vector>
#include "defines/defines.h"
#include "ipc/ipc.h"

using namespace ime_config_detail;

namespace ime_config_detail
{
bool WriteConfiguredValues(const std::vector<ConfigValueUpdate> &updates)
{
    ConfigFileLock lock;
    if (!lock)
        return false;
    std::error_code exists_error;
    const bool config_exists = std::filesystem::is_regular_file(g_config_path, exists_error);
    const auto config_size =
        config_exists ? std::filesystem::file_size(g_config_path, exists_error) : std::uintmax_t{0};
    std::string text = ReadFileText(g_config_path);
    if (!TomlTextIsParseable(text))
    {
        if (config_exists && config_size > 0 && text.empty())
        {
            return false;
        }
        text = ReadFileText(g_config_path.parent_path() / kConfigTemplateFileName);
        if (!TomlTextIsParseable(text))
        {
            return false;
        }
    }

    for (const auto &update : updates)
    {
        // 凭证类键统一在这里封装：所有写入都经过这条路径，调用方传的一律是用户输入的明文，
        // 落盘的永远是 DPAPI 密文。DPAPI 不可用时 SealSecret 返回空串——那种情况下拒绝本次
        // 写入，而不是退回明文。清空 token 传的是空的字符串字面量 ""，封装后仍是空串，照常保存。
        std::string value = update.value;
        // 只封装字符串字面量：凭证键将来若变成布尔或数值（或调用方误传一个裸量），替换进去的
        // 密文会带引号，把原本的 TOML 类型改掉。形状不对就不动它，宁可漏封也不改类型。
        if (IsSensitiveConfigKey(update.section, update.key) && value.size() >= 2 && value.front() == '"' &&
            value.back() == '"')
        {
            // 设置页收到的是哨兵而不是明文，原样保存时会把哨兵回传——那不是用户输入的新凭证，
            // 跳过这次更新，磁盘上已有的密文保持不变。
            const std::string submitted = UnquoteTomlScalar(value);
            if (submitted == kSealedCredentialSentinel)
            {
                continue;
            }
            value = SealSecret(submitted);
            // 空结果只有在输入本身非空时才算失败：清空凭证传的是空明文，封装后本来就是空串，
            // 那不是 DPAPI 故障，不能因此把整批设置写回一起丢掉。
            if (value.empty() && !submitted.empty())
            {
                return false;
            }
            value = EscapeTomlBasicString(value);
        }
        const bool replaced = ReplaceTomlValuePreservingFormatting(text, update.section, update.key, value);
        const bool applied = replaced || InsertTomlValuePreservingFormatting(text, update.section, update.key, value);
        if (!applied)
        {
            return false;
        }
    }

    try
    {
        (void)toml::parse(text);
    }
    catch (const toml::parse_error &)
    {
        return false;
    }

    // Write a temp file and rename it so a crash can never leave the user with a truncated config. This only makes the
    // directory entry swap atomic: there is no FlushFileBuffers, so a power loss can still lose the contents.
    if (!WriteFileTextAtomically(g_config_path, text))
    {
        return false;
    }

    RememberConfigWriteTime();
    NotifyImeServerConfigChanged();
    return true;
}

bool WriteConfiguredValue(const std::string &section, const std::string &key, const std::string &replacement)
{
    return WriteConfiguredValues({{section, key, replacement}});
}
} // namespace ime_config_detail

namespace
{
HWND FindImeServerCandidateWindow()
{
    // Candidate, tray menu, and floating toolbar share the same class. FindWindow
    // without a title often hits the toolbar, which does not apply config.
    if (const HWND hwnd = FindWindowW(L"metasequoiaime_windows", L"metaseuqoiaimecandwnd"))
    {
        return hwnd;
    }
    return FindWindowW(L"metasequoiaime_windows", nullptr);
}

bool SendAuxConfigNotification(const wchar_t *message)
{
    HANDLE pipe = CreateFileW(FANY_IME_AUX_NAMED_PIPE, GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE && GetLastError() == ERROR_PIPE_BUSY &&
        WaitNamedPipeW(FANY_IME_AUX_NAMED_PIPE, 200))
    {
        pipe = CreateFileW(FANY_IME_AUX_NAMED_PIPE, GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    }
    if (pipe == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    DWORD bytesWritten = 0;
    const DWORD byteCount = static_cast<DWORD>(wcslen(message) * sizeof(wchar_t));
    const bool sent = WriteFile(pipe, message, byteCount, &bytesWritten, nullptr) != FALSE && bytesWritten == byteCount;
    CloseHandle(pipe);
    return sent;
}
} // namespace

namespace ime_config_detail
{
void NotifyImeServer(UINT windowMessage, const wchar_t *auxMessage, WPARAM wParam)
{
    const HWND hwnd = FindImeServerCandidateWindow();
    DWORD serverProcessId = 0;
    if (hwnd)
    {
        GetWindowThreadProcessId(hwnd, &serverProcessId);
    }

    if (serverProcessId == GetCurrentProcessId())
    {
        PostMessageW(hwnd, windowMessage, wParam, 0);
        return;
    }

    // MetasequoiaImeServer runs with uiAccess while the standalone Settings
    // process does not. Cross-process WM_USER delivery can therefore be
    // rejected by UIPI. The session-less Aux pipe is already the supported
    // cross-integrity control path; use it for config invalidation as well.
    if (!SendAuxConfigNotification(auxMessage) && hwnd)
    {
        // Retain the old route as a best-effort fallback. The Server's periodic
        // file watcher remains the final recovery path if both transports are
        // temporarily unavailable during startup.
        PostMessageW(hwnd, windowMessage, wParam, 0);
    }
}
} // namespace ime_config_detail

void NotifyImeServerConfigChanged()
{
    NotifyImeServer(WM_APPLY_IME_CONFIG, L"ConfigChanged");
}

void NotifyImeServerCandidateSkinRefresh()
{
    NotifyImeServer(WM_APPLY_IME_CONFIG, L"CandidateSkinRefresh", 1);
}

void NotifyImeServerInputSchemeChanged()
{
    NotifyImeServer(WM_APPLY_IME_INPUT_SCHEME, L"InputSchemeChanged");
}

bool NotifyImeServerRestart()
{
    // No window message carries a restart, so there is no PostMessage fallback
    // here: if the Aux pipe is unavailable the Server is not running anyway, and
    // the caller reports that instead of silently doing nothing.
    return SendAuxConfigNotification(L"RestartServer");
}
