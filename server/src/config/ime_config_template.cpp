// 升级时以安装包出厂模板为骨架重建用户配置：模板合并、凭证兜底重放、损坏配置的留证与抢救，
// 以及旧 ACP 乱码目录的配置找回。
#include "config/ime_config_internal.h"
#include <fmt/xchar.h>
#include <Windows.h>
#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <system_error>
#include <utility>
#include <vector>
#include "voice-input/voice_providers.h"

using namespace ime_config_detail;

namespace
{
// 凭证类键：token / api_key / secret 等，以及每个提供商单独保存的 token 槽位
// （token_<provider> / asr_token[_<provider>] / polish_token[_<provider>]）。这类值一旦丢失，
// 用户就得重新去各家控制台申请再填一遍，是升级里代价最高的配置，所以单独兜底：不管模板怎么漂移、
// 文件是否损坏，只要用户填过真值就一条都不能丢。
bool IsCredentialKey(const std::string &key)
{
    static const std::set<std::string> exact = {"token",  "api_key",     "apikey",    "secret_id",   "secret_key",
                                                "app_id", "asr_app_key", "asr_token", "polish_token"};
    if (exact.count(key) != 0)
    {
        return true;
    }
    return key.rfind("token_", 0) == 0 || key.rfind("asr_token_", 0) == 0 || key.rfind("polish_token_", 0) == 0;
}

// 剥掉单行 TOML 字符串两侧的引号。凭证值从不跨行，够用了。
std::string UnquoteTomlScalar(const std::string &value)
{
    if (value.size() >= 2 && (value.front() == '"' || value.front() == '\'') && value.back() == value.front())
    {
        return value.substr(1, value.size() - 2);
    }
    return value;
}

// 用户是否真的填过这个凭证：区别于出厂占位符（<YOUR_...> / FAKESECRET_ / 空）。assignment_id 为
// MakeTomlAssignmentId 生成的 "section\x01key"。
bool AssignmentHoldsRealCredential(const std::string &assignment_id, const std::string &raw_value)
{
    const size_t separator = assignment_id.find('\x01');
    const std::string key = separator == std::string::npos ? assignment_id : assignment_id.substr(separator + 1);
    if (!IsCredentialKey(key))
    {
        return false;
    }
    return !VoiceInput::IsPlaceholderToken(UnquoteTomlScalar(raw_value));
}

// 损坏留证时不要顺手把明文凭证也留一份。那种文本解析不过，只能按行找 `key = "..."`，好在凭证
// 永远是单行基本字符串。留证的价值在于看清是什么字符破坏了 TOML，这一点不受影响。
std::string SealPlaintextSecretsLineOriented(const std::string &text)
{
    std::string sealed_text = text;
    std::string section;
    size_t line_begin = 0;
    while (line_begin <= sealed_text.size())
    {
        const size_t line_end = sealed_text.find('\n', line_begin);
        const size_t stop = line_end == std::string::npos ? sealed_text.size() : line_end;
        const std::string line = sealed_text.substr(line_begin, stop - line_begin);
        const size_t first = line.find_first_not_of(" \t\r");
        if (first != std::string::npos && line[first] == '[')
        {
            const size_t close = line.find(']', first);
            if (close != std::string::npos)
            {
                section = line.substr(first + 1, close - first - 1);
            }
        }
        else
        {
            const size_t equals = line.find('=');
            if (equals != std::string::npos && equals > first)
            {
                std::string key = line.substr(first, equals - first);
                const size_t key_end = key.find_last_not_of(" \t");
                if (key_end != std::string::npos)
                {
                    key.erase(key_end + 1);
                }
                const size_t quote = line.find('"', equals);
                const size_t closing_quote = quote == std::string::npos ? std::string::npos : line.find('"', quote + 1);
                if (IsSensitiveConfigKey(section, key) && closing_quote != std::string::npos)
                {
                    // 只封「用户填过真值的明文」：空值、出厂占位符和已经是密文的一律原样留证。
                    const std::string plaintext = line.substr(quote + 1, closing_quote - quote - 1);
                    const bool needs_sealing =
                        !plaintext.empty() && !IsSealedSecret(plaintext) && !VoiceInput::IsPlaceholderToken(plaintext);
                    if (needs_sealing)
                    {
                        const std::string value = SealSecret(plaintext);
                        if (!value.empty())
                        {
                            sealed_text.replace(line_begin + quote + 1, closing_quote - quote - 1, value);
                        }
                    }
                }
            }
        }
        if (line_end == std::string::npos)
        {
            break;
        }
        line_begin = line_end + 1;
    }
    return sealed_text;
}

// 把用户填过真值的凭证逐条重放到 text 上：有键改值，无键则在其分节里插入。幂等——重放已经等于
// 目标值的凭证不改变结果。既给正常合并兜底（新模板漏掉某个凭证键的模板漂移），也给损坏配置的抢救
// 路径兜底（整体合并失败、只能回退到出厂模板时，仍保住 token）。
std::string ReapplyRealCredentials(std::string text, const std::map<std::string, std::string> &user_values)
{
    for (const auto &entry : user_values)
    {
        if (!AssignmentHoldsRealCredential(entry.first, entry.second))
        {
            continue;
        }
        const size_t separator = entry.first.find('\x01');
        const std::string section = separator == std::string::npos ? std::string() : entry.first.substr(0, separator);
        const std::string key = separator == std::string::npos ? entry.first : entry.first.substr(separator + 1);
        if (!ReplaceTomlValuePreservingFormatting(text, section, key, entry.second))
        {
            InsertTomlValuePreservingFormatting(text, section, key, entry.second);
        }
    }
    return text;
}

// 以新模板为骨架（注释、分节顺序、新增项都来自新版），只把用户改过的值填回去。
std::string MergeTomlIntoTemplate(const std::string &template_text, std::map<std::string, std::string> user_values,
                                  const std::map<std::string, std::string> &baseline_values)
{
    const auto fallback_id = MakeTomlAssignmentId("appearance", "fallback_fonts");
    if (!user_values.empty() && user_values.find(fallback_id) == user_values.end())
    {
        const auto font = user_values.find(MakeTomlAssignmentId("appearance", "font"));
        const auto default_font = user_values.find(MakeTomlAssignmentId("appearance", "default_font"));
        user_values[fallback_id] = "[" + (font == user_values.end() ? "\"Noto Sans SC\"" : font->second) + ", " +
                                   (default_font == user_values.end() ? "\"Microsoft YaHei\"" : default_font->second) +
                                   "]";
    }
    struct ValuePatch
    {
        size_t begin;
        size_t end;
        std::string value;
    };
    std::vector<ValuePatch> patches;

    ForEachTomlAssignment(
        template_text, [&](const std::string &section, const std::string &key, size_t value_begin, size_t value_end) {
            const std::string id = MakeTomlAssignmentId(section, key);
            const auto user = user_values.find(id);
            if (user == user_values.end())
            {
                return;
            }
            // 仍等于上一版默认值，说明用户没动过这一项，让新版默认值生效。
            const auto baseline = baseline_values.find(id);
            if (baseline != baseline_values.end() && baseline->second == user->second)
            {
                return;
            }
            patches.push_back({value_begin, value_end, user->second});
        });

    std::string merged = template_text;
    for (auto patch = patches.rbegin(); patch != patches.rend(); ++patch)
    {
        merged.replace(patch->begin, patch->end - patch->begin, patch->value);
    }
    merged = ReapplyRealCredentials(std::move(merged), user_values);
    return merged;
}

std::filesystem::path AcpDecodedUtf8Path(const std::filesystem::path &wide_path)
{
    try
    {
        return std::filesystem::path(wide_path.u8string());
    }
    catch (...)
    {
        return {};
    }
}

// 把一份解析不过的 config.toml 留证到 config.toml.corrupt-<时间戳>，方便事后排查到底是什么
// 字符破坏了 TOML，也给用户一个手工找回的机会。留证前先把明文凭证封上——坏文件同样是落在用户
// 目录里的一个纯文本文件，不能因为它「已经坏了」就把凭证明文留在那里。备份失败不影响后续流程。
void BackupCorruptConfig(const std::string &corrupt_text)
{
    SYSTEMTIME now{};
    GetLocalTime(&now);
    const std::wstring name = fmt::format(L"config.toml.corrupt-{:04}{:02}{:02}-{:02}{:02}{:02}", now.wYear, now.wMonth,
                                          now.wDay, now.wHour, now.wMinute, now.wSecond);
    WriteFileBytes(g_config_path.parent_path() / name, SealPlaintextSecretsLineOriented(corrupt_text));
}
} // namespace

namespace ime_config_detail
{
void RecoverLegacyAcpMangledConfig()
{
    const std::filesystem::path data_dir = g_config_path.parent_path();
    const std::filesystem::path mangled_dir = AcpDecodedUtf8Path(data_dir);
    if (mangled_dir.empty() || mangled_dir == data_dir)
    {
        return;
    }

    const std::filesystem::path mangled_config = mangled_dir / L"config.toml";
    std::error_code error;
    if (!std::filesystem::is_regular_file(mangled_config, error))
    {
        return;
    }

    const std::string mangled_text = ReadFileText(mangled_config);
    if (!TomlTextIsParseable(mangled_text))
    {
        return;
    }

    ConfigFileLock lock;
    if (!lock)
    {
        return;
    }

    const std::string real_text = ReadFileText(g_config_path);
    const std::string template_text = ReadFileText(data_dir / kConfigTemplateFileName);
    const bool real_unusable = !TomlTextIsParseable(real_text);
    const bool real_is_stock = !template_text.empty() && real_text == template_text;
    const bool real_never_saved = !std::filesystem::is_regular_file(data_dir / kConfigBaselineFileName, error);
    if (!real_unusable && !real_is_stock && !real_never_saved)
    {
        return;
    }

    // 找回的那份配置里如果有明文凭证，落地前先封上，别让「找回」变成把明文又抄一遍。
    std::string restored_text = mangled_text;
    SealConfigSecrets(restored_text);
    if (!WriteFileTextAtomically(g_config_path, restored_text))
    {
        return;
    }

    const std::filesystem::path mangled_baseline = mangled_dir / kConfigBaselineFileName;
    if (std::filesystem::is_regular_file(mangled_baseline, error))
    {
        const std::string baseline_text = ReadFileText(mangled_baseline);
        if (!baseline_text.empty())
        {
            WriteFileTextAtomically(data_dir / kConfigBaselineFileName, baseline_text);
        }
    }
}

void SyncConfigWithInstalledTemplate()
{
    const std::filesystem::path data_dir = g_config_path.parent_path();
    const std::filesystem::path template_path = data_dir / kConfigTemplateFileName;
    const std::string template_text = ReadFileText(template_path);
    if (template_text.empty())
    {
        return;
    }

    ConfigFileLock lock;
    if (!lock)
    {
        return;
    }

    const std::filesystem::path baseline_path = data_dir / kConfigBaselineFileName;
    std::error_code exists_error;
    const bool config_exists = std::filesystem::is_regular_file(g_config_path, exists_error);
    const auto config_size =
        config_exists ? std::filesystem::file_size(g_config_path, exists_error) : std::uintmax_t{0};
    const std::string user_text = ReadFileText(g_config_path);
    if (!TomlTextIsParseable(user_text))
    {
        if (config_exists && config_size > 0 && user_text.empty())
        {
            // 文件在、非空，却读出空串：多半是读取失败而非真的空，绝不能拿模板覆盖。
            return;
        }
        // 走到这里：config.toml 存在、非空，但解析不过（上次写入被打断留下半截文件，或某个值里混入了
        // 破坏 TOML 的字符）。旧逻辑直接拿模板覆盖，等于把用户全部配置——尤其是 API token——清零，
        // 这正是「更新后 token 又要重填」的根因。改为：先备份坏文件留证，再逐行抢救出可识别的赋值重放
        // 到新模板上；即便整体抢救结果仍解析不过，也只回退到「模板 + 重放凭证」，保住最难重填的 token。
        if (config_exists && config_size > 0)
        {
            BackupCorruptConfig(user_text);
            const std::map<std::string, std::string> salvaged_values = ParseTomlAssignments(user_text);
            std::string salvaged = MergeTomlIntoTemplate(template_text, salvaged_values, {});
            SealConfigSecrets(salvaged);
            if (TomlTextIsParseable(salvaged))
            {
                if (WriteFileTextAtomically(g_config_path, salvaged))
                {
                    WriteFileTextAtomically(baseline_path, template_text);
                }
                return;
            }
            const std::string fallback = ReapplyRealCredentials(template_text, salvaged_values);
            std::string sealed_fallback = fallback;
            SealConfigSecrets(sealed_fallback);
            if (TomlTextIsParseable(sealed_fallback) && WriteFileTextAtomically(g_config_path, sealed_fallback))
            {
                WriteFileTextAtomically(baseline_path, template_text);
                return;
            }
        }
        if (WriteFileTextAtomically(g_config_path, template_text))
        {
            WriteFileTextAtomically(baseline_path, template_text);
        }
        return;
    }

    const std::string baseline_text = ReadFileText(baseline_path);
    if (baseline_text == template_text)
    {
        return;
    }

    // merged 里的凭证是明文（解析时已解封、重放时按新模板填回），落盘前统一封装。这样
    // MergeTomlIntoTemplate 保持「文本进、文本出」的纯函数语义，密文形式只由写盘这一步决定。
    std::string merged =
        MergeTomlIntoTemplate(template_text, ParseTomlAssignments(user_text), ParseTomlAssignments(baseline_text));
    SealConfigSecrets(merged);
    if (!TomlTextIsParseable(merged))
    {
        return;
    }

    if (WriteFileTextAtomically(g_config_path, merged))
    {
        WriteFileTextAtomically(baseline_path, template_text);
    }
}
} // namespace ime_config_detail

std::string MergeConfigIntoTemplate(const std::string &template_text, const std::string &user_text,
                                    const std::string &baseline_text)
{
    return MergeTomlIntoTemplate(template_text, ParseTomlAssignments(user_text), ParseTomlAssignments(baseline_text));
}
