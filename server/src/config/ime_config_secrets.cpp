// config.toml 里 API 凭证的 DPAPI 落盘保护：封装 / 解封、整份文本的就地封装，以及升级时把老版本
// 留下的明文凭证清掉。设计说明见 ime_config_secrets.h。
#include "config/ime_config_secrets.h"
#include "config/ime_config_internal.h"
#include <Windows.h>
#include <dpapi.h>
#include <cstddef>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <vector>
#include "voice-input/voice_providers.h"

using namespace ime_config_detail;

namespace
{
// 落盘标记。头部之后是 base64 的 DPAPI blob，只含 [A-Za-z0-9+/=]，塞进 TOML 基本字符串不需要转义。
constexpr std::string_view kSealedPrefix = "dpapi:v1:";

// DPAPI blob 至少几十字节，base64 之后远长于这个下限；过短说明是用户手打的普通值，不是密文。
constexpr size_t kMinSealedBase64Length = 40;

// 传给 DPAPI 的附加熵。它本身不是密钥（就在二进制里，谁都读得到），作用是把 blob 圈定在
// 「本产品的配置凭证」这个用途上：用户目录里其他用 DPAPI 保护的数据不会被这份配置解开。
constexpr char kSecretEntropy[] = "MetasequoiaIME/config.toml/credentials/v1";

// 凭证键名 → 允许出现的分节。带分节判断，免得把皮肤、代理之类同名的普通字段一起封掉。
const std::map<std::string, std::set<std::string>> &SensitiveKeysBySection()
{
    static const std::map<std::string, std::set<std::string>> table = {
        {"voice_input",
         {"asr_app_key", "asr_token", "asr_token_doubao", "asr_token_openai", "asr_token_siliconflow", "asr_token_groq",
          "polish_token", "polish_token_siliconflow", "polish_token_openai", "polish_token_deepseek",
          "polish_token_groq"}},
        {"ai_assistant", {"token", "token_deepseek", "token_openai", "token_siliconflow", "token_groq"}},
        {"tencent_tmt", {"secret_id", "secret_key"}},
        {"custom_translation", {"api_key"}},
        {"niutrans", {"app_id", "apikey"}},
    };
    return table;
}

// 出厂占位符不是秘密，封了反而看不出「用户没填过」。沿用与运行时同一套判定。
// 下发给设置页的哨兵同样按「不是秘密」处理：它是本方案自己的标记，既不能被封装（真封了就会
// 变成一个能解开的凭证），也不能被当成用户填过的值。
bool IsPlaceholderValue(const std::string &value)
{
    return value == kSealedCredentialSentinel || VoiceInput::IsPlaceholderToken(value);
}

// 需要并且可以落盘封装：明文非空、不是占位符、还不是密文。
bool NeedsSealing(const std::string &plaintext)
{
    return !plaintext.empty() && !IsSealedSecret(plaintext) && !IsPlaceholderValue(plaintext);
}

// 分节名与键名统一按小写比较：TOML 键区分大小写，但把大小写差异也算成凭证更安全。
std::string AsciiLower(std::string value)
{
    for (char &ch : value)
    {
        if (ch >= 'A' && ch <= 'Z')
        {
            ch = static_cast<char>(ch - 'A' + 'a');
        }
    }
    return value;
}

// 分节名缺失时（调用方只知道键名，比如写入路径）退一步只按键名判断：凭证键名本身在本产品里
// 没有歧义，宁可多封一个也不会漏封；带分节的精确判断始终优先。
bool SensitiveKeyExistsAnywhere(std::string_view key)
{
    const std::string lowered = AsciiLower(std::string(key));
    for (const auto &entry : SensitiveKeysBySection())
    {
        if (entry.second.count(lowered) != 0)
        {
            return true;
        }
    }
    return false;
}

std::string Base64Encode(const std::vector<BYTE> &bytes)
{
    if (bytes.empty())
    {
        return {};
    }
    DWORD chars = 0;
    if (!CryptBinaryToStringA(bytes.data(), static_cast<DWORD>(bytes.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                              nullptr, &chars) ||
        chars == 0)
    {
        return {};
    }
    std::string base64(chars, '\0');
    if (!CryptBinaryToStringA(bytes.data(), static_cast<DWORD>(bytes.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                              base64.data(), &chars))
    {
        return {};
    }
    base64.resize(chars);
    return base64;
}

bool Base64Decode(const std::string &base64, std::vector<BYTE> &bytes)
{
    if (base64.empty())
    {
        return false;
    }
    DWORD byte_count = 0;
    if (!CryptStringToBinaryA(base64.c_str(), static_cast<DWORD>(base64.size()), CRYPT_STRING_BASE64, nullptr,
                              &byte_count, nullptr, nullptr) ||
        byte_count == 0)
    {
        return false;
    }
    bytes.assign(byte_count, 0);
    return CryptStringToBinaryA(base64.c_str(), static_cast<DWORD>(base64.size()), CRYPT_STRING_BASE64, bytes.data(),
                                &byte_count, nullptr, nullptr) != FALSE;
}

// DPAPI 的输出缓冲要用 LocalFree 释放；这两个包装保证任何提前返回都不漏。
bool ProtectWithDpapi(const std::string &plaintext, std::vector<BYTE> &output)
{
    DATA_BLOB input{};
    input.pbData = reinterpret_cast<BYTE *>(const_cast<char *>(plaintext.data()));
    input.cbData = static_cast<DWORD>(plaintext.size());
    DATA_BLOB entropy{};
    entropy.pbData = reinterpret_cast<BYTE *>(const_cast<char *>(kSecretEntropy));
    entropy.cbData = static_cast<DWORD>(sizeof(kSecretEntropy) - 1);
    DATA_BLOB protected_blob{};
    const BOOL ok = CryptProtectData(&input, L"MetasequoiaIME config credential", &entropy, nullptr, nullptr,
                                     CRYPTPROTECT_UI_FORBIDDEN, &protected_blob);
    if (!ok || protected_blob.pbData == nullptr || protected_blob.cbData == 0)
    {
        return false;
    }
    output.assign(protected_blob.pbData, protected_blob.pbData + protected_blob.cbData);
    LocalFree(protected_blob.pbData);
    return true;
}

bool UnprotectWithDpapi(const std::vector<BYTE> &sealed_bytes, std::string &plaintext)
{
    if (sealed_bytes.empty())
    {
        return false;
    }
    DATA_BLOB input{};
    input.pbData = const_cast<BYTE *>(sealed_bytes.data());
    input.cbData = static_cast<DWORD>(sealed_bytes.size());
    DATA_BLOB entropy{};
    entropy.pbData = reinterpret_cast<BYTE *>(const_cast<char *>(kSecretEntropy));
    entropy.cbData = static_cast<DWORD>(sizeof(kSecretEntropy) - 1);
    DATA_BLOB plain_blob{};
    const BOOL ok =
        CryptUnprotectData(&input, nullptr, &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &plain_blob);
    if (!ok || plain_blob.pbData == nullptr)
    {
        return false;
    }
    plaintext.assign(reinterpret_cast<const char *>(plain_blob.pbData), plain_blob.cbData);
    LocalFree(plain_blob.pbData);
    return true;
}

// 值为单行基本字符串时取出引号内的原文；其余形状（多行、数组、非字符串）返回 false：
// 凭证永远是单行字符串，形状不对就不要动它。
bool BareStringLiteral(const std::string &raw_value, std::string &out)
{
    if (raw_value.size() < 2 || raw_value.front() != '"' || raw_value.back() != '"' ||
        raw_value.find('\n') != std::string::npos)
    {
        return false;
    }
    out = raw_value.substr(1, raw_value.size() - 2);
    return true;
}
} // namespace

namespace ime_config_detail
{
// 下发给设置页前的收敛：只把「真凭证」换成哨兵，空值和出厂占位符原样传下去。
// 定义放在具名命名空间里而不是文件内的匿名命名空间，因为设置页与 WebView2 宿主两个
// 可执行文件都要链接它。
std::string MaskSealedCredential(std::string_view value)
{
    const std::string owned(value);
    // 内存里常驻的是密文，而刚提交、还没写完的值可能还是明文，两种形态都不能下发。
    if (owned.empty() || IsPlaceholderValue(owned))
    {
        return owned;
    }
    return std::string(kSealedCredentialSentinel);
}

bool IsSensitiveConfigKey(std::string_view section, std::string_view key)
{
    const std::string key_id = AsciiLower(std::string(key));
    if (section.empty())
    {
        return SensitiveKeyExistsAnywhere(key_id);
    }
    const std::string section_id = AsciiLower(std::string(section));
    const auto found = SensitiveKeysBySection().find(section_id);
    if (found == SensitiveKeysBySection().end())
    {
        return false;
    }
    return found->second.count(key_id) != 0;
}

bool IsSealedSecret(std::string_view value)
{
    if (value.size() < kSealedPrefix.size() || value.compare(0, kSealedPrefix.size(), kSealedPrefix) != 0)
    {
        return false;
    }
    return value.size() - kSealedPrefix.size() >= kMinSealedBase64Length;
}

std::string SealSecret(std::string_view plaintext)
{
    if (!NeedsSealing(std::string(plaintext)))
    {
        return std::string(plaintext);
    }
    std::vector<BYTE> sealed_bytes;
    if (!ProtectWithDpapi(std::string(plaintext), sealed_bytes))
    {
        // 空串 = 封装失败。调用方必须据此放弃本次写入，任何情况下都不退回明文。
        return {};
    }
    const std::string base64 = Base64Encode(sealed_bytes);
    if (base64.empty())
    {
        return {};
    }
    return std::string(kSealedPrefix) + base64;
}

std::string SealForMemory(std::string_view section, std::string_view key, std::string_view value)
{
    if (!IsSensitiveConfigKey(section, key))
    {
        return std::string(value);
    }
    const std::string sealed = SealSecret(value);
    return sealed.empty() ? std::string(value) : sealed;
}

std::string UnsealSecret(std::string_view stored)
{
    if (!IsSealedSecret(stored))
    {
        return std::string(stored);
    }
    std::vector<BYTE> sealed_bytes;
    std::string plaintext;
    if (!Base64Decode(std::string(stored.substr(kSealedPrefix.size())), sealed_bytes) ||
        !UnprotectWithDpapi(sealed_bytes, plaintext))
    {
        // 解不开就原样交出去：调用方的占位符过滤会把它当成不可用凭证（不会把密文发给服务方），
        // 而用户填过的值也不会在内存里被抹成空。
        return std::string(stored);
    }
    return plaintext;
}

std::string UnquoteTomlScalar(const std::string &value)
{
    if (value.size() >= 2 && (value.front() == '"' || value.front() == '\'') && value.back() == value.front())
    {
        return value.substr(1, value.size() - 2);
    }
    return value;
}

bool SealConfigSecrets(std::string &text)
{
    struct ValuePatch
    {
        size_t begin;
        size_t end;
        std::string value;
    };
    std::vector<ValuePatch> patches;
    ForEachTomlAssignment(
        text, [&](const std::string &section, const std::string &key, size_t value_begin, size_t value_end) {
            if (!IsSensitiveConfigKey(section, key))
            {
                return;
            }
            std::string plaintext;
            if (!BareStringLiteral(text.substr(value_begin, value_end - value_begin), plaintext) ||
                !NeedsSealing(plaintext))
            {
                return;
            }
            const std::string sealed = SealSecret(plaintext);
            if (sealed.empty())
            {
                // 封装失败：不动这条，交给调用方决定是否继续。
                return;
            }
            patches.push_back({value_begin, value_end, EscapeTomlBasicString(sealed)});
        });
    if (patches.empty())
    {
        return false;
    }
    // 从后往前替换，前面的偏移才不会因为长度变化而失效。
    for (auto patch = patches.rbegin(); patch != patches.rend(); ++patch)
    {
        text.replace(patch->begin, patch->end - patch->begin, patch->value);
    }
    return true;
}

bool SealPlaintextConfigSecretsOnDisk()
{
    ConfigFileLock lock;
    if (!lock)
    {
        return false;
    }
    const std::string text = ReadFileText(g_config_path);
    if (text.empty())
    {
        return false;
    }
    std::string sealed_text = text;
    if (!SealConfigSecrets(sealed_text) || !TomlTextIsParseable(sealed_text) ||
        !WriteFileTextAtomically(g_config_path, sealed_text))
    {
        return false;
    }
    // 写成时间与 Server 通知都要跟上：这里和 WriteConfiguredValues 走的是同一条「文件刚变过」的约定，
    // 漏掉任何一个都会让内存里的凭证与磁盘上的密文对不上。
    RememberConfigWriteTime();
    NotifyImeServerConfigChanged();
    return true;
}
} // namespace ime_config_detail
