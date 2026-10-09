// config.toml 凭证加密（DPAPI）的回归测试。这里锁死六条契约：
// 1. 密文不泄露明文，且能原样解回；
// 2. 出厂占位符与空值不封——它们不是秘密，封了会让「用户没填过」和「填过」再也分不开；
// 3. 读路径（ParseTomlAssignments）拿到的是明文，写路径落盘的是密文——这条一旦断了，
//    凭证会以密文形式发给服务方，表现为「填了 token 却一直鉴权失败」；
// 4. 下发给设置页的是哨兵而不是明文，且页面把哨兵原样回传时不得覆盖磁盘上已有的密文；
// 5. 清空凭证（空明文）照样能写：它不是 DPAPI 故障，不能连带丢掉同批次的其他改动；
// 6. 内存里存的同样是密文：明文只在「马上要发请求」的那一刻解出来（见
//    credentials_are_sealed_in_memory_and_unsealed_only_for_requests）。这条一旦断了，
//    磁盘上的加密就形同虚设——读一次进程内存就能拿走全部 key。
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "config/ime_config.h"
#include "config/ime_config_internal.h"
#include "tests/includes/test_framework.h"
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

using namespace ime_config_detail;

namespace
{
// 把配置目录重定向到一次性目录：写路径的用例会真实落盘，绝不能碰开发机的用户配置。
// METASEQUOIA_IME_CONFIG_DIR 只改配置位置，不动数据目录，所以引擎侧不受影响。
class ScopedConfigRoot
{
  public:
    ScopedConfigRoot()
    {
        previous_ = ReadEnv(L"METASEQUOIA_IME_CONFIG_DIR", had_previous_);
        data_previous_ = ReadEnv(L"METASEQUOIA_IME_DATA_DIR", data_had_previous_);
        root_ = std::filesystem::temp_directory_path() /
                (L"msime-config-secrets-test-" + std::to_wstring(GetCurrentProcessId()));
        std::error_code ec;
        std::filesystem::remove_all(root_, ec);
        std::filesystem::create_directories(root_, ec);
        REQUIRE(!ec);
        REQUIRE(std::filesystem::copy_file(MSIME_DEFAULT_CONFIG_PATH, root_ / L"config.default.toml",
                                           std::filesystem::copy_options::overwrite_existing, ec));
        REQUIRE(!ec);
        SetEnvironmentVariableW(L"METASEQUOIA_IME_CONFIG_DIR", root_.c_str());
        SetEnvironmentVariableW(L"METASEQUOIA_IME_DATA_DIR", root_.c_str());
    }
    ~ScopedConfigRoot()
    {
        SetEnvironmentVariableW(L"METASEQUOIA_IME_CONFIG_DIR", had_previous_ ? previous_.c_str() : nullptr);
        SetEnvironmentVariableW(L"METASEQUOIA_IME_DATA_DIR", data_had_previous_ ? data_previous_.c_str() : nullptr);
        std::error_code ec;
        std::filesystem::remove_all(root_, ec);
    }
    ScopedConfigRoot(const ScopedConfigRoot &) = delete;
    ScopedConfigRoot &operator=(const ScopedConfigRoot &) = delete;

    const std::filesystem::path &root() const
    {
        return root_;
    }

  private:
    static std::wstring ReadEnv(const wchar_t *name, bool &had_previous)
    {
        wchar_t buffer[32768];
        const DWORD length = GetEnvironmentVariableW(name, buffer, 32768);
        had_previous = length != 0 || GetLastError() != ERROR_ENVVAR_NOT_FOUND;
        return std::wstring(buffer, length);
    }

    std::wstring previous_;
    bool had_previous_ = false;
    std::wstring data_previous_;
    bool data_had_previous_ = false;
    std::filesystem::path root_;
};

std::string ReadConfigText(const std::filesystem::path &path)
{
    std::ifstream input(path, std::ios::binary);
    REQUIRE(static_cast<bool>(input));
    return std::string((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
}

// 与写入侧同一个入口：设置页的一次保存就是若干个 ConfigValueUpdate。
bool WriteCredential(const char *section, const char *key, const std::string &raw_value)
{
    return WriteConfiguredValues({{section, key, EscapeTomlBasicString(raw_value)}});
}
} // namespace

TEST_CASE(sealed_secret_hides_plaintext_and_round_trips)
{
    const std::string plaintext = "sk-live-0123456789abcdef";
    const std::string sealed = SealSecret(plaintext);
    REQUIRE(!sealed.empty());
    REQUIRE(IsSealedSecret(sealed));
    // 密文里绝不能出现明文本身，否则加密没有任何意义。
    REQUIRE(sealed.find(plaintext) == std::string::npos);
    REQUIRE_EQ(UnsealSecret(sealed), plaintext);
}

TEST_CASE(sealed_secret_is_idempotent)
{
    // 写入路径可能把已经封装过的值再交进来一次（例如合并后重放），重复封装必须是无操作，
    // 否则密文会被再包一层，用户每次改配置都多一层、且再也解不回原始值。
    const std::string sealed = SealSecret("sk-live-0123456789abcdef");
    REQUIRE_EQ(SealSecret(sealed), sealed);
    REQUIRE_EQ(UnsealSecret(SealSecret(sealed)), std::string("sk-live-0123456789abcdef"));
}

TEST_CASE(plaintext_and_foreign_values_pass_through_unchanged)
{
    // 空值：用户清空 token 后保存，不能因此报错或产生密文。
    REQUIRE(SealSecret("").empty());
    REQUIRE(UnsealSecret("").empty());
    // 出厂占位符不是秘密，保持原样才看得出「没填过」。
    REQUIRE_EQ(SealSecret("<YOUR_OWN_ASR_TOKEN>"), std::string("<YOUR_OWN_ASR_TOKEN>"));
    REQUIRE_EQ(SealSecret("FAKESECRET_ABCDEF"), std::string("FAKESECRET_ABCDEF"));
    // 不是密文形状的普通值原样返回，绝不尝试解密。
    REQUIRE_EQ(UnsealSecret("sk-plain"), std::string("sk-plain"));
    // 形状像密文但解不开（别的机器/别的用户加密的）：原样返回。调用方的占位符过滤会把它
    // 判为不可用凭证，既不会把密文发给服务方，也不会把用户的值抹成空。
    const std::string undecryptable = "dpapi:v1:" + std::string(60, 'A');
    REQUIRE_EQ(UnsealSecret(undecryptable), undecryptable);
}

TEST_CASE(sensitive_keys_are_matched_per_section)
{
    REQUIRE(IsSensitiveConfigKey("voice_input", "asr_token"));
    REQUIRE(IsSensitiveConfigKey("voice_input", "polish_token_deepseek"));
    REQUIRE(IsSensitiveConfigKey("ai_assistant", "token_openai"));
    REQUIRE(IsSensitiveConfigKey("tencent_tmt", "secret_key"));
    REQUIRE(IsSensitiveConfigKey("custom_translation", "api_key"));
    REQUIRE(IsSensitiveConfigKey("niutrans", "apikey"));
    // 只按键名判断时（写路径可能拿不到分节）宁多勿漏。
    REQUIRE(IsSensitiveConfigKey("", "asr_token"));
    // 同名但不是凭证的键不能被封：皮肤、代理等分节里也有叫 token 的普通字段。
    REQUIRE(!IsSensitiveConfigKey("skin", "token"));
    REQUIRE(!IsSensitiveConfigKey("voice_input", "language"));
    REQUIRE(!IsSensitiveConfigKey("ai_assistant", "model"));
}

TEST_CASE(sealing_config_text_covers_every_credential_section_and_leaves_others_alone)
{
    const std::string text = "[voice_input]\n"
                             "language = \"zh-cn\"\n"
                             "asr_token = \"sk-asr-secret\"\n"
                             "asr_token_doubao = \"<YOUR_OWN_DOUBAO_TOKEN>\"\n"
                             "[ai_assistant]\n"
                             "token = \"sk-ai-secret\"\n"
                             "model = \"v2\"\n"
                             "[tencent_tmt]\n"
                             "secret_id = \"real-secret-id\"\n"
                             "secret_key = \"real-secret-key\"\n"
                             "[custom_translation]\n"
                             "api_key = \"real-api-key\"\n"
                             "[niutrans]\n"
                             "app_id = \"real-app-id\"\n"
                             "apikey = \"real-apikey\"\n"
                             "[skin]\n"
                             "token = \"not-a-credential\"\n";

    std::string sealed = text;
    REQUIRE(SealConfigSecrets(sealed));
    for (const char *plaintext : {"sk-asr-secret", "sk-ai-secret", "real-secret-id", "real-secret-key", "real-api-key",
                                  "real-app-id", "real-apikey"})
    {
        REQUIRE(sealed.find(plaintext) == std::string::npos);
    }
    // 非凭证的值一个都不能动。
    REQUIRE(sealed.find("language = \"zh-cn\"") != std::string::npos);
    REQUIRE(sealed.find("model = \"v2\"") != std::string::npos);
    REQUIRE(sealed.find("token = \"not-a-credential\"") != std::string::npos);
    // 占位符保持原样。
    REQUIRE(sealed.find("asr_token_doubao = \"<YOUR_OWN_DOUBAO_TOKEN>\"") != std::string::npos);
    // 封完仍是合法 TOML——否则下一次启动就会落进「配置损坏」的抢救路径。
    REQUIRE(TomlTextIsParseable(sealed));

    // 再封一次是无操作：升级路径会在同一份文本上反复走封装。
    std::string again = sealed;
    REQUIRE(!SealConfigSecrets(again));
    REQUIRE_EQ(again, sealed);
}

TEST_CASE(parsed_assignments_hand_back_plaintext_for_sealed_config)
{
    // ParseTomlAssignments 是模板合并用的 TOML 文本级工具，返回值保留 TOML 编码（带引号）。
    // 这里验证密文经过它之后，引号内的内容是解密后的明文而非 dpapi: 密文——模板合并只会
    // 把「非空的真凭证」往模板里搬，拿到密文会误判成用户没配过。
    // 真正的配置加载路径是 LoadImeConfig → StoredSecret，它返回的是密文（契约 6）。
    const std::string text = "[voice_input]\nasr_token = \"sk-asr-secret\"\n[ai_assistant]\ntoken = \"sk-ai-secret\"\n";
    std::string sealed = text;
    REQUIRE(SealConfigSecrets(sealed));

    const auto values = ParseTomlAssignments(sealed);
    // 返回值是 TOML 编码的基本字符串（带双引号），与非敏感键的 raw_value 一致
    REQUIRE_EQ(values.at(MakeTomlAssignmentId("voice_input", "asr_token")), std::string("\"sk-asr-secret\""));
    REQUIRE_EQ(values.at(MakeTomlAssignmentId("ai_assistant", "token")), std::string("\"sk-ai-secret\""));
    // 去引号后必须是明文，不能残留 dpapi: 前缀
    const std::string asr_value = values.at(MakeTomlAssignmentId("voice_input", "asr_token"));
    REQUIRE(asr_value.size() > 2u);
    REQUIRE_EQ(asr_value.front(), '"');
    REQUIRE_EQ(asr_value.back(), '"');
    const std::string plaintext = asr_value.substr(1, asr_value.size() - 2);
    REQUIRE_EQ(plaintext, std::string("sk-asr-secret"));
    REQUIRE_EQ(plaintext.find("dpapi:v1:"), std::string::npos);
}

TEST_CASE(shipped_template_holds_no_value_that_would_be_sealed)
{
    // 出厂模板里不该有任何「封装器认为需要保护」的值：真出现一个，说明模板被塞进了真凭证，
    // 或者出现了一种占位符新写法而 IsPlaceholderToken 没跟上——后者会让全新安装的第一次启动
    // 就把占位符封成密文，用户再也看不出自己没填过。
    std::ifstream input(MSIME_DEFAULT_CONFIG_PATH, std::ios::binary);
    REQUIRE(static_cast<bool>(input));
    const std::string shipped((std::istreambuf_iterator<char>(input)), {});

    std::string sealed = shipped;
    REQUIRE(!SealConfigSecrets(sealed));
    REQUIRE_EQ(sealed, shipped);
}

TEST_CASE(masking_replaces_only_real_credentials_with_the_sentinel)
{
    // 真凭证：一律换成哨兵，明文不许留在下发给页面的 JSON 里。
    const std::string sentinel(kSealedCredentialSentinel);
    REQUIRE_EQ(MaskSealedCredential("sk-live-0123456789abcdef"), sentinel);
    // 密文同样要收敛成哨兵：内存里存的就是密文（契约 6），如果这里对密文放行，设置页
    // 收到并保存后就会把 dpapi:v1:... 当成 token 写进配置，用户看到「已配置」但鉴权全挂。
    const std::string sealed_round_trip = SealSecret("sk-live-0123456789abcdef");
    REQUIRE(IsSealedSecret(sealed_round_trip));
    REQUIRE_EQ(MaskSealedCredential(sealed_round_trip), sentinel);
    // 空值与出厂占位符原样下发：页面靠它们区分「没填过」和「填过但值在服务端」，
    // 统一换成哨兵会让设置页把没配过的项也显示成已配置。
    REQUIRE(MaskSealedCredential("").empty());
    REQUIRE_EQ(MaskSealedCredential("<YOUR_OWN_ASR_TOKEN>"), std::string("<YOUR_OWN_ASR_TOKEN>"));
    REQUIRE_EQ(MaskSealedCredential("FAKESECRET_ABCDEF"), std::string("FAKESECRET_ABCDEF"));
    // 哨兵本身不是密文，也不是占位符——它必须能被写入路径一眼认出来，别再被当成明文封一遍。
    REQUIRE(!IsSealedSecret(sentinel));
    REQUIRE_EQ(SealSecret(sentinel), sentinel);
}

TEST_CASE(settings_page_echo_of_the_sentinel_does_not_overwrite_stored_credentials)
{
    // 设置页收到的是哨兵，用户没动那个输入框就点保存时，回传的就是哨兵。写入路径必须跳过
    // 这类更新：把哨兵当明文存下去，用户下次用到凭证时会拿着 "__METASEQUOIA_SEALED__"
    // 去请求服务方，表现为「配置看起来还在，但鉴权全挂」。
    ScopedConfigRoot config_root;
    InitImeConfig();
    const std::filesystem::path config_path = config_root.root() / L"config.toml";

    REQUIRE(WriteCredential("voice_input", "asr_token", "sk-asr-live-credential"));
    const std::string after_write = ReadConfigText(config_path);
    REQUIRE(after_write.find("sk-asr-live-credential") == std::string::npos);
    REQUIRE(after_write.find("dpapi:v1:") != std::string::npos);

    // 原样回传哨兵：文件必须一个字节都不变。
    const std::string sentinel_literal = EscapeTomlBasicString(std::string(kSealedCredentialSentinel));
    REQUIRE(WriteConfiguredValues({{"voice_input", "asr_token", sentinel_literal}}));
    const std::string after_echo = ReadConfigText(config_path);
    REQUIRE_EQ(after_echo, after_write);

    // 同一次保存里既有哨兵回传、又有用户真正改过的另一项：只落盘改动过的那一项。
    REQUIRE(WriteConfiguredValues({{"voice_input", "asr_token", sentinel_literal},
                                   {"voice_input", "polish_token", EscapeTomlBasicString("sk-polish-new")}}));
    const std::string after_mixed = ReadConfigText(config_path);
    const auto lines_of = [](const std::string &text, const std::string &needle) {
        std::vector<std::string> found;
        size_t at = text.find(needle);
        while (at != std::string::npos)
        {
            const size_t end = text.find('\n', at);
            found.push_back(text.substr(at, end == std::string::npos ? std::string::npos : end - at));
            at = text.find(needle, end == std::string::npos ? text.size() : end);
        }
        return found;
    };
    const auto asr_lines = lines_of(after_mixed, "asr_token = ");
    const auto asr_lines_before = lines_of(after_echo, "asr_token = ");
    REQUIRE(!asr_lines.empty());
    REQUIRE_EQ(asr_lines.front(), asr_lines_before.front());
    // 新凭证同样以密文落盘，明文不留在文件里。
    REQUIRE(after_mixed.find("sk-polish-new") == std::string::npos);
    REQUIRE(after_mixed.find("dpapi:v1:") != std::string::npos);

    // 读回来：内存里是密文，解封才得到明文；哨兵没有混进凭证集合。
    InitImeConfig();
    const VoiceInputConfig reloaded = GetConfiguredVoiceInput();
    REQUIRE(IsSealedSecret(reloaded.asr_token));
    REQUIRE_EQ(UnsealSecret(reloaded.asr_token), std::string("sk-asr-live-credential"));
    REQUIRE_EQ(UnsealSecret(reloaded.polish_token), std::string("sk-polish-new"));
    REQUIRE(reloaded.asr_token.find("__METASEQUOIA_SEALED__") == std::string::npos);
    REQUIRE(reloaded.asr_token.find("sk-asr-live-credential") == std::string::npos);
}

TEST_CASE(clearing_a_credential_does_not_drop_the_rest_of_the_batch)
{
    // 清空 token 传的是空明文，DPAPI 对空输入本来就返回空——那不是「DPAPI 不可用」。把它误判成
    // 失败，会让「切到一个还没填 token 的服务方」整批设置都写不进去：用户看到界面变了、重开
    // 又变回去。这条用例锁死「空明文照常写、同批次其他改动也不丢」。
    ScopedConfigRoot config_root;
    InitImeConfig();
    const std::filesystem::path config_path = config_root.root() / L"config.toml";

    REQUIRE(WriteCredential("ai_assistant", "token", "sk-ai-live-credential"));
    REQUIRE(ReadConfigText(config_path).find("sk-ai-live-credential") == std::string::npos);

    // 同一批次：清空凭证 + 改一个普通键，两件都要落地。
    REQUIRE(WriteConfiguredValues(
        {{"ai_assistant", "token", std::string("\"\"")}, {"ai_assistant", "provider", std::string("\"openai\"")}}));
    const std::string after_clear = ReadConfigText(config_path);
    REQUIRE(after_clear.find("sk-ai-live-credential") == std::string::npos);
    REQUIRE(after_clear.find("token = \"\"") != std::string::npos);
    REQUIRE(after_clear.find("provider = \"openai\"") != std::string::npos);

    // 清空后读回来就是空：不能把上一次的密文留在内存里当成还在用。
    InitImeConfig();
    REQUIRE(GetConfiguredAiAssistant().token.empty());
}

TEST_CASE(seal_for_memory_is_the_storage_form_for_newly_typed_values)
{
    // 用户新填的值在「写盘」和「存内存」两处必须是同一种形态，否则会出现磁盘上是密文、
    // 内存里是明文这种错位，而内存那一份才是攻击者真正想要的东西。
    // DPAPI 每次调用都会换随机盐，所以同一明文封两次得到的是两串不同密文：这里只能比
    // 「能解回原文」，不能比密文相等。
    const std::string for_memory = SealForMemory("ai_assistant", "token", "sk-new-credential");
    REQUIRE(IsSealedSecret(for_memory));
    REQUIRE_EQ(UnsealSecret(for_memory), std::string("sk-new-credential"));
    REQUIRE(for_memory.find("sk-new-credential") == std::string::npos);
    REQUIRE(IsSealedSecret(SealForMemory("voice_input", "asr_token", "sk-new-credential")));
    // 幂等：已经是密文的值再交进来一次不得再包一层。
    const std::string sealed = SealSecret("sk-new-credential");
    REQUIRE_EQ(SealForMemory("ai_assistant", "token", sealed), sealed);
    // 非凭证键原样通过：调用方对所有键都调它，该不该封由这里判断。
    REQUIRE_EQ(SealForMemory("ai_assistant", "model", "v9"), std::string("v9"));
    REQUIRE_EQ(SealForMemory("voice_input", "asr_endpoint", "https://example.invalid"),
               std::string("https://example.invalid"));
    // 空值与出厂占位符照旧。
    REQUIRE(SealForMemory("ai_assistant", "token", "").empty());
    REQUIRE_EQ(SealForMemory("ai_assistant", "token", "<YOUR_OWN_TOKEN>"), std::string("<YOUR_OWN_TOKEN>"));
}

TEST_CASE(credentials_are_sealed_in_memory_and_unsealed_only_for_requests)
{
    // 契约 6 的端到端版本：进程空闲时，任何一个真凭证在内存里都必须是密文。明文只在请求
    // 即将发出的那一刻由 UnsealSecret 解出，解出来的临时量随请求结束销毁（消费点共五处：
    // cloud_translation / voice_input_service / ai_assistant / doubao_asr_client /
    // api_credential_test）。这条一旦断了，读者只要读一次进程内存就能拿走全部 key。
    ScopedConfigRoot config_root;
    InitImeConfig();
    const std::filesystem::path config_path = config_root.root() / L"config.toml";

    // 用户新填的凭证：写盘是密文，内存也是密文。
    REQUIRE(SetConfiguredVoiceInputString("asr_token", "sk-asr-live-credential"));
    const VoiceInputConfig voice = GetConfiguredVoiceInput();
    REQUIRE(IsSealedSecret(voice.asr_token));
    REQUIRE(voice.asr_token.find("sk-asr-live-credential") == std::string::npos);
    REQUIRE_EQ(UnsealSecret(voice.asr_token), std::string("sk-asr-live-credential"));
    // 每个提供商一份的槽位同样只存密文。
    REQUIRE(SetConfiguredVoiceInputString("asr_token_doubao", "sk-doubao-live-credential"));
    const VoiceInputConfig voice_slots = GetConfiguredVoiceInput();
    REQUIRE(voice_slots.asr_tokens.count("doubao") == 1);
    REQUIRE(IsSealedSecret(voice_slots.asr_tokens.at("doubao")));

    REQUIRE(SetConfiguredAiAssistantString("token", "sk-ai-live-credential"));
    const std::string ai_token = GetConfiguredAiAssistant().token;
    REQUIRE(IsSealedSecret(ai_token));
    REQUIRE_EQ(UnsealSecret(ai_token), std::string("sk-ai-live-credential"));
    // 非凭证字段不能被顺手封起来：model、prompt 这些要原样可读。
    REQUIRE(SetConfiguredAiAssistantString("model", "v9-test"));
    REQUIRE_EQ(GetConfiguredAiAssistant().model, std::string("v9-test"));

    // 云翻译三家走同一套存储形态。
    REQUIRE(SetConfiguredTencentTmtString("secret_key", "real-secret-key"));
    const TencentTmtConfig tencent = GetConfiguredTencentTmt();
    REQUIRE(IsSealedSecret(tencent.secret_key));
    REQUIRE_EQ(UnsealSecret(tencent.secret_key), std::string("real-secret-key"));
    REQUIRE(SetConfiguredCustomTranslationString("api_key", "real-api-key"));
    const CustomTranslationConfig custom = GetConfiguredCustomTranslation();
    REQUIRE(IsSealedSecret(custom.api_key));
    REQUIRE(SetConfiguredNiuTransString("apikey", "real-apikey"));
    const NiuTransConfig niutrans = GetConfiguredNiuTrans();
    REQUIRE(IsSealedSecret(niutrans.apikey));

    // 磁盘上同样一个明文都没有。
    const std::string text = ReadConfigText(config_path);
    for (const char *plaintext : {"sk-asr-live-credential", "sk-doubao-live-credential", "sk-ai-live-credential",
                                  "real-secret-key", "real-api-key", "real-apikey"})
    {
        REQUIRE(text.find(plaintext) == std::string::npos);
    }
    REQUIRE(text.find("dpapi:v1:") != std::string::npos);

    // 重新加载（LoadImeConfig → StoredSecret）之后内存里仍然是密文。
    InitImeConfig();
    const VoiceInputConfig reloaded = GetConfiguredVoiceInput();
    REQUIRE(IsSealedSecret(reloaded.asr_token));
    REQUIRE(reloaded.asr_token.find("sk-asr-live-credential") == std::string::npos);
    // 基键 asr_token 在加载末尾会被规范化成「生效供应商槽位的值」（ime_config.cpp:739
    // voice.asr_token = stored），而本用例给生效供应商豆包单独配了凭证，所以这里解出来的是
    // 豆包那一份。基键自己那一份仍留在 asr_tokens 里，只是不再是生效值。
    REQUIRE_EQ(UnsealSecret(reloaded.asr_token), std::string("sk-doubao-live-credential"));
    REQUIRE(IsSealedSecret(reloaded.asr_tokens.at("doubao")));
    REQUIRE_EQ(UnsealSecret(reloaded.asr_tokens.at("doubao")), std::string("sk-doubao-live-credential"));
}
