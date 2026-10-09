#include "api_credential_test.h"

#include "cloud/custom_translation.h"
#include "cloud/niutrans_translation.h"
#include "cloud/tencent_tmt.h"
#include "cloud/translation_gloss.h"
#include "config/ime_config.h"
#include "config/ime_config_secrets.h"
#include "voice-input/doubao_asr_client.h"

#include "utils/network_proxy.h"
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <cstdint>
#include <mutex>
#include <string_view>
#include <vector>

namespace
{
constexpr long kConnectTimeoutMs = 5000;
constexpr long kRequestTimeoutMs = 15000;
constexpr std::size_t kMaxResponseBytes = 256 * 1024;

struct HttpResponse
{
    CURLcode code = CURLE_FAILED_INIT;
    long status = 0;
    std::string body;
    std::string error;
};

std::string Value(const ApiCredentialTest::Request &request, const char *key)
{
    const auto found = request.config.find(key);
    return found == request.config.end() ? std::string{} : CloudTranslation::TrimSecret(found->second);
}

// 请求里的哪个字段对应哪份已存凭证。地图按服务区分：同一个 "token" 字段在语音、润色和 AI
// 助手三处指向不同的键，分不清就会拿错钥匙去测。
std::string StoredCredentialStoredForm(const ApiCredentialTest::Request &request, const std::string &submitted,
                                       const char *field)
{
    const std::string name(field == nullptr ? "" : field);
    if (submitted != ime_config_detail::kSealedCredentialSentinel)
    {
        return submitted;
    }

    // 逐供应商令牌表优先：页面按供应商读写 asr_tokens / polish_tokens / tokens，
    // 当前选中的供应商若在表里有值，真正会用的就是它。
    const std::string provider = Value(request, "provider");
    const bool has_provider = !provider.empty() && provider != "custom";
    const VoiceInputConfig voice = GetConfiguredVoiceInput();
    const AiAssistantConfig ai = GetConfiguredAiAssistant();
    const auto pick = [&provider, &has_provider](const std::map<std::string, std::string> &tokens,
                                                 const std::string &fallback) -> std::string {
        if (has_provider)
        {
            const auto found = tokens.find(provider);
            if (found != tokens.end() && !found->second.empty())
            {
                return found->second;
            }
        }
        return fallback;
    };

    if (request.service == "ai.assistant")
    {
        return name == "token" ? pick(ai.tokens, ai.token) : submitted;
    }
    if (request.service == "voice.polish")
    {
        return name == "token" ? pick(voice.polish_tokens, voice.polish_token) : submitted;
    }
    if (request.service == "voice.asr")
    {
        if (name == "token")
        {
            return pick(voice.asr_tokens, voice.asr_token);
        }
        if (name == "appId")
        {
            return voice.asr_app_key;
        }
        return submitted;
    }
    if (request.service == "translation.tencent")
    {
        const TencentTmtConfig tencent_tmt = GetConfiguredTencentTmt();
        if (name == "secretId")
        {
            return tencent_tmt.secret_id;
        }
        if (name == "secretKey")
        {
            return tencent_tmt.secret_key;
        }
        return submitted;
    }
    if (request.service == "translation.niutrans")
    {
        const NiuTransConfig niutrans = GetConfiguredNiuTrans();
        if (name == "appId")
        {
            return niutrans.app_id;
        }
        if (name == "apiKey")
        {
            return niutrans.apikey;
        }
        return submitted;
    }
    if (request.service == "translation.custom")
    {
        if (name == "apiKey")
        {
            return GetConfiguredCustomTranslation().api_key;
        }
        return submitted;
    }
    return submitted;
}

// 已存凭证在内存和磁盘里都是 DPAPI 密文（见 ime_config_secrets.h），测试请求要用的是明文：解封
// 只发生在这里，用完就随请求对象销毁。非密文原样返回，所以页面直接提交的明文照样能用。
std::string StoredCredential(const ApiCredentialTest::Request &request, const std::string &submitted, const char *field)
{
    return ime_config_detail::UnsealSecret(StoredCredentialStoredForm(request, submitted, field));
}

size_t WriteResponse(char *data, size_t size, size_t count, void *user)
{
    const size_t bytes = size * count;
    auto *response = static_cast<std::string *>(user);
    if (bytes > kMaxResponseBytes - (std::min)(response->size(), kMaxResponseBytes))
        return 0;
    response->append(data, bytes);
    return bytes;
}

void InitCurl()
{
    static std::once_flag once;
    std::call_once(once, [] { curl_global_init(CURL_GLOBAL_DEFAULT); });
}

bool IsHttpEndpoint(const std::string &endpoint)
{
    return endpoint.rfind("https://", 0) == 0 || endpoint.rfind("http://", 0) == 0;
}

std::string ErrorDetail(const HttpResponse &response)
{
    if (response.code != CURLE_OK)
        return response.error.empty() ? curl_easy_strerror(response.code) : response.error;
    try
    {
        const auto root = nlohmann::json::parse(response.body);
        if (root.contains("error"))
        {
            const auto &error = root.at("error");
            if (error.is_object() && error.contains("message") && error.at("message").is_string())
                return error.at("message").get<std::string>();
            if (error.is_string())
                return error.get<std::string>();
        }
        if (root.contains("message") && root.at("message").is_string())
            return root.at("message").get<std::string>();
        if (root.contains("errorMsg") && root.at("errorMsg").is_string())
            return root.at("errorMsg").get<std::string>();
    }
    catch (...)
    {
    }
    return "HTTP " + std::to_string(response.status);
}

HttpResponse PerformJsonPost(const std::string &endpoint, const std::string &token, const std::string &payload)
{
    InitCurl();
    HttpResponse response;
    CURL *curl = curl_easy_init();
    if (!curl)
        return response;
    char error[CURL_ERROR_SIZE] = {};
    curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    const std::string authorization = "Authorization: Bearer " + token;
    headers = curl_slist_append(headers, authorization.c_str());
    curl_easy_setopt(curl, CURLOPT_URL, endpoint.c_str());
    NetworkProxy::ApplyToCurl(curl);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(payload.size()));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteResponse);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response.body);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, kConnectTimeoutMs);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, kRequestTimeoutMs);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    response.code = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status);
    response.error = error;
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return response;
}

ApiCredentialTest::Result TestChat(const ApiCredentialTest::Request &request)
{
    const std::string token = StoredCredential(request, Value(request, "token"), "token");
    const std::string endpoint = Value(request, "endpoint");
    const std::string model = Value(request, "model");
    if (!CloudTranslation::IsUsableSecret(token))
        return {false, "请先填写有效的 API Key。"};
    if (!IsHttpEndpoint(endpoint) || model.empty())
        return {false, "请填写有效的 HTTPS 接口地址和模型名。"};
    nlohmann::json body = {{"model", model},
                           {"stream", false},
                           {"max_tokens", 1},
                           {"messages", {{{"role", "user"}, {"content", "Reply OK"}}}}};
    const std::string provider = Value(request, "provider");
    if (provider == "deepseek")
        body["thinking"] = {{"type", "disabled"}};
    else if (provider == "siliconflow")
        body["enable_thinking"] = false;
    const HttpResponse response = PerformJsonPost(endpoint, token, body.dump());
    if (response.code == CURLE_OK && response.status >= 200 && response.status < 300)
        return {true, "连接成功，API Key 和模型配置有效。"};
    return {false, "测试失败：" + ErrorDetail(response)};
}

void AppendLe16(std::vector<unsigned char> &out, std::uint16_t value)
{
    out.push_back(static_cast<unsigned char>(value));
    out.push_back(static_cast<unsigned char>(value >> 8));
}

void AppendLe32(std::vector<unsigned char> &out, std::uint32_t value)
{
    AppendLe16(out, static_cast<std::uint16_t>(value));
    AppendLe16(out, static_cast<std::uint16_t>(value >> 16));
}

std::vector<unsigned char> SilentWav()
{
    constexpr std::uint32_t sample_rate = 16000;
    constexpr std::uint32_t data_size = sample_rate * 2;
    std::vector<unsigned char> wav;
    wav.reserve(44 + data_size);
    wav.insert(wav.end(), {'R', 'I', 'F', 'F'});
    AppendLe32(wav, 36 + data_size);
    wav.insert(wav.end(), {'W', 'A', 'V', 'E', 'f', 'm', 't', ' '});
    AppendLe32(wav, 16);
    AppendLe16(wav, 1);
    AppendLe16(wav, 1);
    AppendLe32(wav, sample_rate);
    AppendLe32(wav, sample_rate * 2);
    AppendLe16(wav, 2);
    AppendLe16(wav, 16);
    wav.insert(wav.end(), {'d', 'a', 't', 'a'});
    AppendLe32(wav, data_size);
    wav.resize(44 + data_size, 0);
    return wav;
}

ApiCredentialTest::Result TestBatchAsr(const ApiCredentialTest::Request &request)
{
    const std::string token = StoredCredential(request, Value(request, "token"), "token");
    const std::string endpoint = Value(request, "endpoint");
    const std::string model = Value(request, "model");
    if (!CloudTranslation::IsUsableSecret(token))
        return {false, "请先填写有效的 API Key。"};
    if (!IsHttpEndpoint(endpoint) || model.empty())
        return {false, "请填写有效的 HTTPS 接口地址和模型名。"};

    InitCurl();
    HttpResponse response;
    CURL *curl = curl_easy_init();
    if (!curl)
        return {false, "无法初始化网络请求。"};
    char error[CURL_ERROR_SIZE] = {};
    const auto wav = SilentWav();
    curl_mime *mime = curl_mime_init(curl);
    curl_mimepart *file = curl_mime_addpart(mime);
    curl_mime_name(file, "file");
    curl_mime_filename(file, "credential-test.wav");
    curl_mime_type(file, "audio/wav");
    curl_mime_data(file, reinterpret_cast<const char *>(wav.data()), wav.size());
    curl_mimepart *model_part = curl_mime_addpart(mime);
    curl_mime_name(model_part, "model");
    curl_mime_data(model_part, model.c_str(), CURL_ZERO_TERMINATED);
    curl_slist *headers = nullptr;
    const std::string authorization = "Authorization: Bearer " + token;
    headers = curl_slist_append(headers, authorization.c_str());
    headers = curl_slist_append(headers, "Expect:");
    curl_easy_setopt(curl, CURLOPT_URL, endpoint.c_str());
    NetworkProxy::ApplyToCurl(curl);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteResponse);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response.body);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, kConnectTimeoutMs);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, kRequestTimeoutMs);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    response.code = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status);
    response.error = error;
    curl_slist_free_all(headers);
    curl_mime_free(mime);
    curl_easy_cleanup(curl);
    if (response.code == CURLE_OK && response.status >= 200 && response.status < 300)
        return {true, "连接成功，API Key 和模型配置有效。"};
    return {false, "测试失败：" + ErrorDetail(response)};
}

ApiCredentialTest::Result TestTranslation(const ApiCredentialTest::Request &request)
{
    std::vector<std::string> translated;
    if (request.service == "translation.tencent")
    {
        const TencentTmt::Credentials credentials{StoredCredential(request, Value(request, "secretId"), "secretId"),
                                                  StoredCredential(request, Value(request, "secretKey"), "secretKey"),
                                                  "ap-guangzhou"};
        if (!CloudTranslation::IsUsableSecret(credentials.secret_id) ||
            !CloudTranslation::IsUsableSecret(credentials.secret_key))
            return {false, "请先填写有效的 SecretId 和 SecretKey。"};
        translated = TencentTmt::TextTranslateBatch(credentials, {"测试"}, "zh", "en");
    }
    else if (request.service == "translation.niutrans")
    {
        const NiuTransTranslation::Config config{StoredCredential(request, Value(request, "appId"), "appId"),
                                                 StoredCredential(request, Value(request, "apiKey"), "apiKey")};
        if (!NiuTransTranslation::IsUsableConfig(config))
            return {false, "请先填写有效的 APP ID 和 API Key。"};
        translated = NiuTransTranslation::TextTranslateBatch(config, {"测试"}, "zh", "en");
    }
    else
    {
        const CustomTranslation::Config config{Value(request, "endpoint"),
                                               StoredCredential(request, Value(request, "apiKey"), "apiKey")};
        if (!CustomTranslation::IsSupportedEndpoint(config.endpoint))
            return {false, "请先填写有效的翻译接口地址。"};
        translated = CustomTranslation::TextTranslateBatch(config, {"测试"}, "ZH", "EN");
    }
    if (!translated.empty() && !translated.front().empty())
        return {true, "连接成功，翻译服务配置有效。"};
    return {false, "测试失败：服务未返回有效译文，请检查凭据、接口地址和网络。"};
}
} // namespace

namespace ApiCredentialTest
{
Result Run(const Request &request)
{
    if (request.service.rfind("translation.", 0) == 0)
        return TestTranslation(request);
    if (request.service == "voice.polish" || request.service == "ai.assistant")
        return TestChat(request);
    if (request.service == "voice.asr")
    {
        if (Value(request, "provider") != "doubao")
            return TestBatchAsr(request);
        const bool legacy = Value(request, "authMode") == "legacy";
        const std::string app_id = StoredCredential(request, Value(request, "appId"), "appId");
        const std::string token = StoredCredential(request, Value(request, "token"), "token");
        if (!CloudTranslation::IsUsableSecret(token) || (legacy && !CloudTranslation::IsUsableSecret(app_id)))
            return {false, legacy ? "请先填写有效的 App ID 和 Access Token。" : "请先填写有效的 API Key。"};
        const std::string error = DoubaoAsrClient::TestCredentials(Value(request, "endpoint"), legacy, app_id, token,
                                                                   Value(request, "resourceId"));
        return error.empty() ? Result{true, "连接成功，豆包语音识别凭据有效。"} : Result{false, "测试失败：" + error};
    }
    return {false, "不支持的配置测试类型。"};
}
} // namespace ApiCredentialTest
