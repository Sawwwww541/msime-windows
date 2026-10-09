#pragma once

// config.toml 里 API 凭证（token / api_key / secret_* 等）的落盘保护。
//
// 这些键以前是明文写进 config.toml 的：用户目录里一个纯文本文件、任何带用户权限的进程、
// 备份、网盘同步、把配置贴到 issue 里，都会把凭证原样带走。现在它们统一以
// "dpapi:v1:<base64(CryptProtectData blob)>" 的形式落盘，密钥由 Windows DPAPI 绑到当前
// 用户，别的账户或另一台机器拿到这份配置也解不开。
//
// 内存里也只留密文：全局配置（g_voice_input / g_ai_assistant / g_tencent_tmt / g_custom_translation /
// g_niutrans）保存的就是落盘的那个密文，明文只在真正要发往网络的那一刻、在请求作用域里解出来
// （cloud_translation.cpp 解析凭证、voice_input_service.cpp 拼 Authorization 头、ai_assistant.cpp
// 拼 Bearer、doubao_asr_client.cpp 拼握手头）。否则「进程里常驻明文 API key」这件事本身就是一个
// 可被同机任意进程读走的暴露面——文件加密挡不住内存扫描。
//
// 于是本模块的契约是：密文是唯一的存储形态，明文是短命的临时量。

#include <cstddef>
#include <string>
#include <string_view>

namespace ime_config_detail
{
// 已配置凭证的哨兵值：下发给设置页时用它替换真实明文，页面因此永远不需要持有已存凭证。
//
// 为什么不干脆「不下发」：设置页要靠「空 / 非空」区分「没配过」和「配过」，输入框留空就是
// 「没配过」的表示法。哨兵把「配过、值在服务端」表达出来，页面已有的判空逻辑一行都不用改。
//
// 取值避开 <YOUR_...> 和 FAKESECRET_*：那两种出厂占位符已经被
// VoiceInput::IsPlaceholderToken 定义成「不可用凭证」，混用会让「已配置」被误判成「没配」。
//
// 哨兵在本模块里是惰性的：它既不会被封装成密文（SealSecret 原样返回），也不会被当成真凭证
// 再去替换一次（MaskSealedCredential 原样返回）。这样「页面把哨兵回传」只会走到写入路径的
// 跳过分支，任何时候都不会有哨兵落盘。
inline constexpr std::string_view kSealedCredentialSentinel = "__METASEQUOIA_SEALED__";

// 该分节里的这个键是否属于凭证。分节参与判断，避免把皮肤、代理之类同名的普通字段一起封掉。
bool IsSensitiveConfigKey(std::string_view section, std::string_view key);

// 把下发用的凭证值收敛成哨兵：真凭证变哨兵，空值和出厂占位符原样返回（它们是页面必须看到的
// 真实状态）。服务端拿回哨兵时，写入路径跳过该次更新、测试路径改用自己存的凭证——所以哨兵
// 永远不落盘，也不会被误当成用户输入的真凭证。
//
// 两种形态的真凭证都要收敛：内存里常驻的是密文，而设置页刚提交、还没走完写入路径的值可能仍是
// 明文，两者都不能下发。
std::string MaskSealedCredential(std::string_view value);

// 值是否已经是本方案落盘的密文形式。
bool IsSealedSecret(std::string_view value);

// 明文凭证 → 落盘密文。空值、出厂占位符（<YOUR_...> / FAKESECRET_）和已经是密文的值原样返回：
// 占位符不是秘密，封了反而让「用户没填过」这件事看不出来。DPAPI 不可用时返回空串，调用方据此
// 放弃本次写入，宁可不保存也不能退回明文。
std::string SealSecret(std::string_view plaintext);

// 用户刚在设置页填的明文 → 内存与磁盘共同使用的存储形态（密文）。非凭证键、空值、出厂占位符和
// 已经是密文的值原样返回。
//
// 为什么需要它：设置项的 setter 是「先写盘、再改内存」，写盘那一步会封装，但内存赋值拿到的仍是
// 用户输入的明文——不在这里换掉，一次保存就让明文一直常驻到下次重载。
//
// 封装失败时退回明文而不是空串：写盘此时已经失败并放弃了这次保存，再让内存里的值消失，只会让
// 用户看到「保存成功但没配上」。
std::string SealForMemory(std::string_view section, std::string_view key, std::string_view value);

// 落盘密文 → 明文。非密文原样返回。解不开（换了 Windows 账户、机器或摘要被改）时原样返回密文，
// 后续的占位符过滤会把它当成不可用凭证，既不会把密文发给服务方，也不会把用户填过的值抹成空。
std::string UnsealSecret(std::string_view stored);

// 去掉 TOML 标量两侧的引号。凭证值从不跨行，够用了。
std::string UnquoteTomlScalar(const std::string &value);

// 整份 TOML 文本里的凭证就地封装：不是字符串的赋值、空值、占位符和已是密文的值都不动。
// 返回是否改写过 text。
bool SealConfigSecrets(std::string &text);

// 把磁盘上 config.toml 里剩余的明文凭证就地封装，并在真的改写时通知 Server 重新加载。
// 升级路径用：老版本写下的明文凭证在第一次启动时被清掉，用户不用重填。
bool SealPlaintextConfigSecretsOnDisk();
} // namespace ime_config_detail
