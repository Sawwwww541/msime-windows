#pragma once

// 应用内更新的全局互斥标记（UpgradeInProgress）。
//
// 安装器（installer/msime_setup.iss）在停掉输入法进程之前，把
// HKLM\Software\Metasequoia\MetasequoiaIME\UpgradeInProgress 写成
// yyyymmddhhnnss（本地时间），安装收尾时清掉。窗口期内：
// - TSF DLL 的保活路径（windows/src/IME/MetasequoiaIME.cpp 的
//   LaunchServerIfNeeded）不再拉起 Server；
// - Server / Watchdog / 设置进程启动时安静退出。
//
// 没有它时的真实故障（2026-10-14 实测）：安装器杀掉进程后，TSF 的语言配置
// 激活通知（OnActivated）立刻经 ShellExecute 把 Server 拉回来，Server 打开
// msime.db 等数据文件，安装器替换文件时 MoveFile 重试 4 次后，在
// /SUPPRESSMSGBOXES 下默认「中止」并回滚——用户看到的是「下载完没更新」。
//
// 安装器崩溃或时钟异常会留下过期标记，所以超过 kUpgradeGuardMaxAgeSeconds
// 的标记一律视为不存在；标记解析不出来时同样视为不存在（宁可放行也不能
// 把输入法永久锁死）。
//
// 头文件实现（inline）：Server / Watchdog / 设置进程都直接 include，不动
// CMake 目标；TSF DLL 在 windows/ 树下不能依赖 Server 的头文件，按同一契约
// 有一份等价实现（windows/src/IME/MetasequoiaIME.cpp）。

#include <Windows.h>

namespace update
{

inline constexpr wchar_t kUpgradeGuardKey[] = L"Software\\Metasequoia\\MetasequoiaIME";
inline constexpr wchar_t kUpgradeGuardValue[] = L"UpgradeInProgress";
inline constexpr long long kUpgradeGuardMaxAgeSeconds = 45 * 60;

// 两个 100ns 单位（FILETIME）时间戳之差换算成秒。
inline long long UpgradeGuardSecondsBetween(const FILETIME &earlier, const FILETIME &later)
{
    ULARGE_INTEGER a{};
    a.LowPart = earlier.dwLowDateTime;
    a.HighPart = earlier.dwHighDateTime;
    ULARGE_INTEGER b{};
    b.LowPart = later.dwLowDateTime;
    b.HighPart = later.dwHighDateTime;
    if (b.QuadPart >= a.QuadPart)
        return static_cast<long long>((b.QuadPart - a.QuadPart) / 10'000'000ULL);
    return -static_cast<long long>((a.QuadPart - b.QuadPart) / 10'000'000ULL);
}

// 解析标记里 yyyymmddhhnnss 形式的本地时间。失败返回 false。
inline bool ParseUpgradeGuardTimestamp(const wchar_t *text, FILETIME &out)
{
    if (!text)
        return false;
    for (int index = 0; index < 14; ++index)
    {
        if (text[index] < L'0' || text[index] > L'9')
            return false;
    }
    if (text[14] != L'\0')
        return false;

    const auto number = [text](int offset, int digits) {
        int value = 0;
        for (int index = 0; index < digits; ++index)
            value = value * 10 + (text[offset + index] - L'0');
        return value;
    };

    SYSTEMTIME system_time{};
    system_time.wYear = static_cast<WORD>(number(0, 4));
    system_time.wMonth = static_cast<WORD>(number(4, 2));
    system_time.wDay = static_cast<WORD>(number(6, 2));
    system_time.wHour = static_cast<WORD>(number(8, 2));
    system_time.wMinute = static_cast<WORD>(number(10, 2));
    system_time.wSecond = static_cast<WORD>(number(12, 2));
    return SystemTimeToFileTime(&system_time, &out) != FALSE;
}

// 升级窗口期返回 true。用 GetLocalTime 与标记配对：两边都按「字面时间戳」比较，
// 时区偏移相互抵消，不受 UTC/本地时间差异影响。
inline bool IsUpgradeInProgress()
{
    wchar_t buffer[32]{};
    DWORD bytes = sizeof(buffer) - sizeof(wchar_t);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, kUpgradeGuardKey, kUpgradeGuardValue, RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
                     nullptr, buffer, &bytes) != ERROR_SUCCESS)
        return false;

    FILETIME marked{};
    if (!ParseUpgradeGuardTimestamp(buffer, marked))
        return false;

    SYSTEMTIME local_now{};
    GetLocalTime(&local_now);
    FILETIME now{};
    if (!SystemTimeToFileTime(&local_now, &now))
        return false;

    const long long seconds = UpgradeGuardSecondsBetween(marked, now);
    return seconds >= -60 && seconds <= kUpgradeGuardMaxAgeSeconds;
}

} // namespace update
