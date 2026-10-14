// 应用内更新的纯函数层：宿主（Server / 设置进程）下发数据的校验与展示格式化。
// 网络、下载、安装都在宿主侧，页面只发动作、读快照——这一层不含任何 DOM 与协议收发，
// 因此可以单测。与 C++ 侧 server/src/update/update_manager.cpp 的校验规则保持一致：
// 两侧都校验，页面不因为是宿主发的就照单全收。

export type Version = {
  display: string;
  parts: number[];
};

// 契约 updateResponse.versions[] 的单项经 normalizeVersions 收紧后的形态。
export type UpdateVersion = {
  version: string;
  prerelease: boolean;
  publishedAt: string;
  size: number;
  installerUrl: string;
  mirrorUrl: string;
  sha256: string;
  releaseUrl: string;
  signed?: boolean;
};

export type VersionTrust = {
  /** 发布清单声明该版本未签名时的醒目警告；签名或未知时为 null。 */
  warning: string | null;
  /** 该版本公布的 SHA256；没有公布时为 null（宿主会拒绝应用内下载）。 */
  sha256: string | null;
};

export type UpdateState =
  | 'idle'
  | 'checking'
  | 'upToDate'
  | 'updateAvailable'
  | 'downloading'
  | 'verifying'
  | 'ready'
  | 'installing'
  | 'error';

const SHA256 = /^[0-9a-f]{64}$/;
const HTTPS_URL = /^https:\/\/.+/i;

export function parseVersion(value: string): Version | null {
  const match = value.trim().match(/^v?(\d+(?:\.\d+)*)(?:[-+].*)?$/i);
  if (!match) {
    return null;
  }

  const display = match[1];
  if (!display) {
    return null;
  }

  return {
    display,
    parts: display.split('.').map(Number)
  };
}

export function compareVersions(left: Version, right: Version): number {
  const length = Math.max(left.parts.length, right.parts.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (left.parts[index] ?? 0) - (right.parts[index] ?? 0);
    if (difference !== 0) {
      return difference;
    }
  }
  return 0;
}

// 宿主已经校验过一次，这里再按同样的规则收紧：版本号不可排序、地址不是 https、
// 校验和不是 64 位小写十六进制的条目直接丢掉，绝不给它渲染成可点的下载目标。
export function normalizeVersions(raw: unknown): UpdateVersion[] {
  if (!Array.isArray(raw)) {
    return [];
  }

  const versions: UpdateVersion[] = [];
  const seen = new Set<string>();
  for (const item of raw) {
    if (!item || typeof item !== 'object') continue;
    const record = item as Record<string, unknown>;
    const parsed = typeof record.version === 'string' ? parseVersion(record.version) : null;
    if (!parsed) continue;
    const installerUrl = typeof record.installerUrl === 'string' ? record.installerUrl : '';
    if (!HTTPS_URL.test(installerUrl)) continue;
    if (seen.has(parsed.display)) continue;
    seen.add(parsed.display);
    const sha256 = typeof record.sha256 === 'string' && SHA256.test(record.sha256) ? record.sha256 : '';
    const mirrorUrl = typeof record.mirrorUrl === 'string' && HTTPS_URL.test(record.mirrorUrl) ? record.mirrorUrl : '';
    const releaseUrl = typeof record.releaseUrl === 'string' && HTTPS_URL.test(record.releaseUrl) ? record.releaseUrl : '';
    const entry: UpdateVersion = {
      version: parsed.display,
      prerelease: record.prerelease === true,
      publishedAt: typeof record.publishedAt === 'string' ? record.publishedAt : '',
      size: typeof record.size === 'number' && Number.isFinite(record.size) && record.size > 0 ? record.size : 0,
      installerUrl,
      mirrorUrl,
      sha256,
      releaseUrl
    };
    // signed 只在宿主声明过时存在：页面据此区分「未签名（警告）」和「签名状态未知」。
    if (typeof record.signed === 'boolean') {
      entry.signed = record.signed;
    }
    versions.push(entry);
  }
  // 宿主已按版本号降序下发，这里再排一次：页面不依赖宿主实现的顺序假设。
  versions.sort((left, right) => compareVersions(parseVersion(left.version)!, parseVersion(right.version)!));
  return versions.reverse();
}

// 安装前的信任信息。应用内更新由宿主下载后自动校验 SHA256，所以这里不再让用户手敲
// Get-FileHash；未签名警告照旧醒目——那是用户在点「立即更新」之前该看到的。
export function describeVersionTrust(version: UpdateVersion): VersionTrust {
  return {
    warning:
      version.signed === false
        ? '该版本未经代码签名，SmartScreen 会拦截，且 uiAccess 失效（候选窗无法浮在以管理员身份运行的程序之上）。'
        : null,
    sha256: version.sha256 || null
  };
}

// 版本下拉里每个选项的说明文字：位置信息（最新/当前版本）与预发布标记都在这一处拼，
// 页面不各写一遍。
export function describeVersionOption(
  version: UpdateVersion,
  options: { isLatest: boolean; currentVersion: string | null }
): string {
  const tags: string[] = [];
  const current = options.currentVersion ? parseVersion(options.currentVersion) : null;
  if (current && compareVersions(parseVersion(version.version)!, current) === 0) {
    tags.push('当前版本');
  }
  if (options.isLatest && tags.length === 0) {
    tags.push('最新');
  }
  if (version.prerelease) {
    tags.push('预发布');
  }
  return tags.length > 0 ? `v${version.version}（${tags.join('，')}）` : `v${version.version}`;
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return '';
  }
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  const units = ['KB', 'MB', 'GB'];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 100 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`;
}

// 发布日期只取到日：发布时间对「要不要装这个版本」没有意义，版本号本身才有序。
export function formatPublishedAt(publishedAt: string): string {
  const match = publishedAt.match(/^(\d{4})-(\d{2})-(\d{2})/);
  return match ? `${match[1]}-${match[2]}-${match[3]}` : '';
}

// 状态行文案。宿主下发的 message 已经是人类可读的完整句子，这里只补它不带的部分
// （上次检测时间），并给「已是最新」配上时间戳。
export function describeUpdateStatus(state: UpdateState, message: string, lastCheckedAt: string): string {
  const suffix = lastCheckedAt ? `（${lastCheckedAt}）` : '';
  switch (state) {
    case 'upToDate':
      return `已是最新版本${suffix}`;
    case 'updateAvailable':
      return message ? `${message}${suffix}` : `发现新版本${suffix}`;
    case 'ready':
      return '安装包已就绪';
    case 'installing':
      return '正在启动安装程序…';
    default:
      return message;
  }
}
