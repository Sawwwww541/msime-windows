import { describe, expect, it } from 'vitest';
import {
  compareVersions,
  describeUpdateStatus,
  describeVersionOption,
  describeVersionTrust,
  formatBytes,
  formatPublishedAt,
  normalizeVersions,
  parseVersion,
  type UpdateVersion
} from './update-manifest';

const DIGEST = 'a'.repeat(64);
const GITHUB = 'https://github.com/metasequoiaime/MSIME-Windows/releases/download/v0.10.1/MetasequoiaIME_Setup_v0.10.1.exe';

const version = (overrides: Partial<UpdateVersion> = {}): UpdateVersion => ({
  version: '0.10.1',
  prerelease: false,
  publishedAt: '2026-10-11T20:39:29Z',
  size: 90173264,
  installerUrl: GITHUB,
  mirrorUrl: `https://dl.msime.app/gh/${GITHUB}`,
  sha256: DIGEST,
  releaseUrl: 'https://github.com/metasequoiaime/MSIME-Windows/releases/tag/v0.10.1',
  signed: true,
  ...overrides
});

describe('parseVersion', () => {
  it('accepts the shapes the release pipeline produces', () => {
    expect(parseVersion('0.3.1')?.parts).toEqual([0, 3, 1]);
    expect(parseVersion('v0.3.1')?.display).toBe('0.3.1');
    expect(parseVersion(' 0.0.9.2 ')?.parts).toEqual([0, 0, 9, 2]);
    expect(parseVersion('1.2.3-beta.1')?.display).toBe('1.2.3');
  });

  it('rejects anything it cannot order', () => {
    expect(parseVersion('')).toBeNull();
    expect(parseVersion('latest')).toBeNull();
    expect(parseVersion('v')).toBeNull();
  });
});

describe('compareVersions', () => {
  it('orders by numeric component, not lexically', () => {
    const order = (left: string, right: string) =>
      compareVersions(parseVersion(left)!, parseVersion(right)!);
    expect(order('0.10.0', '0.9.0')).toBeGreaterThan(0);
    expect(order('0.3.1', '0.3.1')).toBe(0);
    // A shorter version is not automatically older: 0.3 and 0.3.0 are the same release.
    expect(order('0.3', '0.3.0')).toBe(0);
    expect(order('0.3.1', '0.3')).toBeGreaterThan(0);
  });
});

describe('normalizeVersions', () => {
  it('keeps well-formed entries and sorts them newest first', () => {
    const versions = normalizeVersions([
      version({ version: '0.9.5', size: 110650144, signed: undefined }),
      version({ version: '0.10.1' }),
      version({ version: '0.10.0' })
    ]);
    expect(versions.map((entry) => entry.version)).toEqual(['0.10.1', '0.10.0', '0.9.5']);
    expect(versions[0].mirrorUrl).toContain('dl.msime.app');
    // 未声明签名状态的条目不带 signed 字段，页面据此显示「签名状态未知」。
    expect('signed' in versions[2]).toBe(false);
  });

  it('drops entries the host must never have rendered as downloadable', () => {
    const versions = normalizeVersions([
      { version: 'latest', installerUrl: GITHUB },
      { version: '0.10.1', installerUrl: 'http://insecure.example/x.exe' },
      { version: '0.10.1', installerUrl: 'javascript:alert(1)' },
      { version: '0.10.1' },
      null,
      'nope'
    ]);
    expect(versions).toEqual([]);
  });

  it('keeps an entry whose optional fields are unusable, with them blanked', () => {
    const versions = normalizeVersions([{ version: '0.10.1', installerUrl: GITHUB, sha256: 'not-a-digest' }]);
    expect(versions).toHaveLength(1);
    expect(versions[0].sha256).toBe('');
  });

  it('blanks unusable optional fields instead of dropping the entry', () => {
    const versions = normalizeVersions([
      {
        version: 'v0.10.1',
        installerUrl: GITHUB,
        sha256: 'zz',
        mirrorUrl: 'not-a-url',
        releaseUrl: 42,
        size: -1,
        publishedAt: null,
        prerelease: 'yes'
      }
    ]);
    expect(versions).toHaveLength(1);
    expect(versions[0].version).toBe('0.10.1');
    expect(versions[0].sha256).toBe('');
    expect(versions[0].mirrorUrl).toBe('');
    expect(versions[0].releaseUrl).toBe('');
    expect(versions[0].size).toBe(0);
    expect(versions[0].publishedAt).toBe('');
    expect(versions[0].prerelease).toBe(false);
  });

  it('deduplicates repeated versions', () => {
    const versions = normalizeVersions([version(), version({ size: 1 })]);
    expect(versions).toHaveLength(1);
    expect(versions[0].size).toBe(90173264);
  });

  it('rejects anything that is not an array', () => {
    expect(normalizeVersions(undefined)).toEqual([]);
    expect(normalizeVersions({})).toEqual([]);
  });
});

describe('describeVersionTrust', () => {
  it('warns when the release is known to be unsigned', () => {
    const trust = describeVersionTrust(version({ signed: false }));
    expect(trust.warning).toContain('未经代码签名');
    expect(trust.sha256).toBe(DIGEST);
  });

  it('stays quiet once a release is signed, but still offers the digest', () => {
    const trust = describeVersionTrust(version({ signed: true }));
    expect(trust.warning).toBeNull();
    expect(trust.sha256).toBe(DIGEST);
  });

  it('says nothing about signing when the host did not report it', () => {
    const trust = describeVersionTrust(version({ signed: undefined }));
    expect(trust.warning).toBeNull();
    expect(trust.sha256).toBe(DIGEST);
  });

  it('has no digest when the version never published one', () => {
    const trust = describeVersionTrust(version({ sha256: '' }));
    expect(trust.sha256).toBeNull();
  });
});

describe('describeVersionOption', () => {
  it('marks the newest entry and the installed version', () => {
    expect(describeVersionOption(version(), { isLatest: true, currentVersion: '0.9.5' })).toBe('v0.10.1（最新）');
    expect(describeVersionOption(version(), { isLatest: true, currentVersion: '0.10.1' })).toBe('v0.10.1（当前版本）');
    expect(describeVersionOption(version({ version: '0.9.5' }), { isLatest: false, currentVersion: '0.10.1' })).toBe('v0.9.5');
  });

  it('labels prereleases', () => {
    expect(describeVersionOption(version({ prerelease: true }), { isLatest: true, currentVersion: null })).toBe(
      'v0.10.1（最新，预发布）'
    );
  });

  it('prefers the current-version tag over the newest tag', () => {
    expect(describeVersionOption(version(), { isLatest: true, currentVersion: 'v0.10.1' })).toBe('v0.10.1（当前版本）');
  });
});

describe('formatBytes', () => {
  it('scales to the unit a person reads', () => {
    expect(formatBytes(0)).toBe('');
    expect(formatBytes(-1)).toBe('');
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(2048)).toBe('2.0 KB');
    expect(formatBytes(90173264)).toBe('86.0 MB');
    expect(formatBytes(5 * 1024 * 1024 * 1024)).toBe('5.0 GB');
  });
});

describe('formatPublishedAt', () => {
  it('keeps the date and drops the time of day', () => {
    expect(formatPublishedAt('2026-10-11T20:39:29Z')).toBe('2026-10-11');
    expect(formatPublishedAt('')).toBe('');
    expect(formatPublishedAt('garbage')).toBe('');
  });
});

describe('describeUpdateStatus', () => {
  it('pairs the up-to-date verdict with when it was checked', () => {
    expect(describeUpdateStatus('upToDate', '已是最新版本', '2026-10-14T17:00:00')).toBe('已是最新版本（2026-10-14T17:00:00）');
  });

  it('passes the host message through for every other state', () => {
    expect(describeUpdateStatus('error', '检查失败，请稍后重试', '')).toBe('检查失败，请稍后重试');
    expect(describeUpdateStatus('updateAvailable', '发现新版本 v0.10.1', '2026-10-14T17:00:00')).toBe(
      '发现新版本 v0.10.1（2026-10-14T17:00:00）'
    );
    expect(describeUpdateStatus('ready', '', '')).toBe('安装包已就绪');
    expect(describeUpdateStatus('installing', '', '')).toBe('正在启动安装程序…');
  });
});
