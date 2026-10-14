import { onHostMessage } from '../utils/host-messages';
import { serializeHostMessage, type ServerMessage, type SettingsMessage } from '../../../../shared/messages';
import { updateConfig } from './config-sync';
import { setupToggleButton } from './shared';
import {
  describeUpdateStatus,
  describeVersionOption,
  describeVersionTrust,
  formatBytes,
  formatPublishedAt,
  normalizeVersions,
  type UpdateState,
  type UpdateVersion
} from './update-manifest';

type UpdateResponse = Extract<ServerMessage, { type: 'updateResponse' }>;
type UpdateAction = Extract<SettingsMessage, { type: 'updateRequest' }>['data']['action'];

// 与宿主的 updateResponse 契约字段一一对应（engine/contracts/webview/messages.json）。
const RELEASE_PAGE_URL = 'https://github.com/metasequoiaime/MSIME-Windows/releases';

export function setupAboutSettings(): void {
  setupToggleButton('serverDiagnosticLogToggleBtn', (active) => {
    updateConfig('general.diagnostic_log', active);
  });
  setupToggleButton('tsfDiagnosticLogToggleBtn', (active) => {
    updateConfig('general.tsf_diagnostic_log', active);
  });
  // 自动更新：启停模式。开启后每次启动应用（Server 进程）自动检测一次更新，
  // 发现新版本时打开本页提示；关闭则只在点「检查更新」时检测。写入走通用配置通道。
  setupToggleButton('autoUpdateToggleBtn', (active) => {
    updateConfig('general.auto_update', active);
  });

  // These two rows shipped as buttons with no handler, so the settings page advertised a privacy
  // policy that did nothing when pressed. They are wired to the documents that actually govern
  // the software; the terms a user agrees to for an open-source product are its licence.
  for (const [id, url] of [
    ['about-website-link', 'https://msime.app/'],
    ['about-license-link', 'https://github.com/metasequoiaime/MSIME-Windows/blob/main/LICENSE'],
    ['about-privacy-link', 'https://github.com/metasequoiaime/MSIME-Windows/blob/main/PRIVACY.md'],
  ] as const) {
    const button = document.getElementById(id);
    if (button instanceof HTMLButtonElement) {
      button.addEventListener('click', () => postExternalUrl(url));
    } else {
      console.warn(`[about] document link ${id} not found`);
    }
  }

  const checkButton = document.getElementById('about-check-update');
  const versionLabel = document.querySelector('#about-settings .about-version');
  const statusLabel = document.getElementById('about-update-status');
  const dialog = document.getElementById('about-update-dialog');
  const versionSelect = document.getElementById('about-update-version-select') as HTMLSelectElement | null;
  const versionMeta = document.getElementById('about-update-version-meta');
  const dialogTrust = document.getElementById('about-update-dialog-trust');
  const progress = document.getElementById('about-update-progress');
  const progressBar = document.getElementById('about-update-progress-bar');
  const progressText = document.getElementById('about-update-progress-text');
  const cancelButton = document.getElementById('about-update-cancel');
  const releaseButton = document.getElementById('about-update-release');
  const downloadButton = document.getElementById('about-update-download');

  if (!(checkButton instanceof HTMLButtonElement) ||
      !(versionLabel instanceof HTMLElement) ||
      !(statusLabel instanceof HTMLElement) ||
      !(dialog instanceof HTMLDialogElement) ||
      !(versionSelect instanceof HTMLSelectElement) ||
      !(versionMeta instanceof HTMLElement) ||
      !(dialogTrust instanceof HTMLElement) ||
      !(progress instanceof HTMLElement) ||
      !(progressBar instanceof HTMLElement) ||
      !(progressText instanceof HTMLElement) ||
      !(cancelButton instanceof HTMLButtonElement) ||
      !(releaseButton instanceof HTMLButtonElement) ||
      !(downloadButton instanceof HTMLButtonElement)) {
    console.warn('[about] update controls not found');
    return;
  }

  // 对话框随关于页的分节 HTML 一起加载，默认在 #about-settings 容器里。用户切到别的
  // 分时时该容器是 display:none——留在里面的模态对话框会变成不可见的页面锁。挂到
  // body 下，对话框的显隐只由自己控制。
  if (dialog.parentElement !== document.body) {
    document.body.append(dialog);
  }

  // ---- 页面侧状态 ----
  // 页面不复制宿主的状态机：这里只记「哪个请求在途」，其余一律以宿主推送的
  // updateResponse 为准。
  let requestCounter = 0;
  let activeRequestId: string | null = null;
  let currentVersion: string | null = null;
  let versions: UpdateVersion[] = [];
  let selectedVersion: string | null = null;
  let downloadState: UpdateState = 'idle';
  let lastCheckedAt = '';

  const setStatus = (message: string, kind: 'idle' | 'success' | 'error' = 'idle') => {
    statusLabel.textContent = message;
    statusLabel.dataset.kind = kind;
  };

  const post = (action: UpdateAction, version?: string) => {
    const webview = window.chrome?.webview;
    if (!webview) return;
    const requestId = `update-${++requestCounter}`;
    activeRequestId = requestId;
    webview.postMessage(serializeHostMessage({
      type: 'updateRequest',
      data: version === undefined ? { requestId, action } : { requestId, action, version }
    }));
  };

  const setDialogOpen = (open: boolean) => {
    if (open) {
      if (!dialog.open) {
        dialog.showModal();
      }
      return;
    }

    if (dialog.open) {
      dialog.close();
    }
  };

  // ---- 版本下拉与信任信息 ----

  const renderVersionMeta = () => {
    const entry = versions.find((item) => item.version === selectedVersion) ?? null;
    versionMeta.replaceChildren();
    dialogTrust.replaceChildren();
    releaseButton.hidden = !entry?.releaseUrl;
    if (!entry) {
      downloadButton.disabled = true;
      return;
    }
    downloadButton.disabled = false;

    const facts: string[] = [];
    const size = formatBytes(entry.size);
    if (size) facts.push(size);
    const published = formatPublishedAt(entry.publishedAt);
    if (published) facts.push(published);
    facts.push(entry.signed === true ? '已签名' : entry.signed === false ? '未签名' : '签名状态未知');
    versionMeta.textContent = facts.join(' · ');

    // 应用内更新由宿主下载并校验，所以这里展示校验和供用户知情，而不是让用户自己敲命令。
    const trust = describeVersionTrust(entry);
    if (trust.warning) {
      const warning = document.createElement('p');
      warning.className = 'about-update-warning';
      warning.textContent = trust.warning;
      dialogTrust.append(warning);
    }
    if (trust.sha256) {
      const label = document.createElement('p');
      label.className = 'about-update-verify-label';
      label.textContent = '下载后自动校验 SHA256：';
      const digest = document.createElement('code');
      digest.className = 'about-update-verify-digest';
      digest.textContent = trust.sha256;
      dialogTrust.append(label, digest);
    } else {
      const note = document.createElement('p');
      note.className = 'about-update-verify-label';
      note.textContent = '该版本未公布校验和，宿主会拒绝应用内下载，请前往发布页手动下载。';
      dialogTrust.append(note);
      downloadButton.disabled = true;
    }
  };

  const fillVersionSelect = () => {
    // 列表真变了才重建：启动提示里只有最新版，用户点「检查更新」拿到完整目录后要能补上，
    // 但列表没变时不能把用户已经选好的版本冲掉。
    const listed = Array.from(versionSelect.options).map((option) => option.value).join(',');
    const incoming = versions.map((entry) => entry.version).join(',');
    if (listed === incoming) {
      if (selectedVersion !== null && versions.some((entry) => entry.version === selectedVersion)) {
        versionSelect.value = selectedVersion;
        renderVersionMeta();
        return;
      }
    }
    versionSelect.replaceChildren();
    versions.forEach((entry, index) => {
      const option = document.createElement('option');
      option.value = entry.version;
      option.textContent = describeVersionOption(entry, {
        isLatest: index === 0,
        currentVersion
      });
      versionSelect.append(option);
    });
    selectedVersion = versions.length > 0 ? versions[0].version : null;
    if (selectedVersion !== null) {
      versionSelect.value = selectedVersion;
    }
    renderVersionMeta();
  };

  versionSelect.addEventListener('change', () => {
    selectedVersion = versionSelect.value;
    renderVersionMeta();
  });

  // ---- 下载进度 ----

  const setProgress = (visible: boolean, percent: number, text: string) => {
    progress.hidden = !visible;
    progressBar.style.width = `${Math.max(0, Math.min(100, percent))}%`;
    progressText.textContent = text;
  };

  const renderDownloadState = (state: UpdateState, message: string, percent: number, received: number, total: number) => {
    downloadState = state;
    switch (state) {
      case 'downloading': {
        const size = formatBytes(total);
        const done = formatBytes(received);
        setProgress(true, percent, size ? `${percent}%（${done} / ${size}）` : `${percent}%`);
        downloadButton.disabled = true;
        downloadButton.textContent = '正在下载…';
        cancelButton.textContent = '取消下载';
        break;
      }
      case 'verifying': {
        setProgress(true, 100, message || '正在校验安装包…');
        downloadButton.disabled = true;
        downloadButton.textContent = '正在校验…';
        cancelButton.textContent = '取消下载';
        break;
      }
      case 'ready': {
        setProgress(false, 100, '');
        downloadButton.disabled = false;
        downloadButton.textContent = '立即安装';
        cancelButton.textContent = '稍后';
        break;
      }
      case 'installing': {
        setProgress(false, 100, '');
        downloadButton.disabled = true;
        downloadButton.textContent = '正在安装…';
        cancelButton.textContent = '稍后';
        break;
      }
      case 'error': {
        setProgress(false, 0, '');
        downloadButton.disabled = false;
        downloadButton.textContent = '重试';
        cancelButton.textContent = '稍后';
        break;
      }
      default: {
        setProgress(false, 0, '');
        downloadButton.disabled = false;
        downloadButton.textContent = '立即更新';
        cancelButton.textContent = '稍后';
        break;
      }
    }
  };

  // ---- 响应处理 ----

  // 只有用户点过「检查更新」之后才允许自动弹出更新对话框。status 响应（关于页加载时
  // 发起的查询，可能合并了 Server 启动检测的结果）只在状态行内联提示——曾经它在后台
  // 直接 showModal，而关于页是延迟加载的、用户停在别的分节时容器是 display:none，
  // 一个不可见的模态对话框会把整个设置页锁死。
  const openUpdateDialog = () => {
    if (versions.length === 0) {
      return;
    }
    fillVersionSelect();
    renderDownloadState(downloadState, '', 0, 0, 0);
    setDialogOpen(true);
  };

  const handleResponse = (response: UpdateResponse) => {
    if (autoProgressMode) {
      handleAutoProgressResponse(response);
    }
    if (response.requestId === activeRequestId) {
      activeRequestId = null;
    }
    if (typeof response.currentVersion === 'string' && response.currentVersion) {
      currentVersion = response.currentVersion;
      versionLabel.textContent = `v${currentVersion}`;
    }
    if (typeof response.lastCheckedAt === 'string') {
      lastCheckedAt = response.lastCheckedAt;
    }

    const normalized = normalizeVersions(response.versions);
    if (normalized.length > 0) {
      versions = normalized;
    }
    const state = response.state;
    const message = response.message ?? '';

    if (response.action === 'download') {
      // 下载进度推送与请求 id 无关：对话框可能关过再开，进度照常反映。
      renderDownloadState(state, message, response.percent ?? 0, response.receivedBytes ?? 0, response.totalBytes ?? 0);
      if (state === 'error') {
        setStatus(message || '下载失败，请重试', 'error');
      } else if (state === 'ready') {
        setStatus('安装包已就绪，可以安装', 'success');
      }
      return;
    }

    if (response.action === 'install') {
      if (response.ok) {
        setStatus('正在启动安装程序，安装期间输入法会短暂重启…', 'success');
      } else {
        setStatus(message || '安装启动失败，请重试', 'error');
      }
      return;
    }

    if (response.action === 'cancel') {
      renderDownloadState('idle', '', 0, 0, 0);
      setStatus('下载已取消', 'idle');
      return;
    }

    // check / status
    if (state === 'checking') {
      checkButton.disabled = true;
      checkButton.textContent = '正在检查…';
      setStatus(response.ok ? '正在检查更新…' : '前一次检查还在进行，请稍候…', 'idle');
      return;
    }
    // 下载 / 校验 / 就绪 / 安装中：这些状态由 download 推送驱动，check 与 status 的响应
    // 只是同一状态的另一种到达方式（例如忙碌拒绝），照常渲染进度，不碰检查按钮。
    if (state === 'downloading' || state === 'verifying' || state === 'ready' || state === 'installing') {
      renderDownloadState(state, message, response.percent ?? 0, response.receivedBytes ?? 0, response.totalBytes ?? 0);
      setStatus(describeUpdateStatus(state, message, lastCheckedAt), 'idle');
      return;
    }
    checkButton.disabled = false;
    checkButton.textContent = '检查更新';

    if (state === 'error') {
      // 检查失败但本地已知有更新时，用户刚点过按钮，把对话框摆出来，内容用上次检测的结果。
      if (versions.length > 0 && downloadState !== 'downloading' && downloadState !== 'ready') {
        openUpdateDialog();
        setStatus(`${message || '检查失败'}，显示上次检测到的版本`, 'error');
      } else {
        setStatus(message || '检查失败，请稍后重试', 'error');
      }
      return;
    }
    if (state === 'updateAvailable') {
      // 手动检查的响应用户刚点了按钮，直接弹对话框；status 响应（关于页加载时的查询，
      // 可能合并了 Server 启动检测的结果）只在状态行提示，不弹模态——见 openUpdateDialog 注释。
      if (response.action === 'check') {
        openUpdateDialog();
        return;
      }
      setStatus(describeUpdateStatus('updateAvailable', message, lastCheckedAt), 'success');
      return;
    }
    if (state === 'upToDate') {
      setStatus(describeUpdateStatus('upToDate', message, lastCheckedAt), 'success');
      return;
    }
    setStatus(describeUpdateStatus(state as UpdateState, message, lastCheckedAt), 'idle');
  };

  onHostMessage('updateResponse', handleResponse);

  // ---- 自动更新的进度模式 ----

  // Server 进程（另一个进程）正在自动更新时，宿主把设置页切到「关于」并进入这个
  // 模式：对话框直接打开，状态每秒轮询一次。进度来自 Server 写在状态文件里的
  // live 对象（设置进程合并后经 updateResponse 返回，见 update_manager.cpp 的
  // GetMergedStatus）。安装阶段本窗口会被安装器关闭——那之后输入法会自己重启。
  let autoProgressMode = false;
  let autoPollTimer: number | undefined;

  const stopAutoPolling = () => {
    if (autoPollTimer !== undefined) {
      window.clearInterval(autoPollTimer);
      autoPollTimer = undefined;
    }
  };

  const enterAutoUpdateMode = () => {
    if (autoProgressMode) return;
    autoProgressMode = true;
    // 自动模式的对话框只用来展示：版本选择、下载、安装都由 Server 发起。
    fillVersionSelect();
    renderDownloadState('downloading', '', 0, 0, 0);
    setDialogOpen(true);
    setStatus('自动更新进行中…', 'idle');
    post('status');
    stopAutoPolling();
    autoPollTimer = window.setInterval(() => {
      if (!autoProgressMode) return;
      post('status');
    }, 1000);
  };

  const handleAutoProgressResponse = (response: UpdateResponse) => {
    const state = response.state;
    if (state === 'error') {
      stopAutoPolling();
      setStatus(response.message || '自动更新失败，可在本页手动重试', 'error');
      return;
    }
    if (state === 'upToDate' || state === 'updateAvailable') {
      stopAutoPolling();
      return;
    }
    if (state === 'installing') {
      setStatus('正在安装更新，安装期间输入法会短暂重启…', 'success');
    }
  };

  window.addEventListener('msime:auto-update-progress', enterAutoUpdateMode);
  if ((window as unknown as { __msimeAutoUpdateProgress?: boolean }).__msimeAutoUpdateProgress) {
    enterAutoUpdateMode();
  }

  // ---- 按钮 ----

  cancelButton.addEventListener('click', () => {
    if (autoProgressMode) {
      // 自动模式：只关掉对话框。绝不能发 cancel——那会取消别的进程的下载上下文。
      setDialogOpen(false);
      return;
    }
    if (downloadState === 'downloading' || downloadState === 'verifying') {
      post('cancel');
      return;
    }
    // 稍后：对话框关掉，下载（若有）在后台继续，状态行仍可见。
    setDialogOpen(false);
  });
  downloadButton.addEventListener('click', () => {
    if (autoProgressMode) {
      // 自动模式的安装由 Server 发起，这里没有可点的操作。
      return;
    }
    if (downloadState === 'ready') {
      post('install', selectedVersion ?? undefined);
      return;
    }
    if (downloadState === 'downloading' || downloadState === 'verifying' || downloadState === 'installing') {
      return;
    }
    if (!selectedVersion) {
      return;
    }
    post('download', selectedVersion);
  });
  releaseButton.addEventListener('click', () => {
    const entry = versions.find((item) => item.version === selectedVersion);
    postExternalUrl(entry?.releaseUrl || RELEASE_PAGE_URL);
  });
  dialog.addEventListener('click', (event) => {
    if (event.target === dialog) {
      cancelButton.click();
    }
  });

  checkButton.addEventListener('click', () => {
    if (activeRequestId !== null) {
      return;
    }
    post('check');
  });

  // 打开关于页时先问一次状态：Server 启动检测的结果在另一个进程里，经状态文件合并后
  // 随这次响应到达，只在状态行提示（不弹模态对话框）。
  post('status');
}

function postExternalUrl(url: string): void {
  if (window.chrome?.webview) {
    window.chrome?.webview.postMessage(serializeHostMessage({ type: 'openExternalUrl', data: url }));
    return;
  }

  window.open(url, '_blank', 'noopener,noreferrer');
}
