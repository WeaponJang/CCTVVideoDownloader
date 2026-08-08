/**
 * 主窗口逻辑 - NW.js 浏览器上下文
 * 连接 UI 与 Node.js 模块
 */

// NW.js 混合上下文下可直接 require
const { parseCCTVVideo, isCCTVUrl, buildQualityList } = require('./js/cctv-parser.js');
const { downloadVideo, findFFmpeg } = require('./js/cctv-downloader.js');
const path = require('path');
const fs = require('fs');

// 默认下载目录
const DEFAULT_SAVE_DIR = path.join(
  process.env.USERPROFILE || process.env.HOME || path.dirname(process.execPath),
  'Downloads'
);

// DOM 元素
const urlInput = document.getElementById('urlInput');
const parseBtn = document.getElementById('parseBtn');
const statusArea = document.getElementById('statusArea');
const logArea = document.getElementById('logArea');
const saveDirInput = document.getElementById('saveDirInput');
const changeDirBtn = document.getElementById('changeDirBtn');
const openFolderBtn = document.getElementById('openFolderBtn');
const progressContainer = document.getElementById('progressContainer');
const progressBar = document.getElementById('progressBar');
const progressText = document.getElementById('progressText');

// 新增 DOM 元素
const videoInfoSection = document.getElementById('videoInfoSection');
const videoInfoGrid = document.getElementById('videoInfoGrid');
const apiBadge = document.getElementById('apiBadge');
const qualitySection = document.getElementById('qualitySection');
const qualityList = document.getElementById('qualityList');
const qualityCount = document.getElementById('qualityCount');

let currentVideoInfo = null;
let currentQualities = [];
let currentSaveDir = DEFAULT_SAVE_DIR;
let isDownloading = false;

// 初始化
saveDirInput.value = currentSaveDir;

/**
 * 添加日志
 */
function addLog(msg, type) {
  const time = new Date().toLocaleTimeString();
  const div = document.createElement('div');
  div.className = 'log-line' + (type ? ' log-' + type : '');
  div.innerHTML = `<span class="log-time">[${time}]</span> ${escapeHtml(msg)}`;
  logArea.appendChild(div);
  logArea.scrollTop = logArea.scrollHeight;
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

/**
 * 设置状态
 */
function setStatus(msg, type = 'info') {
  statusArea.textContent = msg;
  statusArea.className = 'status-bar status-' + type;
}

/**
 * 更新进度条
 */
function updateProgress(current, total, extra) {
  progressContainer.style.display = 'block';
  if (total > 0 && current >= 0) {
    const pct = Math.round((current / total) * 100);
    progressBar.style.width = pct + '%';
    progressText.textContent = `${pct}% (${current}/${total})`;
  } else if (typeof extra === 'string') {
    // ffmpeg 时间进度
    progressBar.style.width = '100%';
    progressBar.className = 'progress-bar indeterminate';
    progressText.textContent = `已处理 ${extra}`;
  } else if (typeof extra === 'number') {
    const mins = Math.floor(extra / 60);
    const secs = Math.floor(extra % 60);
    progressBar.style.width = '100%';
    progressBar.className = 'progress-bar indeterminate';
    progressText.textContent = `已处理 ${mins}:${String(secs).padStart(2, '0')}`;
  }
}

function hideProgress() {
  progressContainer.style.display = 'none';
  progressBar.style.width = '0%';
  progressBar.className = 'progress-bar';
}

/**
 * 渲染视频信息网格
 */
function renderVideoInfo(info) {
  videoInfoSection.style.display = 'block';
  videoInfoGrid.innerHTML = '';

  // 封面
  const coverWrap = document.getElementById('videoCoverWrap');
  if (info.coverUrl) {
    coverWrap.innerHTML = `<img class="video-cover-img" src="${escapeHtml(info.coverUrl)}" alt="封面">`;
    coverWrap.style.display = 'block';
  } else {
    coverWrap.innerHTML = '';
    coverWrap.style.display = 'none';
  }

  const items = [
    { label: '标题', value: info.title },
    { label: 'GUID', value: info.videoId },
    { label: 'VID', value: info.vid || '-' },
    { label: '频道', value: info.playChannel || '-' },
    { label: '时长', value: (() => { const s = Math.ceil(Number(info.duration) || 0); return s > 0 ? `${Math.floor(s / 60)}分${String(s % 60).padStart(2, '0')}秒` : '-'; })() }
  ];

  for (const item of items) {
    const div = document.createElement('div');
    div.className = 'info-item';
    div.innerHTML = `<div class="info-label">${item.label}</div><div class="info-value">${escapeHtml(item.value)}</div>`;
    videoInfoGrid.appendChild(div);
  }
}

/**
 * 渲染清晰度列表
 */
function renderQualities(qualities) {
  qualitySection.style.display = 'block';
  qualityList.innerHTML = '';

  // 按码率降序排序
  qualities.sort((a, b) => (b.bitrate || 0) - (a.bitrate || 0));

  for (let i = 0; i < qualities.length; i++) {
    const q = qualities[i];
    const div = document.createElement('div');
    div.className = 'quality-item';

    const isEnc = q.source === 'bitrate-select' || q.name.includes('h5e-');
    const encTag = isEnc
      ? '<span class="q-tag tag-enc">加密</span>'
      : '<span class="q-tag tag-free">免解密</span>';

    div.innerHTML = `
      <div class="q-name">${escapeHtml(q.name)} ${encTag}</div>
      <div class="q-bitrate">${q.bitrate ? q.bitrate + 'k' : '-'}</div>
      <div class="q-url">${escapeHtml(q.url)}</div>
      <div class="q-actions">
        <button class="btn btn-small btn-copy" data-idx="${i}">复制</button>
        <button class="btn btn-small btn-dl" data-idx="${i}">下载</button>
      </div>
    `;
    qualityList.appendChild(div);
  }

  qualityCount.textContent = `${qualities.length} 个选项`;

  // 绑定按钮事件
  qualityList.querySelectorAll('.btn-copy').forEach(btn => {
    btn.addEventListener('click', () => {
      const idx = parseInt(btn.dataset.idx);
      const q = currentQualities[idx];
      if (q) {
        // 使用 NW.js 剪贴板
        try {
          const gui = require('nw.gui');
          gui.Clipboard.get().set(q.url, 'text');
        } catch (e) {
          // fallback
          navigator.clipboard && navigator.clipboard.writeText(q.url);
        }
        addLog('已复制链接: ' + q.name, 'success');
      }
    });
  });

  qualityList.querySelectorAll('.btn-dl').forEach(btn => {
    btn.addEventListener('click', () => {
      const idx = parseInt(btn.dataset.idx);
      handleDownload(idx);
    });
  });
}

/**
 * 解析视频
 */
async function handleParse() {
  const url = urlInput.value.trim();
  if (!url) {
    setStatus('请输入视频链接', 'error');
    return;
  }

  if (!isCCTVUrl(url)) {
    setStatus('请输入有效的央视网(CCTV)链接', 'error');
    return;
  }

  parseBtn.disabled = true;
  setStatus('正在解析...', 'info');
  addLog('开始解析: ' + url);

  // 清空之前的信息
  videoInfoSection.style.display = 'none';
  qualitySection.style.display = 'none';
  videoInfoGrid.innerHTML = '';
  qualityList.innerHTML = '';

  try {
    currentVideoInfo = await parseCCTVVideo(url, (info) => {
      addLog(info.message);
      setStatus(info.message, 'info');
    });

    // 渲染视频信息
    renderVideoInfo(currentVideoInfo);

    // 渲染清晰度列表
    currentQualities = currentVideoInfo.qualityList || [];
    if (currentQualities.length > 0) {
      renderQualities(currentQualities);
      apiBadge.textContent = currentVideoInfo.isEncrypted ? 'H5E' : 'HLS';
    } else {
      addLog('未解析到可用清晰度', 'warn');
    }

    setStatus('解析完成，请选择清晰度下载', 'success');
    addLog(`解析成功: ${currentVideoInfo.title}`);

  } catch (err) {
    setStatus('解析失败: ' + err.message, 'error');
    addLog('解析错误: ' + err.message, 'error');
    currentVideoInfo = null;
    currentQualities = [];
  } finally {
    parseBtn.disabled = false;
  }
}

/**
 * 下载指定清晰度
 */
async function handleDownload(qualityIndex) {
  if (isDownloading) {
    addLog('已有下载任务在进行中', 'warn');
    return;
  }

  const quality = currentQualities[qualityIndex];
  if (!quality || !currentVideoInfo) return;

  isDownloading = true;
  parseBtn.disabled = true;
  // 禁用所有下载按钮
  qualityList.querySelectorAll('.btn-dl').forEach(b => b.disabled = true);
  hideProgress();

  addLog(`开始下载 [${quality.name}]...`);
  setStatus('下载中...', 'info');

  try {
    const finalPath = await downloadVideo(quality, currentVideoInfo, currentSaveDir, {
      onProgress: (current, total, time) => {
        updateProgress(current, total, time);
      },
      onLog: (msg) => {
        addLog(msg);
      },
      onComplete: (mp4Path) => {
        setStatus('下载完成: ' + path.basename(mp4Path), 'success');
        addLog('文件已保存至: ' + mp4Path, 'success');
      },
      onError: (err) => {
        setStatus('下载失败: ' + err.message, 'error');
      }
    });

  } catch (err) {
    setStatus('下载失败: ' + err.message, 'error');
    addLog('下载错误: ' + err.message, 'error');
  } finally {
    isDownloading = false;
    parseBtn.disabled = false;
    qualityList.querySelectorAll('.btn-dl').forEach(b => b.disabled = false);
    hideProgress();
  }
}

/**
 * 更改保存目录
 */
function handleChangeDir() {
  const chooser = document.createElement('input');
  chooser.type = 'file';
  chooser.setAttribute('nwdirectory', '');
  chooser.setAttribute('nwworkingdir', currentSaveDir);
  chooser.style.display = 'none';

  chooser.addEventListener('change', (e) => {
    const dir = e.target.value;
    if (dir) {
      currentSaveDir = dir;
      saveDirInput.value = dir;
      addLog('保存目录已更改为: ' + dir, 'success');
    }
  });

  document.body.appendChild(chooser);
  chooser.click();
  setTimeout(() => chooser.remove(), 1000);
}

/**
 * 打开保存文件夹
 */
function handleOpenFolder() {
  const dir = currentSaveDir;
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  const { exec } = require('child_process');
  exec(`explorer.exe "${dir}"`);
}

// 绑定事件
parseBtn.addEventListener('click', handleParse);
changeDirBtn.addEventListener('click', handleChangeDir);
openFolderBtn.addEventListener('click', handleOpenFolder);

// 回车触发解析
urlInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') handleParse();
});

// 拖入 URL
window.addEventListener('dragover', e => e.preventDefault());
window.addEventListener('drop', e => {
  e.preventDefault();
  const text = e.dataTransfer.getData('text/plain') || e.dataTransfer.getData('text/uri-list');
  if (text && text.includes('cctv')) {
    urlInput.value = text.trim().split('\n')[0];
    addLog('已拖入 URL: ' + urlInput.value);
  }
});

// 初始化状态
setStatus('就绪 - 请粘贴央视网视频链接');
addLog('CCTV 视频下载器已启动');
addLog('支持域名: cctv.com, cctv.cn, cntv.cn');

// 检查环境
const ffmpegPath = findFFmpeg();
addLog(`ffmpeg: ${ffmpegPath}`);
