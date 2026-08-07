/**
 * 主窗口逻辑 - NW.js 浏览器上下文
 * 连接 UI 与 Node.js 模块
 */

// NW.js 混合上下文下可直接 require
const { parseCCTVVideo, isCCTVUrl } = require('./js/cctv-parser.js');
const { downloadVideo, findFFmpeg } = require('./js/cctv-downloader.js');
const path = require('path');
const fs = require('fs');
const { shell } = require('nw.gui') || { shell: null };

// 默认下载目录
const DEFAULT_SAVE_DIR = path.join(
  process.env.USERPROFILE || process.env.HOME || path.dirname(process.execPath),
  'Downloads'
);

// DOM 元素
const urlInput = document.getElementById('urlInput');
const parseBtn = document.getElementById('parseBtn');
const downloadBtn = document.getElementById('downloadBtn');
const openFolderBtn = document.getElementById('openFolderBtn');
const statusArea = document.getElementById('statusArea');
const logArea = document.getElementById('logArea');
const videoTitle = document.getElementById('videoTitle');
const videoCover = document.getElementById('videoCover');
const videoInfo = document.getElementById('videoInfo');
const saveDirInput = document.getElementById('saveDirInput');
const changeDirBtn = document.getElementById('changeDirBtn');
const progressContainer = document.getElementById('progressContainer');
const progressBar = document.getElementById('progressBar');
const progressText = document.getElementById('progressText');

let currentVideoInfo = null;
let currentSaveDir = DEFAULT_SAVE_DIR;
let isDownloading = false;

// 初始化
saveDirInput.value = currentSaveDir;

/**
 * 添加日志
 */
function addLog(msg) {
  const time = new Date().toLocaleTimeString();
  const line = document.createElement('div');
  line.className = 'log-line';
  line.innerHTML = `<span class="log-time">[${time}]</span> ${escapeHtml(msg)}`;
  logArea.appendChild(line);
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
  if (total > 0) {
    const pct = Math.round((current / total) * 100);
    progressBar.style.width = pct + '%';
    progressText.textContent = `${pct}% (${current}/${total})`;
  } else if (typeof extra === 'number') {
    // ffmpeg 时间进度
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
  videoTitle.textContent = '';
  videoCover.src = '';
  videoCover.style.display = 'none';
  videoInfo.textContent = '';

  try {
    currentVideoInfo = await parseCCTVVideo(url, (info) => {
      addLog(info.message);
      setStatus(info.message, 'info');
    });

    // 显示视频信息
    videoTitle.textContent = currentVideoInfo.title;
    if (currentVideoInfo.coverUrl) {
      videoCover.src = currentVideoInfo.coverUrl;
      videoCover.style.display = 'block';
    }

    let infoText = `视频ID: ${currentVideoInfo.videoId}`;
    if (currentVideoInfo.duration) {
      infoText += ` | 时长: ${currentVideoInfo.duration}`;
    }
    infoText += ` | 类型: ${currentVideoInfo.isEncrypted ? '加密流(WASM解密)' : '标准HLS(二进制合并)'}`;
    videoInfo.textContent = infoText;

    setStatus('解析完成，可以下载', 'success');
    addLog(`解析成功: ${currentVideoInfo.title}`);
    downloadBtn.disabled = false;

  } catch (err) {
    setStatus('解析失败: ' + err.message, 'error');
    addLog('解析错误: ' + err.message);
    currentVideoInfo = null;
    downloadBtn.disabled = true;
  } finally {
    parseBtn.disabled = false;
  }
}

/**
 * 下载视频
 */
async function handleDownload() {
  if (!currentVideoInfo || isDownloading) return;

  isDownloading = true;
  downloadBtn.disabled = true;
  parseBtn.disabled = true;
  hideProgress();

  addLog('开始下载...');
  setStatus('下载中...', 'info');

  try {
    const savePath = await downloadVideo(currentVideoInfo, currentSaveDir, {
      onProgress: (current, total, time) => {
        updateProgress(current, total, time);
      },
      onLog: (msg) => {
        addLog(msg);
      },
      onComplete: (finalPath) => {
        setStatus('下载完成: ' + path.basename(finalPath), 'success');
        addLog('文件已保存至: ' + finalPath);
      },
      onError: (err) => {
        setStatus('下载失败: ' + err.message, 'error');
      }
    });

  } catch (err) {
    setStatus('下载失败: ' + err.message, 'error');
    addLog('下载错误: ' + err.message);
  } finally {
    isDownloading = false;
    downloadBtn.disabled = false;
    parseBtn.disabled = false;
    hideProgress();
  }
}

/**
 * 更改保存目录
 */
function handleChangeDir() {
  // 使用 NW.js 的文件选择对话框
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
      addLog('保存目录已更改为: ' + dir);
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
  // 使用系统默认方式打开文件夹
  const { exec } = require('child_process');
  exec(`explorer.exe "${dir}"`);
}

// 绑定事件
parseBtn.addEventListener('click', handleParse);
downloadBtn.addEventListener('click', handleDownload);
changeDirBtn.addEventListener('click', handleChangeDir);
openFolderBtn.addEventListener('click', handleOpenFolder);

// 回车触发解析
urlInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') handleParse();
});

// 初始化状态
setStatus('就绪 - 请粘贴央视网视频链接');
addLog('CCTV视频下载器已启动');
addLog('支持域名: cctv.com, cctv.cn, cntv.cn');

// 检查环境
const ffmpegPath = findFFmpeg();
addLog(`ffmpeg: ${ffmpegPath}`);
