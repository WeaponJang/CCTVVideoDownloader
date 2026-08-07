/**
 * CCTV 视频下载器
 * 支持 HLS 流下载（二进制合并）与加密流解密（WASM + ffmpeg）
 */

const { spawn, execFile } = require('child_process');
const path = require('path');
const fs = require('fs');
const https = require('https');
const http = require('http');
const { URL } = require('url');
const { httpGet, sanitizeFilename } = require('./cctv-parser.js');

const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
const packageDir = path.join(path.dirname(process.execPath), 'package.nw');
/**
 * 二进制拼接合并多个 TS 文件
 * MPEG-TS 是流式格式，直接顺序追加即可播放
 */
function concatTSFiles(segmentFiles, outputPath) {
  return new Promise((resolve, reject) => {
    const writeStream = fs.createWriteStream(outputPath);
    let idx = 0;
    function pipeNext() {
      if (idx >= segmentFiles.length) { writeStream.end(); return; }
      const rs = fs.createReadStream(segmentFiles[idx++]);
      rs.pipe(writeStream, { end: false });
      rs.on('end', pipeNext);
      rs.on('error', reject);
    }
    writeStream.on('finish', () => resolve(outputPath));
    writeStream.on('error', reject);
    pipeNext();
  });
}

/**
 * 查找 ffmpeg 路径
 */
function findFFmpeg() {
  // 优先使用 NW.js 目录下的 ffmpeg
  const nwjsDir = path.dirname(process.execPath);
  const candidates = [
    path.join(nwjsDir, 'ffmpeg.exe'),
    path.join(nwjsDir, 'package.nw', 'ffmpeg.exe'),
    'ffmpeg' // PATH fallback
  ];

  for (const candidate of candidates) {
    try {
      if (path.isAbsolute(candidate) && fs.existsSync(candidate)) return candidate;
    } catch (e) {}
  }
  return 'ffmpeg';
}

/**
 * 下载单个文件到指定路径
 */
function downloadFile(url, destPath, options = {}) {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(url);
    const isHttps = parsedUrl.protocol === 'https:';
    const mod = isHttps ? https : http;

    const reqOptions = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (isHttps ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: 'GET',
      headers: {
        'User-Agent': options.userAgent || USER_AGENT,
        'Accept': '*/*',
        'Accept-Encoding': 'identity',
        'Referer': 'https://www.cctv.com/',
        ...(options.headers || {})
      },
      timeout: options.timeout || 120000
    };

    const req = mod.request(reqOptions, (res) => {
      if ([301, 302, 303, 307].includes(res.statusCode)) {
        const location = res.headers.location;
        if (location) {
          resolve(downloadFile(location, destPath, options));
          return;
        }
      }

      // 检查 HTTP 状态码，非 2xx 视为错误
      if (res.statusCode < 200 || res.statusCode >= 300) {
        fs.unlink(destPath, () => {});
        reject(new Error(`HTTP ${res.statusCode} for ${url}`));
        return;
      }

      const totalSize = parseInt(res.headers['content-length'] || '0', 10);
      let downloadedSize = 0;
      const fileStream = fs.createWriteStream(destPath);

      res.on('data', (chunk) => {
        downloadedSize += chunk.length;
        if (options.onProgress && totalSize > 0) {
          options.onProgress(downloadedSize, totalSize);
        }
      });

      res.pipe(fileStream);
      fileStream.on('finish', () => {
        fileStream.close();
        resolve(destPath);
      });
      fileStream.on('error', (err) => {
        fs.unlink(destPath, () => {});
        reject(err);
      });
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error(`Download timeout: ${url}`)); });
    req.end();
  });
}

/**
 * 解析 m3u8 播放列表，获取所有 TS 片段 URL
 */
function parseM3u8Segments(m3u8Text, baseUrl) {
  const lines = m3u8Text.split(/\r?\n/).map(l => l.trim()).filter(l => l);
  const segments = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.startsWith('#')) continue;
    if (!line) continue;

    let url = line;
    if (!url.startsWith('http')) {
      try {
        url = new URL(url, baseUrl).href;
      } catch (e) {
        url = baseUrl.replace(/\/[^\/]*$/, '/') + url;
      }
    }
    segments.push(url);
  }

  return segments;
}

/**
 * 使用 ffmpeg 直接从 HLS URL 下载并合并
 * 适用于非加密的 HLS 流
 */
function downloadWithFFmpeg(url, outputPath, options = {}) {
  return new Promise((resolve, reject) => {
    const ffmpegPath = findFFmpeg();
    const args = [
      '-y',
      '-headers', `User-Agent: ${USER_AGENT}\r\n`,
      '-i', url,
      '-c', 'copy',
      '-bsf:a', 'aac_adtstoasc',
      outputPath
    ];

    options.onLog && options.onLog(`执行: ${ffmpegPath} ${args.join(' ')}`);

    const proc = spawn(ffmpegPath, args, { windowsHide: true });
    let stderr = '';

    proc.stderr.on('data', (data) => {
      const text = data.toString();
      stderr += text;
      // 解析 ffmpeg 进度
      if (options.onProgress) {
        const timeMatch = text.match(/time=(\d+):(\d+):(\d+\.?\d*)/);
        if (timeMatch) {
          const seconds = parseFloat(timeMatch[1]) * 3600 + parseFloat(timeMatch[2]) * 60 + parseFloat(timeMatch[3]);
          options.onProgress(-1, -1, seconds);
        }
      }
    });

    proc.on('close', (code) => {
      if (code === 0) {
        resolve(outputPath);
      } else {
        reject(new Error(`ffmpeg 退出，代码 ${code}: ${stderr.slice(-500)}`));
      }
    });

    proc.on('error', (err) => {
      reject(new Error(`ffmpeg 启动失败: ${err.message}`));
    });
  });
}

/**
 * 查找可用的 Node.js 可执行文件
 * decrypt.js 需要独立 Node.js 运行时（ES module 支持）
 */
function findNode() {
  const candidates = [
    path.join(path.dirname(process.execPath), 'node.exe'),
    path.join(path.dirname(process.execPath), 'package.nw', 'node.exe')
  ];
  for (const c of candidates) {
    try {
      if (!path.isAbsolute(c)) {
        // 检查 PATH 中是否存在
        const { execSync } = require('child_process');
        execSync(`where ${c}`, { stdio: 'pipe' });
        return c;
      }
      if (fs.existsSync(c)) return c;
    } catch (e) {}
  }
  return null;
}

/**
 * 调用 decrypt.js 解密单个加密 HLS 片段
 * 原项目流程: node decrypt.js <in_file> <out_file>
 * 需要先下载加密片段到本地文件，再传入 decrypt.js
 */
function decryptSegment(encryptedFilePath, outputPath, onLog) {
  return new Promise((resolve, reject) => {
    const nodeExe = findNode();
    let decPath = path.join(packageDir, 'js', 'cctv', 'dec.exe');
    if (!nodeExe) {
	  if (!fs.existsSync(decPath)) {
		reject(new Error('解密程序不存在: ' + decPath));
		return;
	  }
	  const args = [encryptedFilePath, outputPath];
		onLog(`执行: ${decPath} ${args.map(a => path.basename(a)).join(' ')}`);
		const proc = spawn(decPath, args, {
		  windowsHide: true,
		  cwd: path.join(packageDir, 'js', 'cctv')
		});

		let stderr = '';
		proc.stderr.on('data', d => stderr += d.toString());
		proc.stdout.on('data', d => {
		  const msg = d.toString().trim();
		  if (msg && onLog) onLog('[decrypt] ' + msg);
		});

		proc.on('close', (code) => {
		  if (code === 0) {
			resolve(outputPath);
		  } else {
			reject(new Error(`dec 退出码 ${code}: ${stderr.slice(-500)}`));
		  }
		});
		proc.on('error', (err) => {
		  reject(new Error(`启动 dec 失败: ${err.message}`));
		});
    } else {
		const decryptScript = path.join(packageDir, 'js','cctv', 'decrypt.js');
		if (!fs.existsSync(decryptScript)) {
		  reject(new Error('解密脚本不存在: ' + decryptScript));
		  return;
		}

		const args = [decryptScript, encryptedFilePath, outputPath];
		onLog(`执行: ${nodeExe} ${args.map(a => path.basename(a)).join(' ')}`);
		const proc = spawn(nodeExe, args, {
		  windowsHide: true,
		  cwd: path.join(packageDir, 'js', 'cctv')  // 确保 cctv_wasm.js 相对路径正确
		});

		let stderr = '';
		proc.stderr.on('data', d => stderr += d.toString());
		proc.stdout.on('data', d => {
		  const msg = d.toString().trim();
		  if (msg && onLog) onLog('[decrypt] ' + msg);
		});

		proc.on('close', (code) => {
		  if (code === 0) {
			resolve(outputPath);
		  } else {
			reject(new Error(`decrypt.js 退出码 ${code}: ${stderr.slice(-500)}`));
		  }
		});
		proc.on('error', (err) => {
		  reject(new Error(`启动 Node.js 失败: ${err.message}`));
		});
	}
  });
}

/**
 * 下载并解密加密 HLS 流（hls_h5e_url）
 * 流程: 解析 m3u8 -> 逐段 decrypt.js 解密 -> ffmpeg concat 合并 MP4
 */
async function downloadEncryptedHLS(m3u8Url, outputPath, options = {}) {
  const baseUrl = m3u8Url;
  const onProgress = options.onProgress || (() => {});
  const onLog = options.onLog || (() => {});

  onLog('正在获取 h5e 接口的 m3u8 播放列表...');
  const m3u8Resp = await httpGet(m3u8Url);
  const segments = parseM3u8Segments(m3u8Resp.body, baseUrl);

  if (!segments.length) {
    throw new Error('m3u8 中未找到任何视频片段');
  }

  onLog(`共 ${segments.length} 个加密片段，开始逐段解密...`);

  // 创建临时目录
  const tempDir = outputPath + '.tmp';
  if (fs.existsSync(tempDir)) {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
  fs.mkdirSync(tempDir, { recursive: true });

  const decryptedFiles = [];

  try {
    for (let i = 0; i < segments.length; i++) {
      const segUrl = segments[i];
      const encFile = path.join(tempDir, `enc_${String(i).padStart(8, '0')}.ts`);
      const segOutput = path.join(tempDir, `segment_${String(i).padStart(8, '0')}.mp4`);

      onProgress(i, segments.length);
      onLog(`下载加密片段 ${i + 1}/${segments.length}...`);

      // 步骤1: 先下载加密片段到本地文件
      await downloadFile(segUrl, encFile);

      onLog(`解密片段 ${i + 1}/${segments.length}...`);
      // 步骤2: 用 decrypt.js 解密本地文件
      await decryptSegment(encFile, segOutput, onLog);
      decryptedFiles.push(segOutput);
    }

    onProgress(segments.length, segments.length);
    onLog('所有片段解密完成，正在合并...');

    // 生成 concat 文件列表
    const concatListPath = path.join(tempDir, 'concat.txt');
    const concatContent = decryptedFiles.map(f => {
      const escaped = f.replace(/\\/g, '/').replace(/'/g, "'\\''");
      return `file '${escaped}'`;
    }).join('\n');
    fs.writeFileSync(concatListPath, concatContent, 'utf8');

    // 使用 ffmpeg concat 合并
    const ffmpegPath = findFFmpeg();
    await new Promise((resolve, reject) => {
      const args = [
        '-y',
        '-fflags', '+genpts',
        '-f', 'concat',
        '-safe', '0',
        '-i', concatListPath,
        '-avoid_negative_ts', 'make_zero',
        '-map', '0:v:0',
        '-map', '0:a?',
        '-c:v', 'copy',
        '-c:a', 'copy',
        '-movflags', '+faststart',
        '-vsync', '0',
        outputPath
      ];

      onLog(`合并命令: ${ffmpegPath} ${args.join(' ')}`);

      const proc = spawn(ffmpegPath, args, { windowsHide: true });
      let stderr = '';
      proc.stderr.on('data', d => stderr += d.toString());
      proc.on('close', code => {
        if (code === 0) resolve();
        else reject(new Error(`ffmpeg 合并失败 (code ${code}): ${stderr.slice(-500)}`));
      });
      proc.on('error', reject);
    });

    onLog('合并完成！');

  } finally {
    try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch (e) {}
  }

  return outputPath;
}

/**
 * 逐段下载 HLS 片段并合并（非加密流，二进制拼接）
 */
async function downloadPlainHLS(m3u8Url, outputPath, options = {}) {
  const baseUrl = m3u8Url;
  const onProgress = options.onProgress || (() => {});
  const onLog = options.onLog || (() => {});

  onLog('m3u8 地址: ' + m3u8Url);
  onLog('正在获取 m3u8 播放列表...');
  const m3u8Resp = await httpGet(m3u8Url);

  // 诊断: 输出 m3u8 前几行
  const m3u8Lines = m3u8Resp.body.split(/\r?\n/).filter(l => l.trim()).slice(0, 5);
  onLog('m3u8 内容预览: ' + m3u8Lines.join(' | '));

  const segments = parseM3u8Segments(m3u8Resp.body, baseUrl);

  if (!segments.length) {
    throw new Error('m3u8 中未找到任何视频片段');
  }

  onLog(`共 ${segments.length} 个片段，前3个URL:`);
  segments.slice(0, 3).forEach((u, i) => onLog(`  [${i}] ${u}`));

  const tempDir = outputPath + '.tmp';
  onLog('临时目录: ' + tempDir);
  onLog('输出文件: ' + outputPath);
  if (fs.existsSync(tempDir)) {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
  fs.mkdirSync(tempDir, { recursive: true });

  const segmentFiles = [];

  try {
    for (let i = 0; i < segments.length; i++) {
      const segUrl = segments[i];
      const segPath = path.join(tempDir, `seg_${String(i).padStart(5, '0')}.ts`);

      onProgress(i, segments.length);
      try {
        await downloadFile(segUrl, segPath);
      } catch (dlErr) {
        onLog(`片段 ${i} 下载失败: ${dlErr.message}`);
        throw dlErr;
      }

      // 验证文件是否创建
      if (!fs.existsSync(segPath)) {
        throw new Error(`片段 ${i} 下载后文件不存在: ${segPath}`);
      }

      segmentFiles.push(segPath);
    }

    onLog('所有片段下载完成，正在二进制合并...');
    await concatTSFiles(segmentFiles, outputPath);
    onLog('合并完成！');

  } finally {
    try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch (e) {}
  }

  return outputPath;
}

/**
 * 主下载入口
 * @param {object} videoInfo - parseCCTVVideo 返回的视频信息
 * @param {string} saveDir - 保存目录
 * @param {object} callbacks - 回调函数集合
 */
async function downloadVideo(videoInfo, saveDir, callbacks = {}) {
  const { onProgress, onLog, onComplete, onError } = callbacks;
  const log = onLog || (() => {});
  const progress = onProgress || (() => {});

  try {
    // 确保保存目录存在
    if (!fs.existsSync(saveDir)) {
      fs.mkdirSync(saveDir, { recursive: true });
    }

    const ext = videoInfo.isEncrypted ? 'mp4' : 'ts';
    const filename = sanitizeFilename(videoInfo.title) + '.' + ext;
    const outputPath = path.join(saveDir, filename);

    // 避免文件名重复
    let finalPath = outputPath;
    let counter = 1;
    while (fs.existsSync(finalPath)) {
      const nameWithoutExt = sanitizeFilename(videoInfo.title);
      finalPath = path.join(saveDir, `${nameWithoutExt}_${counter}.${ext}`);
      counter++;
    }

    log(`保存至: ${finalPath}`);
    log(`视频类型: ${videoInfo.isEncrypted ? '加密流' : '标准HLS'}`);

    // downloadUrl 是解析后的最佳画质媒体播放列表，rawDownloadUrl 是 master playlist
    const m3u8Url = videoInfo.downloadUrl || videoInfo.rawDownloadUrl;
    log(`播放列表: ${m3u8Url}`);
    log(`ffmpeg: ${findFFmpeg()}`);

    if (videoInfo.isEncrypted) {
      // 加密流: 逐段解密 + ffmpeg 合并
      log('检测到加密视频流 (hls_h5e_url)，启动解密流程...');
      await downloadEncryptedHLS(m3u8Url, finalPath, {
        onProgress: (current, total) => { progress(current, total); },
        onLog: log
      });
    } else {
      // 非加密流: 逐段下载 + 二进制合并
      log('逐段下载并合并中...');
      await downloadPlainHLS(m3u8Url, finalPath, {
        onProgress: (current, total) => { progress(current, total); },
        onLog: log
      });
    }

    log('下载完成！');
    onComplete && onComplete(finalPath);
    return finalPath;

  } catch (err) {
    log('下载出错: ' + err.message);
    onError && onError(err);
    throw err;
  }
}

module.exports = {
  downloadVideo,
  downloadEncryptedHLS,
  downloadPlainHLS,
  downloadFile,
  decryptSegment,
  findFFmpeg
};
