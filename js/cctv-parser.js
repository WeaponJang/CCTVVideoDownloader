/**
 * CCTV 视频解析器
 * 从央视网页面提取视频信息并获取下载地址
 */

const https = require('https');
const http = require('http');
const crypto = require('crypto');
const { URL, URLSearchParams } = require('url');
const HLSParser = require('./hls-parser.js');

// CCTV 有效域名后缀
const CCTV_SUFFIXES = ['cctv.com', 'cctv.cn', 'cntv.cn'];

const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

/**
 * HTTP(S) GET 请求，返回 Promise，支持重试
 */
function httpGet(url, options = {}) {
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
      timeout: options.timeout || 60000
    };

    const req = mod.request(reqOptions, (res) => {
      // 处理重定向
      if ([301, 302, 303, 307].includes(res.statusCode)) {
        const location = res.headers.location;
        if (location) {
          resolve(httpGet(location, options));
          return;
        }
      }

      let data = '';
      res.setEncoding('utf8');
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, body: data }));
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error(`Request timeout: ${url}`)); });
    req.end();
  });
}

/**
 * 从 URL 判断是否为 CCTV 视频
 */
function isCCTVUrl(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    return CCTV_SUFFIXES.some(suffix => {
      return hostname === suffix || hostname.endsWith('.' + suffix);
    });
  } catch (e) {
    return false;
  }
}

/**
 * 从页面 HTML 中提取视频 ID (pid/guid)
 */
function extractVideoId(html) {
  const rules = [
    /var\s+guid\s*=\s*["']([\da-fA-F]+)/,
    /videoCenterId(?:["']\s*,|:)\s*["']([\da-fA-F]+)/,
    /changePlayer\s*\(\s*["']([\da-fA-F]+)/,
    /load[Vv]ideo\s*\(\s*["']([\da-fA-F]+)/,
    /var\s+initMyAray\s*=\s*["']([\da-fA-F]+)/,
    /var\s+ids\s*=\s*\[["']([\da-fA-F]+)/
  ];

  for (const rule of rules) {
    const match = html.match(rule);
    if (match) return match[1];
  }
  return null;
}

/**
 * MD5 哈希
 */
function md5(str) {
  return crypto.createHash('md5').update(String(str)).digest('hex');
}

/**
 * 解析 CCTV 视频 URL，返回视频信息
 * @param {string} url - 央视网页面 URL
 * @param {function} onProgress - 进度回调
 * @returns {object} 视频信息对象
 */
async function parseCCTVVideo(url, onProgress = () => {}) {
  if (!isCCTVUrl(url)) {
    throw new Error('不是有效的央视网视频链接');
  }

  onProgress({ stage: 'fetch', message: '正在获取视频页面...' });

  // 1. 获取页面 HTML
  const pageResp = await httpGet(url);
  const videoId = extractVideoId(pageResp.body);
  if (!videoId) {
    throw new Error('无法从页面中提取视频ID');
  }

  onProgress({ stage: 'parse', message: `视频ID: ${videoId}，正在获取视频信息...` });

  // 2. 构造 API 请求参数
  const tsp = String(Math.floor(Date.now() / 1000));
  const vn = '2049';
  const uid = '826D8646DEBBFD97A82D23CAE45A55BE';
  const secret = '47899B86370B879139C08EA3B5E88267';
  const vc = md5(tsp + vn + secret + uid);

  const params = new URLSearchParams({
    pid: videoId,
    client: 'flash',
    im: '0',
    tsp: tsp,
    vn: vn,
    vc: vc,
    uid: uid,
    wlan: ''
  });

  const apiUrl = `https://vdn.apps.cntv.cn/api/getHttpVideoInfo.do?${params.toString()}`;

  // 3. 调用 API 获取视频信息
  const apiResp = await httpGet(apiUrl);
  let videoData;
  try {
    videoData = JSON.parse(apiResp.body);
  } catch (e) {
    throw new Error('API 返回数据解析失败: ' + e.message);
  }

  onProgress({ stage: 'resolve', message: '正在解析下载地址...' });

  // 4. 提取下载地址
  const manifest = videoData.manifest || {};
  const hlsKeys = ['hls_h5e_url', 'hls_url'];
  let downloadUrl = null;
  let hlsKey = null;
  let isEncrypted = false;

  for (const key of hlsKeys) {
    const candidate = videoData[key] || manifest[key];
    if (candidate) {
      downloadUrl = candidate;
      hlsKey = key;
      isEncrypted = (key === 'hls_h5e_url');
      break;
    }
  }

  if (!downloadUrl) {
    // 尝试直接使用 mp4 地址
    if (videoData.video && videoData.video.chapters) {
      const chapters = videoData.video.chapters;
      if (chapters.length > 0 && chapters[0].url) {
        downloadUrl = chapters[0].url;
      }
    }
  }

  if (!downloadUrl) {
    throw new Error('未找到可用的视频下载地址');
  }

  // 5. 如果是 HLS，解析最佳画质
  let finalUrl = downloadUrl;
  if (downloadUrl.includes('.m3u8')) {
    try {
      const baseUrl = downloadUrl;
      const m3u8Resp = await httpGet(downloadUrl);
      const parser = new HLSParser(baseUrl);
      const bestVariant = parser.best(m3u8Resp.body);
      finalUrl = bestVariant.uri;
      onProgress({ stage: 'resolve', message: `已选择最佳画质: ${bestVariant.resolution.join('x') || 'unknown'}` });
    } catch (e) {
      // 如果解析失败，使用原始 URL
      onProgress({ stage: 'resolve', message: 'HLS解析失败，使用默认画质' });
    }
  }

  const title = sanitizeFilename(videoData.title || 'cctv_video');

  return {
    videoId,
    title,
    downloadUrl: finalUrl,
    rawDownloadUrl: downloadUrl,
    hlsKey,
    isEncrypted,
    coverUrl: videoData.image || '',
    duration: videoData.video?.total_length || '',
    source: 'CCTV'
  };
}

/**
 * 清理文件名中的非法字符
 */
function sanitizeFilename(name) {
  return name
    .replace(/[<>:"/\\|?*\x00-\x1f]/g, '_')
    .replace(/\s+/g, ' ')
    .replace(/\.+$/, '')
    .trim() || 'cctv_video';
}

module.exports = {
  parseCCTVVideo,
  isCCTVUrl,
  extractVideoId,
  httpGet,
  sanitizeFilename
};
