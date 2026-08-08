/**
 * CCTV 视频解析器
 * 从央视网页面提取视频信息并获取下载地址
 */

const https = require('https');
const http = require('http');
const crypto = require('crypto');
const { URL, URLSearchParams } = require('url');

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
 * 从播放页 URL 提取 VID，再调 API 获取 GUID 及元数据
 */
async function extractGuidFromPage(pageUrl) {
  let vid = null;
  try {
    const u = new URL(pageUrl);
    const parts = u.pathname.split('/');
    for (const p of parts) {
      if (/^(VIDE|ARTI)[A-Za-z0-9]+/i.test(p.replace('.shtml', ''))) {
        vid = p.replace('.shtml', '');
        break;
      }
    }
    if (!vid) {
      vid = u.searchParams.get('vid') || u.searchParams.get('VID') || u.searchParams.get('guid');
    }
  } catch (e) {}

  if (!vid) throw new Error('无法从 URL 提取 VID, 请确认是 CCTV 播放页链接');

  const infoApi = `https://api.cntv.cn/Article/newContentInfo?serviceId=tvcctv&id=${vid}`;
  const infoRes = await httpGet(infoApi);
  let infoJson;
  try {
    infoJson = JSON.parse(infoRes.body);
  } catch (e) {
    throw new Error('内容信息接口返回解析失败');
  }

  if (!infoJson || !infoJson.data || !infoJson.data.guid) {
    throw new Error('内容信息接口未返回 guid');
  }

  return {
    vid,
    guid: infoJson.data.guid,
    title: infoJson.data.title || infoJson.data.shorttitle || vid,
    publishTime: infoJson.data.publishTime || '',
    author: infoJson.data.author || '',
    summary: infoJson.data.description || infoJson.data.summary || '',
    videoLength: infoJson.data.videoLength || 0,
    templateType: infoJson.data.template_type || 0
  };
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

  // 1. 从 URL 提取 VID 并获取 GUID + 元数据
  const pageInfo = await extractGuidFromPage(url);
  const videoId = pageInfo.guid;

  onProgress({ stage: 'parse', message: `视频ID: ${videoId}，正在获取视频信息...` });

  // 2. 构造 API 请求参数 (与上传代码一致: client=html5, tai=ipad, 无 vc)
  const tsp = String(Math.floor(Date.now() / 1000));
  const vn = '2049';
  const uid = '826D8646DEBBFD97A82D23CAE45A55BE';

  const params = new URLSearchParams({
    pid: videoId,
    client: 'html5',
    tai: 'ipad',
    tsp: tsp,
    vn: vn,
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

  // 合并页面元数据
  const meta = {
    publishTime: pageInfo.publishTime,
    author: pageInfo.author,
    summary: pageInfo.summary,
    videoLength: pageInfo.videoLength,
    templateType: pageInfo.templateType
  };

  onProgress({ stage: 'resolve', message: '正在解析下载地址...' });

  // 4. 提取下载地址 (保留原始 URL, 不再直接解析 m3u8)
  const manifest = videoData.manifest || {};
  const h5eUrl = videoData['hls_h5e_url'] || manifest.hls_h5e_url || null;
  const hlsUrl = videoData.hls_url || null;
  const isEncrypted = !!h5eUrl;
  const downloadUrl = h5eUrl || hlsUrl;

  if (!downloadUrl) {
    // 尝试直接使用 mp4 地址
    if (videoData.video && videoData.video.chapters) {
      const chapters = videoData.video.chapters;
      if (chapters.length > 0 && chapters[0].url) {
        return {
          videoId,
          vid: pageInfo.vid,
          title: sanitizeFilename(videoData.title || 'cctv_video'),
          downloadUrl: chapters[0].url,
          rawDownloadUrl: chapters[0].url,
          hlsKey: null,
          isEncrypted: false,
          coverUrl: videoData.image || '',
          duration: videoData.video?.totalLength || '',
          source: 'CCTV',
          playChannel: videoData.play_channel || '',
          publishTime: meta.publishTime,
          author: meta.author,
          summary: meta.summary,
          videoLength: meta.videoLength,
          validChapterNum: videoData.video?.validChapterNum || 0,
          templateType: meta.templateType,
          rawApiData: videoData,
          qualityList: []
        };
      }
    }
    throw new Error('未找到可用的视频下载地址');
  }

  // 5. 构建清晰度列表
  const qualityList = buildQualityList(videoData, meta.templateType);

  const title = sanitizeFilename(videoData.title || pageInfo.title || 'cctv_video');

  return {
    videoId,
    vid: pageInfo.vid,
    title,
    downloadUrl,
    rawDownloadUrl: downloadUrl,
    hlsKey: isEncrypted ? 'hls_h5e_url' : 'hls_url',
    isEncrypted,
    coverUrl: videoData.image || '',
    duration: videoData.video?.totalLength || meta.videoLength || '',
    source: 'CCTV',
    playChannel: videoData.play_channel || '',
    publishTime: meta.publishTime,
    author: meta.author,
    summary: meta.summary,
    videoLength: meta.videoLength,
    validChapterNum: videoData.video?.validChapterNum || 0,
    templateType: meta.templateType,
    rawApiData: videoData,
    qualityList
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

/**
 * 从 h5e/hls URL 中提取 GUID
 */
function extractGuidFromUrl(url) {
  try {
    const u = new URL(url);
    const parts = u.pathname.split('/');
    return parts[10] || parts[parts.length - 2] || '';
  } catch (e) {
    return '';
  }
}

/**
 * 根据 API 数据构建清晰度列表 (按频道区分)
 */
function buildQualityList(apiData, templateType) {
  const qualities = [];
  const h5eUrl = apiData.manifest?.hls_h5e_url || null;
  const hlsUrl = apiData.hls_url || null;
  const playChannel = apiData.play_channel || '';
  const brtnum = apiData.video?.validChapterNum || 0;
  const brt = [450, 850, 1200, 2000, 4000, 3000];

  if (!h5eUrl && !hlsUrl) return qualities;

  if (playChannel.indexOf('CCTV-4K') === 0) {
    if (h5eUrl) {
      for (const br of [brt[3], brt[4]]) {
        qualities.push({ name: `h5e-${br}k`, url: h5eUrl.replaceAll('main', br), type: 'hls', bitrate: br, source: 'bitrate-select', guid: extractGuidFromUrl(h5eUrl) });
      }
    }
    if (hlsUrl) {
      const br = brt[4];
      qualities.push({ name: `hls-${br}k`, url: hlsUrl.replaceAll('main', br), type: 'hls', bitrate: br, source: 'bitrate-unenc' });
    }
  } else if (playChannel.indexOf('CCTV-16') === 0) {
    if (h5eUrl) {
      for (const br of [brt[3], brt[5]]) {
        qualities.push({ name: `h5e-${br}k`, url: h5eUrl.replaceAll('main', br), type: 'hls', bitrate: br, source: 'bitrate-select', guid: extractGuidFromUrl(h5eUrl) });
      }
    }
    if (hlsUrl) {
      const br = brt[5];
      qualities.push({ name: `hls-${br}k`, url: hlsUrl.replaceAll('main', br), type: 'hls', bitrate: br, source: 'bitrate-unenc' });
    }
  } else {
    let selectedBitrates = [];
    let unencBrList = [];
    if (brtnum > 3) {
      selectedBitrates = [brt[3], brt[2], brt[1]];
      const tplType = Number(templateType) || 0;
      unencBrList = tplType === 2 ? [brt[3]] : [brt[1]];
    } else if (brtnum === 1) {
      selectedBitrates = [brt[0]]; unencBrList = [brt[0]];
    } else if (brtnum === 2) {
      selectedBitrates = [brt[1]]; unencBrList = [brt[1]];
    } else if (brtnum > 0) {
      selectedBitrates = [brt[2]]; unencBrList = [brt[2]];
    } else {
      selectedBitrates = [brt[0]]; unencBrList = [brt[0]];
    }
    if (h5eUrl) {
      for (const br of selectedBitrates) {
        qualities.push({ name: `h5e-${br}k`, url: h5eUrl.replaceAll('main', br), type: 'hls', bitrate: br, source: 'bitrate-select', guid: extractGuidFromUrl(h5eUrl) });
      }
    }
    if (hlsUrl) {
      for (const br of unencBrList) {
        qualities.push({ name: `hls-${br}k`, url: hlsUrl.replaceAll('main', br), type: 'hls', bitrate: br, source: 'bitrate-unenc' });
      }
    }
  }

  return qualities;
}

/**
 * 下载二进制内容 (返回 Buffer)
 */
function fetchBinary(url) {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(url);
    const isHttps = parsedUrl.protocol === 'https:';
    const mod = isHttps ? https : http;
    const req = mod.get({
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (isHttps ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: 'GET',
      headers: {
        'User-Agent': USER_AGENT,
        'Accept': '*/*',
        'Referer': 'https://tv.cctv.com/'
      },
      timeout: 30000
    }, (res) => {
      if ([301, 302, 303, 307].includes(res.statusCode) && res.headers.location) {
        return fetchBinary(res.headers.location).then(resolve).catch(reject);
      }
      if (res.statusCode === 403 && url.startsWith('https:')) {
        return fetchBinary(url.replace('https:', 'http:')).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode}`));
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve(Buffer.concat(chunks)));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('下载超时')); });
  });
}

module.exports = {
  parseCCTVVideo,
  isCCTVUrl,
  extractGuidFromPage,
  buildQualityList,
  extractGuidFromUrl,
  fetchBinary,
  httpGet,
  sanitizeFilename
};
