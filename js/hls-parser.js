/**
 * HLS Manifest 解析器
 * 从 m3u8 master playlist 中选择最高画质的流
 */

class HLSParser {
  constructor(masterUrl) {
    this.masterUrl = masterUrl || '';
  }

  /**
   * 解析 m3u8 master playlist 文本，返回最佳画质的条目
   */
  best(masterText) {
    const lines = masterText.split(/\r?\n/).map(l => l.trim()).filter(l => l);
    const variants = [];
    const kvRegex = /([A-Z0-9\-]+)=(".*?"|[^,]*)/g;

    let i = 0;
    while (i < lines.length) {
      if (!lines[i].startsWith('#EXT-X-STREAM-INF:')) {
        i++;
        continue;
      }
      const attrStr = lines[i].split(':', 2)[1];
      const attrs = {};
      let match;
      kvRegex.lastIndex = 0;
      while ((match = kvRegex.exec(attrStr)) !== null) {
        let val = match[2];
        if (val.startsWith('"') && val.endsWith('"')) val = val.slice(1, -1);
        attrs[match[1]] = val.trim();
      }

      // 找到下一行非注释行作为 URI
      let uriIdx = i + 1;
      while (uriIdx < lines.length && (lines[uriIdx].startsWith('#') || !lines[uriIdx])) uriIdx++;
      if (uriIdx >= lines.length) break;

      let uri = lines[uriIdx];
      // 相对路径转绝对路径
      if (this.masterUrl && !uri.startsWith('http')) {
        try {
          uri = new URL(uri, this.masterUrl).href;
        } catch (e) {
          // fallback: 拼接
          uri = this.masterUrl.replace(/\/[^\/]*$/, '/') + uri;
        }
      }

      const bandwidth = parseInt(attrs.BANDWIDTH || '0', 10) || 0;
      const res = (attrs.RESOLUTION || '').toLowerCase();
      let width = 0, height = 0;
      if (res.includes('x')) {
        const parts = res.split('x');
        width = parseInt(parts[0], 10) || 0;
        height = parseInt(parts[1], 10) || 0;
      }

      variants.push({
        uri,
        bandwidth,
        resolution: [width, height],
        attrs,
        score: [width * height, bandwidth]
      });

      i = uriIdx + 1;
    }

    if (!variants.length) {
      throw new Error('No HLS variants found in manifest');
    }

    // 按 score 排序取最高
    variants.sort((a, b) => {
      if (b.score[0] !== a.score[0]) return b.score[0] - a.score[0];
      return b.score[1] - a.score[1];
    });

    return variants[0];
  }
}

if (typeof module !== 'undefined') module.exports = HLSParser;
