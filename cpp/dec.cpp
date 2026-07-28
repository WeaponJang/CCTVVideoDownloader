// =============================================================================
// cctv_h5e_decrypt.cpp
// 纯 C++ 实现的 CCTV hls_h5e (new-mode) MPEG-TS 解密工具
// =============================================================================
//
// 功能:
//   - 闭合公式计算 type5 步长 F5 和 type1 步长 F1（无查找表）
//   - Type1 G 变换，支持多头部翻转掩码（01a8xx / 61exxx）
//   - TEA-16 用于 type5；type25 之前使用 classic 模式回退
//   - EPB (00 00 03) 网格对齐 + 03 丢弃（与官方 worker 一致）
//   - MPEG-TS PES 重建，自适应字段填充以处理长度缩减
//
// 无 WASM、无 VMP 字节码、无网络请求。
//
// 编译:
//   c++ -std=c++17 -O2 -o h5e_decrypt cctv_h5e_decrypt.cpp
//
// 逆向研究文档，风险自担。
// =============================================================================

#ifdef _WIN32
#include <windows.h>
#endif

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <utility>
#include <tuple>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <fstream>
#include <iostream>

namespace cctv_h5e {

// ===== TEA / classic / type5 (EPB 感知) =====
// 标准 TEA-16，小端序 32 位字，delta = 0x9E3779B9。

inline void tea_encrypt_block(uint8_t out[8], const uint8_t in[8], const uint8_t key[16]) {
    uint32_t v0, v1, k0, k1, k2, k3;
    std::memcpy(&v0, in, 4);
    std::memcpy(&v1, in + 4, 4);
    std::memcpy(&k0, key, 4);
    std::memcpy(&k1, key + 4, 4);
    std::memcpy(&k2, key + 8, 4);
    std::memcpy(&k3, key + 12, 4);
    uint32_t sum = 0;
    const uint32_t delta = 0x9E3779B9u;
    for (int i = 0; i < 16; i++) {
        sum += delta;
        v0 += (((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1));
        v1 += (((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3));
    }
    std::memcpy(out, &v0, 4);
    std::memcpy(out + 4, &v1, 4);
}

inline void tea_decrypt_block(uint8_t out[8], const uint8_t in[8], const uint8_t key[16]) {
    uint32_t v0, v1, k0, k1, k2, k3;
    std::memcpy(&v0, in, 4);
    std::memcpy(&v1, in + 4, 4);
    std::memcpy(&k0, key, 4);
    std::memcpy(&k1, key + 4, 4);
    std::memcpy(&k2, key + 8, 4);
    std::memcpy(&k3, key + 12, 4);
    const uint32_t delta = 0x9E3779B9u;
    uint32_t sum = delta * 16u;
    for (int i = 0; i < 16; i++) {
        v1 -= (((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3));
        v0 -= (((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1));
        sum -= delta;
    }
    std::memcpy(out, &v0, 4);
    std::memcpy(out + 4, &v1, 4);
}

// 经典布局（无 type25）：密钥@16, 起始=32, 步长=80。
inline void decrypt_classic(uint8_t* nal, size_t len) {
    if (len < 40) return;
    const uint8_t* key = nal + 16;
    for (size_t j = 0; 32 + j * 80 + 8 <= len; j++) {
        size_t o = 32 + j * 80;
        tea_decrypt_block(nal + o, nal + o, key);
    }
}

// Type5 新模式：密钥@5, 起始=64, 步长 S, EPB 感知（与 type1 相同）。
// Worker 网格守卫需要逻辑单元起始处有 16 字节；TEA 仅写入 8 字节。
// 返回可选 EPB 03 丢弃后的新 NAL 长度。
inline size_t decrypt_type5_new(uint8_t* nal, size_t len, uint32_t stride) {
    if (!nal || len < 21 || stride < 8) return len;
    const uint8_t* key = nal + 5;
    std::vector<size_t> epbs;
    for (size_t i = 0; i + 2 < len; i++) {
        if (nal[i] == 0 && nal[i + 1] == 0 && nal[i + 2] == 3) epbs.push_back(i);
    }
    for (size_t k = 0;; k++) {
        size_t o = 64 + k * (size_t)stride;
        if (o + 16 > len) break;
        size_t adj = 0;
        for (size_t e : epbs) {
            if (e < o) adj++;
            else break;
        }
        size_t oo = o + adj;
        if (oo + 8 > len) break;
        tea_decrypt_block(nal + oo, nal + oo, key);
    }
    if (epbs.empty()) return len;
    size_t nlen = len;
    for (auto it = epbs.rbegin(); it != epbs.rend(); ++it) {
        size_t e = *it;
        if (e + 2 < nlen && nal[e] == 0 && nal[e + 1] == 0 && nal[e + 2] == 3) {
            std::memmove(nal + e + 2, nal + e + 3, nlen - (e + 3));
            nlen--;
        }
    }
    return nlen;
}

inline bool is_type25_enable(const uint8_t* nal, size_t len) {
    return len >= 4 && (nal[0] & 0x1f) == 25 && nal[2] == 0x01 && nal[3] == 0x09;
}

// ===== F5 / F1 步长计算 =====
inline constexpr uint16_t kType5F5Base[6] = {160, 192, 224, 256, 288, 320};

// key16: nal+5 处的 16 字节 TEA 密钥（F5 仅使用前 6 字节）。
inline uint32_t type5_stride_f5(const uint8_t* key16) {
    uint32_t le = (uint32_t)key16[0]
                | ((uint32_t)key16[1] << 8)
                | ((uint32_t)key16[2] << 16)
                | ((uint32_t)key16[3] << 24);
    unsigned idx = (unsigned)(le % 6u);
    return (uint32_t)kType5F5Base[idx] | (uint32_t)key16[idx];
}

// 便捷函数：带 header+RBSP 的 NAL，需要 len >= 11（前缀 >= 21）。
inline uint32_t type5_stride_from_nal(const uint8_t* nal, size_t len) {
    if (!nal || len < 11) return 0;
    uint8_t key[6];
    // key[0..3]=nal[5..8], key[4]=nal[9], key[5]=nal[10]
    key[0] = nal[5];
    key[1] = nal[6];
    key[2] = nal[7];
    key[3] = nal[8];
    key[4] = (len > 9) ? nal[9] : 0;
    key[5] = (len > 10) ? nal[10] : 0;
    return type5_stride_f5(key);
}

// Type1 F1：与 F5 相同的 BASE/选择逻辑，key = nal[1:7]。
inline uint32_t type1_stride_f1(const uint8_t* nal, size_t len) {
    if (!nal || len < 7) return 0;
    return type5_stride_f5(nal + 1);
}

// ===== Type1 G + EPB 辅助函数 =====
inline int type1_fbit(uint32_t W) {
    const int w0  = (W >> 0)  & 1;
    const int w8  = (W >> 8)  & 1;
    const int w15 = (W >> 15) & 1;
    const int w19 = (W >> 19) & 1;
    const int w25 = (W >> 25) & 1;
    const int w30 = (W >> 30) & 1;
    const int w31 = (W >> 31) & 1;
    const int t = w0 | w8;
    return (w31 ^ w15 ^ t
            ^ (w8 & w19)
            ^ (w25 & (w0 ^ w19))
            ^ (w0 & (1 ^ w8) & w30)
            ^ ((1 ^ w0) & w19 & w30)
            ^ (w25 & w30 & (w8 ^ w19))) & 1;
}

inline bool type1_is_B_step(int s) {
    return s == 2 || s == 8 || s == 9 || s == 10;
}

// 根据 NAL 头部确定需要翻转的步长掩码。
inline uint16_t type1_flip_mask_from_header(const uint8_t hdr[3]) {
    const uint8_t b0 = hdr[0], b1 = hdr[1], b2 = hdr[2];
    uint16_t m = 0;
    auto setb = [&](int s) { m = (uint16_t)(m | (uint16_t)(1u << s)); };
    if (b0 == 0x01 && b1 == 0xA8) {
        if ((b2 >> 7) & 1) setb(0);
        if ((b2 >> 6) & 1) setb(1);
        if (1 ^ ((b2 >> 5) & 1)) setb(2);
        if ((b2 >> 4) & 1) setb(3);
        if ((b2 >> 3) & 1) setb(4);
        if ((b2 >> 1) & 1) setb(6);
        if ((b2 >> 0) & 1) setb(7);
        setb(9);
        setb(12);
        return m;
    }
    if (b0 == 0x61) {
        if ((b2 >> 1) & 1) setb(0);
        if ((b2 >> 0) & 1) setb(1);
        if (1 ^ ((b2 >> 5) & 1)) setb(2);
        if ((b2 >> 3) & 1) setb(4);
        if ((b2 >> 2) & 1) setb(5);
        if ((b2 >> 1) & 1) setb(6);
        if ((b2 >> 0) & 1) setb(7);
        if ((b2 >> 3) & 1) setb(14);
        if ((b2 >> 2) & 1) setb(15);
        return m;
    }
    // 切片头部族：nal_type=1 且 b1 高半字节为 0x9
    // （41 9a/9b, 01 9e/9f, … — 垂直/移动 h5e）。
    if ((b0 & 0x1f) == 1 && (b1 & 0xf0) == 0x90) {
        if ((b2 >> 7) & 1) setb(0);
        if ((b2 >> 6) & 1) setb(1);
        if (((b0 >> 0) & 1) ^ ((b2 >> 5) & 1)) setb(2);
        if ((b2 >> 4) & 1) setb(3);
        if ((b2 >> 3) & 1) setb(4);
        if ((b2 >> 2) & 1) setb(5);
        if (((b0 >> 0) & 1) ^ ((b0 >> 6) & 1)) setb(7);
        if ((b0 >> 0) & 1) {
            setb(9); setb(10); setb(11); setb(12); setb(14);
        }
        if (((b0 >> 0) & 1) ^ ((b0 >> 6) & 1)) setb(13);
        if ((b1 >> 0) & 1) setb(15);
        return m;
    }
    // 未知族：无翻转（与 61e020 仅核心一致）。
    return 0;
}

inline uint16_t type1_G_flips(uint16_t X, uint16_t Y, uint16_t flip_mask) {
    uint32_t W = (uint32_t)X | ((uint32_t)Y << 16);
    uint16_t P1 = 0;
    for (int s = 0; s < 16; s++) {
        int fv = type1_fbit(W) ^ ((flip_mask >> s) & 1);
        int b = fv ^ (type1_is_B_step(s) ? 1 : 0);
        P1 = (uint16_t)(P1 | (b << (15 - s)));
        W = ((W << 1) | (uint32_t)b) & 0xFFFFFFFFu;
    }
    return P1;
}

inline uint16_t type1_G(uint16_t X, uint16_t Y) {
    // 头部 61e020 / 空翻转集。
    return type1_G_flips(X, Y, 0);
}

inline uint16_t type1_G_nal(uint16_t X, uint16_t Y, const uint8_t nal_hdr[3]) {
    return type1_G_flips(X, Y, type1_flip_mask_from_header(nal_hdr));
}

inline void type1_decrypt_block(uint8_t blk[4]) {
    const uint16_t X = (uint16_t)(blk[0] | (blk[1] << 8));
    const uint16_t Y = (uint16_t)(blk[2] | (blk[3] << 8));
    const uint16_t P1 = type1_G(X, Y);
    blk[0] = (uint8_t)(P1 & 0xFF);
    blk[1] = (uint8_t)((P1 >> 8) & 0xFF);
    blk[2] = (uint8_t)(X & 0xFF);
    blk[3] = (uint8_t)((X >> 8) & 0xFF);
}

inline void type1_decrypt_block_nal(uint8_t blk[4], const uint8_t nal_hdr[3]) {
    const uint16_t X = (uint16_t)(blk[0] | (blk[1] << 8));
    const uint16_t Y = (uint16_t)(blk[2] | (blk[3] << 8));
    const uint16_t P1 = type1_G_nal(X, Y, nal_hdr);
    blk[0] = (uint8_t)(P1 & 0xFF);
    blk[1] = (uint8_t)((P1 >> 8) & 0xFF);
    blk[2] = (uint8_t)(X & 0xFF);
    blk[3] = (uint8_t)((X >> 8) & 0xFF);
}

// 收集 EPB 位置（00 00 03 的起始位置）。
inline void collect_epb_positions(const uint8_t* nal, size_t len,
                                  std::vector<size_t>& epbs) {
    epbs.clear();
    if (!nal || len < 3) return;
    for (size_t i = 0; i + 2 < len; i++) {
        if (nal[i] == 0 && nal[i + 1] == 0 && nal[i + 2] == 3) epbs.push_back(i);
    }
}

// 丢弃每个仍存在的 EPB 的 0x03（从末尾开始）。返回新长度。
inline size_t drop_epb_03(uint8_t* nal, size_t len, const std::vector<size_t>& epbs) {
    if (!nal) return len;
    size_t nlen = len;
    for (auto it = epbs.rbegin(); it != epbs.rend(); ++it) {
        size_t e = *it;
        if (e + 2 < nlen && nal[e] == 0 && nal[e + 1] == 0 && nal[e + 2] == 3) {
            std::memmove(nal + e + 2, nal + e + 3, nlen - (e + 3));
            nlen--;
        }
    }
    return nlen;
}

// 网格守卫：即使在 RBSP 单元起始处需要 ``guard`` 字节剩余（默认 17），
// 也仅重写 4 字节。通过 RBSP→EBSP 映射获取单元字节（跳过 EPB 0x03）；
// 然后丢弃仍完整的 0x03。返回新 NAL 长度。
inline size_t decrypt_type1_new(uint8_t* nal, size_t len, uint32_t stride = 511,
                                size_t start = 64, size_t guard = 17) {
    if (!nal || stride < 4 || len < 3) return len;
    const uint8_t hdr[3] = {nal[0], nal[1], nal[2]};
    std::vector<size_t> epbs;
    collect_epb_positions(nal, len, epbs);
    std::vector<size_t> r2e;
    r2e.reserve(len);
    for (size_t i = 0; i < len; ) {
        if (i + 2 < len && nal[i] == 0 && nal[i + 1] == 0 && nal[i + 2] == 3) {
            r2e.push_back(i);
            r2e.push_back(i + 1);
            i += 3;
        } else {
            r2e.push_back(i);
            i++;
        }
    }
    const size_t rbsp_len = r2e.size();
    for (size_t k = 0;; k++) {
        size_t o = start + k * (size_t)stride;
        if (o + guard > rbsp_len || o + 4 > rbsp_len) break;
        uint8_t blk[4] = {nal[r2e[o]], nal[r2e[o + 1]], nal[r2e[o + 2]],
                          nal[r2e[o + 3]]};
        type1_decrypt_block_nal(blk, hdr);
        nal[r2e[o]] = blk[0];
        nal[r2e[o + 1]] = blk[1];
        nal[r2e[o + 2]] = blk[2];
        nal[r2e[o + 3]] = blk[3];
    }
    if (epbs.empty()) return len;
    return drop_epb_03(nal, len, epbs);
}

// ===== 会话管理 =====

// 会话：type25 启用新模式；步长 F5/F1 仅使用闭合公式。
struct Session {
    bool new_mode = false;
    size_t type1_start = 64;
    size_t type1_guard = 17;
    // Worker 对短于此长度的 type1 NAL 不做处理（无网格，无 EPB 丢弃）。
    size_t type1_min_len = 129;

    uint32_t resolve_type5_stride(const uint8_t* nal, size_t len) const {
        return type5_stride_from_nal(nal, len);
    }
    uint32_t resolve_type1_stride(const uint8_t* nal, size_t len) const {
        uint32_t s = type1_stride_f1(nal, len);
        return s ? s : 511u;
    }

    void on_nal(uint8_t* nal, size_t* io_len) {
        if (!nal || !io_len || *io_len < 1) return;
        size_t len = *io_len;
        const int ntype = nal[0] & 0x1f;
        if (ntype == 25) {
            if (is_type25_enable(nal, len)) new_mode = true;
            return;
        }
        if (!new_mode) {
            if (ntype == 1 || ntype == 5) decrypt_classic(nal, len);
            return;
        }
        if (ntype == 5) {
            uint32_t S = resolve_type5_stride(nal, len);
            if (S >= 8) *io_len = decrypt_type5_new(nal, len, S);
            return;
        }
        if (ntype == 1) {
            if (len < type1_min_len) return;
            uint32_t S = resolve_type1_stride(nal, len);
            *io_len = decrypt_type1_new(nal, len, S, type1_start, type1_guard);
        }
    }
    void on_nal(uint8_t* nal, size_t len) {
        size_t n = len;
        on_nal(nal, &n);
    }
    void reset() { new_mode = false; }
};

// ===== MPEG-TS =====
// 展开一个 TS 包的 AF 填充；返回从载荷中偷取的字节数。
inline size_t expand_af_steal(uint8_t* data, size_t len, size_t pkt_off, size_t need) {
    if (!data || need == 0 || pkt_off + 188 > len) return 0;
    int afc = (data[pkt_off + 3] & 0x30) >> 4;
    if (afc == 1) {
        // 仅载荷 → 引入 AF。af_len = need - 1。
        if (need < 1) return 0;
        size_t af_len = need - 1;
        if (af_len > 182) af_len = 182;
        size_t steal = 1 + af_len;
        uint8_t old_payload[184];
        std::memcpy(old_payload, data + pkt_off + 4, 184);
        data[pkt_off + 3] = (uint8_t)((data[pkt_off + 3] & 0xCF) | 0x30);  // afc=3
        data[pkt_off + 4] = (uint8_t)af_len;
        if (af_len > 0) {
            data[pkt_off + 5] = 0x00;  // 标志位
            for (size_t i = 1; i < af_len; i++) data[pkt_off + 5 + i] = 0xFF;
        }
        size_t new_pl = 184 - steal;
        std::memcpy(data + pkt_off + 5 + af_len, old_payload, new_pl);
        return steal;
    }
    if (afc == 2 || afc == 3) {
        size_t af_len = data[pkt_off + 4];
        size_t pi = 5 + af_len;
        if (pi >= 188) return 0;
        size_t old_payload_len = 188 - pi;
        size_t add = need < old_payload_len ? need : old_payload_len;
        if (add == 0) return 0;
        if (af_len + add > 182) {
            add = 182 - af_len;
            if (add == 0) return 0;
        }
        size_t new_af_len = af_len + add;
        uint8_t old_payload[184];
        std::memcpy(old_payload, data + pkt_off + pi, old_payload_len);
        // 用 0xFF 扩展 AF 体
        for (size_t i = 0; i < add; i++) data[pkt_off + 5 + af_len + i] = 0xFF;
        data[pkt_off + 4] = (uint8_t)new_af_len;
        size_t new_pl = old_payload_len - add;
        std::memcpy(data + pkt_off + 5 + new_af_len, old_payload, new_pl);
        if (new_pl == 0)
            data[pkt_off + 3] = (uint8_t)((data[pkt_off + 3] & 0xCF) | 0x20);  // afc=2
        else
            data[pkt_off + 3] = (uint8_t)((data[pkt_off + 3] & 0xCF) | 0x30);  // afc=3
        return add;
    }
    return 0;
}

// 就地解密 TS 缓冲区中的所有视频 NAL。
// 返回通过 session.on_nal 处理的 NAL 数量。
inline size_t decrypt_ts_inplace(uint8_t* data, size_t len, Session& session,
                                 uint16_t vpid = 0x100) {
    if (!data || len < 188) return 0;

    std::vector<uint8_t> pes;
    std::vector<std::tuple<size_t, size_t, size_t>> spans;
    size_t nal_count = 0;

    auto flush = [&]() {
        if (pes.empty()) return;

        size_t base_skip = 0;
        if (pes.size() >= 9 && pes[0] == 0 && pes[1] == 0 && pes[2] == 1) {
            base_skip = 9 + pes[8];
        }
        if (base_skip > pes.size()) {
            pes.clear();
            spans.clear();
            return;
        }

        std::vector<uint8_t> pes_hdr(pes.begin(), pes.begin() + (std::ptrdiff_t)base_skip);
        std::vector<uint8_t> es(pes.begin() + (std::ptrdiff_t)base_skip, pes.end());

        // 在 ES 中查找 NAL 起始码
        std::vector<std::pair<size_t, size_t>> starts;  // (位置, 起始码长度)
        size_t i = 0;
        while (i + 3 < es.size()) {
            if (i + 4 <= es.size() && es[i] == 0 && es[i + 1] == 0 && es[i + 2] == 0 &&
                es[i + 3] == 1) {
                starts.emplace_back(i, 4);
                i += 4;
            } else if (es[i] == 0 && es[i + 1] == 0 && es[i + 2] == 1) {
                starts.emplace_back(i, 3);
                i += 3;
            } else {
                i++;
            }
        }

        std::vector<uint8_t> new_es;
        new_es.reserve(es.size());
        size_t cursor = 0;
        for (size_t idx = 0; idx < starts.size(); idx++) {
            size_t pos = starts[idx].first;
            size_t sc = starts[idx].second;
            size_t end = (idx + 1 < starts.size()) ? starts[idx + 1].first : es.size();
            if (cursor < pos) new_es.insert(new_es.end(), es.begin() + (std::ptrdiff_t)cursor,
                                            es.begin() + (std::ptrdiff_t)pos);
            new_es.insert(new_es.end(), es.begin() + (std::ptrdiff_t)pos,
                          es.begin() + (std::ptrdiff_t)(pos + sc));
            if (pos + sc >= end) {
                cursor = end;
                continue;
            }
            std::vector<uint8_t> nal(es.begin() + (std::ptrdiff_t)(pos + sc),
                                     es.begin() + (std::ptrdiff_t)end);
            size_t nlen = nal.size();
            session.on_nal(nal.data(), &nlen);
            nal_count++;
            new_es.insert(new_es.end(), nal.begin(), nal.begin() + (std::ptrdiff_t)nlen);
            cursor = end;
        }
        if (cursor < es.size())
            new_es.insert(new_es.end(), es.begin() + (std::ptrdiff_t)cursor, es.end());

        std::vector<uint8_t> new_pes = pes_hdr;
        new_pes.insert(new_pes.end(), new_es.begin(), new_es.end());

        size_t capacity = 0;
        for (auto& sp : spans) capacity += std::get<2>(sp);
        if (capacity > new_pes.size()) {
            size_t remaining = capacity - new_pes.size();
            for (auto it = spans.rbegin(); it != spans.rend() && remaining > 0; ++it) {
                size_t pkt_off = std::get<0>(*it);
                size_t got = expand_af_steal(data, len, pkt_off, remaining);
                remaining -= got;
            }
            // AF 变更后重新计算 spans
            std::vector<std::tuple<size_t, size_t, size_t>> new_spans;
            for (auto& sp : spans) {
                size_t pkt_off = std::get<0>(sp);
                int afc = (data[pkt_off + 3] & 0x30) >> 4;
                if (afc == 0 || afc == 2) continue;
                size_t pi = (afc == 1) ? 4 : (size_t)(5 + data[pkt_off + 4]);
                if (pi >= 188) continue;
                new_spans.emplace_back(pkt_off, pi, 188 - pi);
            }
            spans.swap(new_spans);
        }

        size_t off = 0;
        for (auto& sp : spans) {
            size_t pkt_off = std::get<0>(sp);
            size_t pi = std::get<1>(sp);
            size_t pl = std::get<2>(sp);
            size_t chunk = new_pes.size() - off;
            if (chunk > pl) chunk = pl;
            if (chunk > 0)
                std::memcpy(data + pkt_off + pi, new_pes.data() + off, chunk);
            if (chunk < pl) {
                // 残余（如果 AF 吸收成功则很少出现）
                std::memset(data + pkt_off + pi + chunk, 0xFF, pl - chunk);
            }
            off += pl;
        }

        pes.clear();
        spans.clear();
    };

    for (size_t off = 0; off + 188 <= len; off += 188) {
        if (data[off] != 0x47) continue;
        uint16_t pid =
            (uint16_t)(((data[off + 1] & 0x1f) << 8) | data[off + 2]);
        if (pid != vpid) continue;
        bool pusi = (data[off + 1] & 0x40) != 0;
        int afc = (data[off + 3] & 0x30) >> 4;
        if (afc == 0 || afc == 2) continue;
        size_t pi = (afc == 1) ? 4 : (size_t)(5 + data[off + 4]);
        if (pi >= 188) continue;
        size_t payload_len = 188 - pi;
        if (pusi) flush();
        pes.insert(pes.end(), data + off + pi, data + off + 188);
        spans.emplace_back(off, pi, payload_len);
    }
    flush();
    return nal_count;
}

// 拷贝方式解密：返回明文 TS。
inline std::vector<uint8_t> decrypt_ts(const uint8_t* data, size_t len,
                                       Session& session,
                                       uint16_t vpid = 0x100) {
    std::vector<uint8_t> out(data, data + len);
    decrypt_ts_inplace(out.data(), out.size(), session, vpid);
    return out;
}

// 便捷函数：使用默认会话（内嵌表 key05 + head12）解密。
inline std::vector<uint8_t> decrypt_ts_default(const uint8_t* data, size_t len,
                                               uint16_t vpid = 0x100) {
    Session session;
    return decrypt_ts(data, len, session, vpid);
}

}  // namespace cctv_h5e

// ===== CLI 入口 =====

static std::vector<uint8_t> h5e_read_all(const char* path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    f.seekg(0, std::ios::end);
    std::streamoff n = f.tellg();
    f.seekg(0);
    if (n <= 0) return {};
    std::vector<uint8_t> b((size_t)n);
    f.read(reinterpret_cast<char*>(b.data()), n);
    return b;
}

int main(int argc, char** argv) {
    // Windows 下自动设置控制台代码页为 UTF-8
#ifdef _WIN32
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
#endif

    if (argc < 3) {
        std::fprintf(stderr,
            "cctv_h5e_decrypt — 纯 C++ hls_h5e TS 解密工具\n"
            "  版本: cctv_h5e pure F5/F1+EPB+AF 1.0 (2026-07-23)\n"
            "\n"
            "用法: %s <加密.ts> <输出.ts> [--pid 0x100]\n"
            "\n"
            "参数:\n"
            "  <加密.ts>   输入的加密 TS 文件路径\n"
            "  <输出.ts>   解密后的输出 TS 文件路径\n"
            "  --pid       视频 PID（默认 0x100）\n",
            argv[0]);
        return 1;
    }

    uint16_t vpid = 0x100;
    for (int i = 3; i < argc; i++) {
        if (std::string(argv[i]) == "--pid" && i + 1 < argc)
            vpid = (uint16_t)std::strtoul(argv[++i], nullptr, 0);
    }

    auto enc = h5e_read_all(argv[1]);
    if (enc.empty()) {
        std::fprintf(stderr, "错误: 无法读取文件 %s\n", argv[1]);
        return 1;
    }

    auto out = cctv_h5e::decrypt_ts_default(enc.data(), enc.size(), vpid);
    if (out.empty()) {
        std::fprintf(stderr, "错误: 解密失败，输出为空\n");
        return 1;
    }

    std::ofstream of(argv[2], std::ios::binary);
    if (!of) {
        std::fprintf(stderr, "错误: 无法写入文件 %s\n", argv[2]);
        return 1;
    }
    of.write(reinterpret_cast<char*>(out.data()), (std::streamsize)out.size());

    std::fprintf(stderr, "完成: %zu 字节 -> %s\n", out.size(), argv[2]);
    return 0;
}