// =============================================================================
// cctv_h5e_decrypt.c
// 纯 C11 解密 CCTV hls_h5e (新版模式) MPEG-TS 的实现
// =============================================================================
//
// 特性:
// - 闭合形式 type5 步长 F5 和 type1 步长 F1 (无需查表)
// - 带多头部翻转掩码 (01a8xx / 61exxx) 的 Type1 G 变换
// - type5 使用 TEA-16; type25 之前回退到经典模式
// - EPB (00 00 03) 网格对齐 + 03 丢弃 (匹配官方 worker 行为)
// - 使用 adaptation-field 填充进行 MPEG-TS PES 重建以缩减长度
//
// 无 WASM, 无 VMP 字节码, 无网络操作.
//
// C 用法:
//   #include "cctv_h5e_decrypt.c"
//   size_t out_len;
//   uint8_t* out = cctv_h5e_decrypt_ts_default(data, len, 0x100, &out_len);
//   cctv_h5e_free(out);
//
// CLI (单翻译单元编译):
//   gcc -std=c11 -Os -s -o dec dec.c
//
// 仅供研究与逆向工程记录。使用风险自负。
// =============================================================================

#define CCTV_H5E_CLI
#define CCTV_H5E_IMPLEMENTATION
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

// 通用动态数组追加辅助函数 (模拟 std::vector::push_back)
static void mem_push(void** buf, size_t* size, size_t* cap, size_t elem_size, const void* data, size_t count) {
    if (*size + count > *cap) {
        while (*size + count > *cap) {
            *cap = *cap ? (*cap * 2) : 16;
        }
        void* new_buf = realloc(*buf, *cap * elem_size);
        if (!new_buf) {
            // 在实际的工具代码中，简单处理内存分配失败
            perror("Memory allocation failed");
            exit(EXIT_FAILURE);
        }
        *buf = new_buf;
    }
    memcpy((char*)*buf + (*size * elem_size), data, count * elem_size);
    *size += count;
}

// 翻转位设置辅助宏
#define SETB(m, s) ((m) |= (uint16_t)(1u << (s)))

// ===== TEA / 经典模式 / type5 (感知 EPB) =====

// 标准 TEA-16, 小端序 32位字, delta = 0x9E3779B9.
// 匹配 src/cctv_h5e_pure.py 中的 tea_encrypt_block / tea_decrypt_block.
static inline void tea_encrypt_block(uint8_t out[8], const uint8_t in[8], const uint8_t key[16]) {
    uint32_t v0, v1, k0, k1, k2, k3;
    memcpy(&v0, in, 4);
    memcpy(&v1, in + 4, 4);
    memcpy(&k0, key, 4);
    memcpy(&k1, key + 4, 4);
    memcpy(&k2, key + 8, 4);
    memcpy(&k3, key + 12, 4);
    uint32_t sum = 0;
    const uint32_t delta = 0x9E3779B9u;
    for (int i = 0; i < 16; i++) {
        sum += delta;
        v0 += (((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1));
        v1 += (((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3));
    }
    memcpy(out, &v0, 4);
    memcpy(out + 4, &v1, 4);
}

static inline void tea_decrypt_block(uint8_t out[8], const uint8_t in[8], const uint8_t key[16]) {
    uint32_t v0, v1, k0, k1, k2, k3;
    memcpy(&v0, in, 4);
    memcpy(&v1, in + 4, 4);
    memcpy(&k0, key, 4);
    memcpy(&k1, key + 4, 4);
    memcpy(&k2, key + 8, 4);
    memcpy(&k3, key + 12, 4);
    const uint32_t delta = 0x9E3779B9u;
    uint32_t sum = delta * 16u;
    for (int i = 0; i < 16; i++) {
        v1 -= (((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3));
        v0 -= (((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1));
        sum -= delta;
    }
    memcpy(out, &v0, 4);
    memcpy(out + 4, &v1, 4);
}

// 经典布局 (无 type25): key@16, start=32, stride=80.
static void decrypt_classic(uint8_t* nal, size_t len) {
    if (len < 40) return;
    const uint8_t* key = nal + 16;
    for (size_t j = 0; 32 + j * 80 + 8 <= len; j++) {
        size_t o = 32 + j * 80;
        tea_decrypt_block(nal + o, nal + o, key);
    }
}

// Type5 新模式: key@5, start=64, stride S, 感知 EPB (同 type1).
// Worker 网格保护在逻辑单元起始处需要 16 字节; TEA 仅写入 8 字节.
// 返回丢弃 EPB 0x03 后的新 NAL 长度.
static size_t decrypt_type5_new(uint8_t* nal, size_t len, uint32_t stride) {
    if (!nal || len < 21 || stride < 8) return len;
    const uint8_t* key = nal + 5;

    // 收集 EPB 位置
    size_t* epbs = NULL;
    size_t epb_count = 0;
    size_t epb_cap = 0;
    for (size_t i = 0; i + 2 < len; i++) {
        if (nal[i] == 0 && nal[i + 1] == 0 && nal[i + 2] == 3) {
            size_t val = i;
            mem_push((void**)&epbs, &epb_count, &epb_cap, sizeof(size_t), &val, 1);
        }
    }

    for (size_t k = 0;; k++) {
        size_t o = 64 + k * (size_t)stride;
        if (o + 16 > len) break;
        size_t adj = 0;
        for (size_t e = 0; e < epb_count; e++) {
            if (epbs[e] < o) adj++;
            else break;
        }
        size_t oo = o + adj;
        if (oo + 8 > len) break;
        tea_decrypt_block(nal + oo, nal + oo, key);
    }

    if (epb_count == 0) {
        free(epbs);
        return len;
    }

    size_t nlen = len;
    for (size_t i = epb_count; i > 0; i--) {
        size_t e = epbs[i - 1];
        if (e + 2 < nlen && nal[e] == 0 && nal[e + 1] == 0 && nal[e + 2] == 3) {
            memmove(nal + e + 2, nal + e + 3, nlen - (e + 3));
            nlen--;
        }
    }
    free(epbs);
    return nlen;
}

static bool is_type25_enable(const uint8_t* nal, size_t len) {
    return len >= 4 && (nal[0] & 0x1f) == 25 && nal[2] == 0x01 && nal[3] == 0x09;
}

// ===== F5 / F1 步长 =====

static const uint16_t kType5F5Base[6] = {160, 192, 224, 256, 288, 320};

// key16: nal+5 处的 16字节 TEA 密钥 (F5 仅使用前 6 字节).
static uint32_t type5_stride_f5(const uint8_t* key16) {
    uint32_t le = (uint32_t)key16[0] | ((uint32_t)key16[1] << 8) | ((uint32_t)key16[2] << 16) | ((uint32_t)key16[3] << 24);
    unsigned idx = (unsigned)(le % 6u);
    return (uint32_t)kType5F5Base[idx] | (uint32_t)key16[idx];
}

// 便捷方法: 带有 header+RBSP 的 NAL, 需要 len >= 11 (最好 >= 21).
static uint32_t type5_stride_from_nal(const uint8_t* nal, size_t len) {
    if (!nal || len < 11) return 0;
    uint8_t key[6];
    key[0] = nal[5]; key[1] = nal[6]; key[2] = nal[7]; key[3] = nal[8];
    key[4] = (len > 9) ? nal[9] : 0;
    key[5] = (len > 10) ? nal[10] : 0;
    return type5_stride_f5(key);
}

// Type1 F1: 同 F5 的 BASE/select, key = nal[1:7].
static uint32_t type1_stride_f1(const uint8_t* nal, size_t len) {
    if (!nal || len < 7) return 0;
    return type5_stride_f5(nal + 1);
}

// ===== Type1 G + EPB 辅助函数 =====

static inline int type1_fbit(uint32_t W) {
    const int w0 = (W >> 0) & 1;
    const int w8 = (W >> 8) & 1;
    const int w15 = (W >> 15) & 1;
    const int w19 = (W >> 19) & 1;
    const int w25 = (W >> 25) & 1;
    const int w30 = (W >> 30) & 1;
    const int w31 = (W >> 31) & 1;
    const int t = w0 | w8;
    return (w31 ^ w15 ^ t ^ (w8 & w19) ^ (w25 & (w0 ^ w19)) ^ (w0 & (1 ^ w8) & w30) ^ ((1 ^ w0) & w19 & w30) ^ (w25 & w30 & (w8 ^ w19))) & 1;
}

static inline bool type1_is_B_step(int s) {
    return s == 2 || s == 8 || s == 9 || s == 10;
}

// 需要翻转 Fbit 的步长位掩码 (位 s 置 1 => 翻转步长 s).
static uint16_t type1_flip_mask_from_header(const uint8_t hdr[3]) {
    const uint8_t b0 = hdr[0], b1 = hdr[1], b2 = hdr[2];
    uint16_t m = 0;
    
    if (b0 == 0x01 && b1 == 0xA8) {
        if ((b2 >> 7) & 1) SETB(m, 0);
        if ((b2 >> 6) & 1) SETB(m, 1);
        if (1 ^ ((b2 >> 5) & 1)) SETB(m, 2);
        if ((b2 >> 4) & 1) SETB(m, 3);
        if ((b2 >> 3) & 1) SETB(m, 4);
        if ((b2 >> 1) & 1) SETB(m, 6);
        if ((b2 >> 0) & 1) SETB(m, 7);
        SETB(m, 9); SETB(m, 12);
        return m;
    }
    
    if (b0 == 0x61) {
        if ((b2 >> 1) & 1) SETB(m, 0);
        if ((b2 >> 0) & 1) SETB(m, 1);
        if (1 ^ ((b2 >> 5) & 1)) SETB(m, 2);
        if ((b2 >> 3) & 1) SETB(m, 4);
        if ((b2 >> 2) & 1) SETB(m, 5);
        if ((b2 >> 1) & 1) SETB(m, 6);
        if ((b2 >> 0) & 1) SETB(m, 7);
        if ((b2 >> 3) & 1) SETB(m, 14);
        if ((b2 >> 2) & 1) SETB(m, 15);
        return m;
    }
    
    // 切片头部族: nal_type=1 且 b1 高四位为 0x9
    if ((b0 & 0x1f) == 1 && (b1 & 0xf0) == 0x90) {
        if ((b2 >> 7) & 1) SETB(m, 0);
        if ((b2 >> 6) & 1) SETB(m, 1);
        if (((b0 >> 0) & 1) ^ ((b2 >> 5) & 1)) SETB(m, 2);
        if ((b2 >> 4) & 1) SETB(m, 3);
        if ((b2 >> 3) & 1) SETB(m, 4);
        if ((b2 >> 2) & 1) SETB(m, 5);
        if (((b0 >> 0) & 1) ^ ((b0 >> 6) & 1)) SETB(m, 7);
        if ((b0 >> 0) & 1) {
            SETB(m, 9); SETB(m, 10); SETB(m, 11); SETB(m, 12); SETB(m, 14);
        }
        if (((b0 >> 0) & 1) ^ ((b0 >> 6) & 1)) SETB(m, 13);
        if ((b1 >> 0) & 1) SETB(m, 15);
        return m;
    }
    
    return 0; // 未知族
}

static uint16_t type1_G_flips(uint16_t X, uint16_t Y, uint16_t flip_mask) {
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

static uint16_t type1_G(uint16_t X, uint16_t Y) {
    return type1_G_flips(X, Y, 0);
}

static uint16_t type1_G_nal(uint16_t X, uint16_t Y, const uint8_t nal_hdr[3]) {
    return type1_G_flips(X, Y, type1_flip_mask_from_header(nal_hdr));
}

static inline void type1_decrypt_block_nal(uint8_t blk[4], const uint8_t nal_hdr[3]) {
    const uint16_t X = (uint16_t)(blk[0] | (blk[1] << 8));
    const uint16_t Y = (uint16_t)(blk[2] | (blk[3] << 8));
    const uint16_t P1 = type1_G_nal(X, Y, nal_hdr);
    blk[0] = (uint8_t)(P1 & 0xFF);
    blk[1] = (uint8_t)((P1 >> 8) & 0xFF);
    blk[2] = (uint8_t)(X & 0xFF);
    blk[3] = (uint8_t)((X >> 8) & 0xFF);
}

// 收集 EPB 位置 (00 00 03 的起始处).
static void collect_epb_positions(const uint8_t* nal, size_t len, size_t** out_epbs, size_t* out_count) {
    *out_epbs = NULL;
    *out_count = 0;
    size_t cap = 0;
    if (!nal || len < 3) return;
    for (size_t i = 0; i + 2 < len; i++) {
        if (nal[i] == 0 && nal[i + 1] == 0 && nal[i + 2] == 3) {
            mem_push((void**)out_epbs, out_count, &cap, sizeof(size_t), &i, 1);
        }
    }
}

// 丢弃仍存在的 EPB 的 0x03 (从尾部开始). 返回新长度.
static size_t drop_epb_03(uint8_t* nal, size_t len, const size_t* epbs, size_t epb_count) {
    if (!nal) return len;
    size_t nlen = len;
    for (size_t i = epb_count; i > 0; i--) {
        size_t e = epbs[i - 1];
        if (e + 2 < nlen && nal[e] == 0 && nal[e + 1] == 0 && nal[e + 2] == 3) {
            memmove(nal + e + 2, nal + e + 3, nlen - (e + 3));
            nlen--;
        }
    }
    return nlen;
}

// 网格保护: 在 RBSP 单元起始处要求剩余 ``guard`` 字节 (默认 17)
// 即使只重写 4 字节. 通过 RBSP->EBSP 映射访问单元字节 (跳过 EPB 0x03);
// 然后丢弃仍然存在的 0x03. 返回新 NAL 长度.
static size_t decrypt_type1_new(uint8_t* nal, size_t len, uint32_t stride, size_t start, size_t guard) {
    if (!nal || stride < 4 || len < 3) return len;
    const uint8_t hdr[3] = {nal[0], nal[1], nal[2]};

    size_t* epbs = NULL;
    size_t epb_count = 0;
    collect_epb_positions(nal, len, &epbs, &epb_count);

    size_t* r2e = NULL;
    size_t r2e_size = 0;
    size_t r2e_cap = len; // 最大不超过 len
    r2e = (size_t*)malloc(len * sizeof(size_t));
    
    for (size_t i = 0; i < len; ) {
        if (i + 2 < len && nal[i] == 0 && nal[i + 1] == 0 && nal[i + 2] == 3) {
            r2e[r2e_size++] = i;
            r2e[r2e_size++] = i + 1;
            i += 3;
        } else {
            r2e[r2e_size++] = i;
            i++;
        }
    }

    for (size_t k = 0;; k++) {
        size_t o = start + k * (size_t)stride;
        if (o + guard > r2e_size || o + 4 > r2e_size) break;
        uint8_t blk[4] = {nal[r2e[o]], nal[r2e[o + 1]], nal[r2e[o + 2]], nal[r2e[o + 3]]};
        type1_decrypt_block_nal(blk, hdr);
        nal[r2e[o]] = blk[0];
        nal[r2e[o + 1]] = blk[1];
        nal[r2e[o + 2]] = blk[2];
        nal[r2e[o + 3]] = blk[3];
    }

    free(r2e);

    if (epb_count == 0) {
        free(epbs);
        return len;
    }

    size_t nlen = drop_epb_03(nal, len, epbs, epb_count);
    free(epbs);
    return nlen;
}

// ===== 会话 =====

typedef struct {
    bool new_mode;
    size_t type1_start;
    size_t type1_guard;
    size_t type1_min_len;
} CctvH5eSession;

static void session_init(CctvH5eSession* s) {
    s->new_mode = false;
    s->type1_start = 64;
    s->type1_guard = 17;
    s->type1_min_len = 129;
}

static void session_reset(CctvH5eSession* s) {
    s->new_mode = false;
}

static void session_on_nal(CctvH5eSession* s, uint8_t* nal, size_t* io_len) {
    if (!nal || !io_len || *io_len < 1) return;
    size_t len = *io_len;
    const int ntype = nal[0] & 0x1f;

    if (ntype == 25) {
        if (is_type25_enable(nal, len)) s->new_mode = true;
        return;
    }

    if (!s->new_mode) {
        if (ntype == 1 || ntype == 5) decrypt_classic(nal, len);
        return;
    }

    if (ntype == 5) {
        uint32_t S = type5_stride_from_nal(nal, len);
        if (S >= 8) *io_len = decrypt_type5_new(nal, len, S);
        return;
    }

    if (ntype == 1) {
        if (len < s->type1_min_len) return;
        uint32_t S = type1_stride_f1(nal, len);
        if (!S) S = 511u;
        *io_len = decrypt_type1_new(nal, len, S, s->type1_start, s->type1_guard);
    }
}

// ===== MPEG-TS =====

// 扩展单个 TS 包上的 AF 填充; 返回从有效载荷中偷取的字节数.
static size_t expand_af_steal(uint8_t* data, size_t len, size_t pkt_off, size_t need) {
    if (!data || need == 0 || pkt_off + 188 > len) return 0;
    int afc = (data[pkt_off + 3] & 0x30) >> 4;
    if (afc == 1) {
        if (need < 1) return 0;
        size_t af_len = need - 1;
        if (af_len > 182) af_len = 182;
        size_t steal = 1 + af_len;
        uint8_t old_payload[184];
        memcpy(old_payload, data + pkt_off + 4, 184);
        data[pkt_off + 3] = (uint8_t)((data[pkt_off + 3] & 0xCF) | 0x30); // afc=3
        data[pkt_off + 4] = (uint8_t)af_len;
        if (af_len > 0) {
            data[pkt_off + 5] = 0x00; // flags
            for (size_t i = 1; i < af_len; i++) data[pkt_off + 5 + i] = 0xFF;
        }
        size_t new_pl = 184 - steal;
        memcpy(data + pkt_off + 5 + af_len, old_payload, new_pl);
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
        memcpy(old_payload, data + pkt_off + pi, old_payload_len);
        for (size_t i = 0; i < add; i++) data[pkt_off + 5 + af_len + i] = 0xFF;
        data[pkt_off + 4] = (uint8_t)new_af_len;
        size_t new_pl = old_payload_len - add;
        memcpy(data + pkt_off + 5 + new_af_len, old_payload, new_pl);
        if (new_pl == 0) data[pkt_off + 3] = (uint8_t)((data[pkt_off + 3] & 0xCF) | 0x20); // afc=2
        else data[pkt_off + 3] = (uint8_t)((data[pkt_off + 3] & 0xCF) | 0x30); // afc=3
        return add;
    }
    return 0;
}

typedef struct {
    size_t off;
    size_t pi;
    size_t pl;
} Span;

typedef struct {
    size_t pos;
    size_t sc_len;
} StartCode;

// 解密 TS 缓冲区中的所有视频 NAL (原地操作).
static size_t decrypt_ts_inplace(uint8_t* data, size_t len, CctvH5eSession* session, uint16_t vpid) {
    if (!data || len < 188) return 0;

    // PES 数据
    uint8_t* pes_data = NULL;
    size_t pes_size = 0;
    size_t pes_cap = 0;

    // spans 数据
    Span* spans = NULL;
    size_t spans_count = 0;
    size_t spans_cap = 0;

    size_t nal_count = 0;

    // flush 局部逻辑用闭包宏替代，或者直接展开
    #define DO_FLUSH() \
        do { \
            if (pes_size > 0) { \
                size_t base_skip = 0; \
                if (pes_size >= 9 && pes_data[0] == 0 && pes_data[1] == 0 && pes_data[2] == 1) { \
                    base_skip = 9 + pes_data[8]; \
                } \
                if (base_skip > pes_size) { \
                    pes_size = 0; spans_count = 0; \
                } else { \
                    uint8_t* new_pes = NULL; \
                    size_t new_pes_size = 0; \
                    size_t new_pes_cap = 0; \
                    /* 拷贝 pes_hdr */ \
                    mem_push((void**)&new_pes, &new_pes_size, &new_pes_cap, 1, pes_data, base_skip); \
                    \
                    const uint8_t* es = pes_data + base_skip; \
                    size_t es_size = pes_size - base_skip; \
                    \
                    StartCode* starts = NULL; \
                    size_t starts_count = 0; \
                    size_t starts_cap = 0; \
                    \
                    size_t i = 0; \
                    while (i + 3 < es_size) { \
                        if (i + 4 <= es_size && es[i] == 0 && es[i+1] == 0 && es[i+2] == 0 && es[i+3] == 1) { \
                            StartCode sc = {i, 4}; \
                            mem_push((void**)&starts, &starts_count, &starts_cap, sizeof(StartCode), &sc, 1); \
                            i += 4; \
                        } else if (es[i] == 0 && es[i+1] == 0 && es[i+2] == 1) { \
                            StartCode sc = {i, 3}; \
                            mem_push((void**)&starts, &starts_count, &starts_cap, sizeof(StartCode), &sc, 1); \
                            i += 3; \
                        } else { \
                            i++; \
                        } \
                    } \
                    \
                    size_t cursor = 0; \
                    for (size_t idx = 0; idx < starts_count; idx++) { \
                        size_t pos = starts[idx].pos; \
                        size_t sc = starts[idx].sc_len; \
                        size_t end = (idx + 1 < starts_count) ? starts[idx+1].pos : es_size; \
                        \
                        if (cursor < pos) \
                            mem_push((void**)&new_pes, &new_pes_size, &new_pes_cap, 1, es + cursor, pos - cursor); \
                        \
                        mem_push((void**)&new_pes, &new_pes_size, &new_pes_cap, 1, es + pos, sc); \
                        \
                        if (pos + sc >= end) { \
                            cursor = end; \
                            continue; \
                        } \
                        \
                        size_t nal_len = end - (pos + sc); \
                        uint8_t* nal_buf = (uint8_t*)malloc(nal_len); \
                        memcpy(nal_buf, es + pos + sc, nal_len); \
                        size_t nlen = nal_len; \
                        session_on_nal(session, nal_buf, &nlen); \
                        nal_count++; \
                        mem_push((void**)&new_pes, &new_pes_size, &new_pes_cap, 1, nal_buf, nlen); \
                        free(nal_buf); \
                        cursor = end; \
                    } \
                    if (cursor < es_size) \
                        mem_push((void**)&new_pes, &new_pes_size, &new_pes_cap, 1, es + cursor, es_size - cursor); \
                    \
                    free(starts); \
                    \
                    /* 处理容量和 AF 吸收 */ \
                    size_t capacity = 0; \
                    for (size_t j = 0; j < spans_count; j++) capacity += spans[j].pl; \
                    if (capacity > new_pes_size) { \
                        size_t remaining = capacity - new_pes_size; \
                        for (size_t j = spans_count; j > 0 && remaining > 0; j--) { \
                            size_t got = expand_af_steal(data, len, spans[j-1].off, remaining); \
                            remaining -= got; \
                        } \
                        /* 重新计算 spans */ \
                        size_t new_spans_count = 0; \
                        for (size_t j = 0; j < spans_count; j++) { \
                            size_t pkt_off = spans[j].off; \
                            int afc = (data[pkt_off + 3] & 0x30) >> 4; \
                            if (afc == 0 || afc == 2) continue; \
                            size_t pi = (afc == 1) ? 4 : (5 + data[pkt_off + 4]); \
                            if (pi >= 188) continue; \
                            spans[new_spans_count].off = pkt_off; \
                            spans[new_spans_count].pi = pi; \
                            spans[new_spans_count].pl = 188 - pi; \
                            new_spans_count++; \
                        } \
                        spans_count = new_spans_count; \
                    } \
                    \
                    /* 回写 TS 包 */ \
                    size_t off = 0; \
                    for (size_t j = 0; j < spans_count; j++) { \
                        size_t pkt_off = spans[j].off; \
                        size_t pi = spans[j].pi; \
                        size_t pl = spans[j].pl; \
                        size_t chunk = new_pes_size - off; \
                        if (chunk > pl) chunk = pl; \
                        if (chunk > 0) memcpy(data + pkt_off + pi, new_pes + off, chunk); \
                        if (chunk < pl) memset(data + pkt_off + pi + chunk, 0xFF, pl - chunk); \
                        off += pl; \
                    } \
                    free(new_pes); \
                    pes_size = 0; \
                    spans_count = 0; \
                } \
            } \
        } while(0)

    for (size_t off = 0; off + 188 <= len; off += 188) {
        if (data[off] != 0x47) continue;
        uint16_t pid = (uint16_t)(((data[off + 1] & 0x1f) << 8) | data[off + 2]);
        if (pid != vpid) continue;

        bool pusi = (data[off + 1] & 0x40) != 0;
        int afc = (data[off + 3] & 0x30) >> 4;
        if (afc == 0 || afc == 2) continue;
        size_t pi = (afc == 1) ? 4 : (5 + data[off + 4]);
        if (pi >= 188) continue;
        size_t payload_len = 188 - pi;

        if (pusi) {
            DO_FLUSH();
        }

        mem_push((void**)&pes_data, &pes_size, &pes_cap, 1, data + off + pi, payload_len);
        
        Span sp = {off, pi, payload_len};
        mem_push((void**)&spans, &spans_count, &spans_cap, sizeof(Span), &sp, 1);
    }

    DO_FLUSH();
    #undef DO_FLUSH

    free(pes_data);
    free(spans);
    return nal_count;
}


// ===== C API 封装 =====

typedef struct cctv_h5e_session {
    CctvH5eSession impl;
} cctv_h5e_session;

cctv_h5e_session* cctv_h5e_session_create(void) {
    cctv_h5e_session* s = (cctv_h5e_session*)malloc(sizeof(cctv_h5e_session));
    if (s) session_init(&s->impl);
    return s;
}

void cctv_h5e_session_destroy(cctv_h5e_session* s) {
    free(s);
}

void cctv_h5e_session_reset(cctv_h5e_session* s) {
    if (s) session_reset(&s->impl);
}

int cctv_h5e_decrypt_nal(cctv_h5e_session* s, uint8_t* nal, size_t* io_nal_len) {
    if (!s || !nal || !io_nal_len) return -1;
    session_on_nal(&s->impl, nal, io_nal_len);
    return 0;
}

int cctv_h5e_decrypt_ts(cctv_h5e_session* s, uint8_t* ts, size_t ts_len, uint16_t vpid) {
    if (!s || !ts) return -1;
    return (int)decrypt_ts_inplace(ts, ts_len, &s->impl, vpid);
}

int cctv_h5e_decrypt_ts_alloc(const uint8_t* ts_in, size_t ts_len, uint8_t** out_ts, size_t* out_len, uint16_t vpid) {
    if (!ts_in || !out_ts || !out_len) return -1;
    *out_ts = (uint8_t*)malloc(ts_len ? ts_len : 1);
    if (!*out_ts) return -1;
    memcpy(*out_ts, ts_in, ts_len);
    
    CctvH5eSession session;
    session_init(&session);
    decrypt_ts_inplace(*out_ts, ts_len, &session, vpid);
    *out_len = ts_len;
    return 0;
}

void cctv_h5e_free(void* p) {
    free(p);
}

const char* cctv_h5e_version(void) {
    return "cctv_h5e pure F5/F1+EPB+AF 1.0 C11 (2026-07-23)";
}

// ===== CLI 命令行入口 =====

#ifdef CCTV_H5E_CLI

static uint8_t* h5e_read_all(const char* path, size_t* out_size) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n <= 0) {
        fclose(f);
        return NULL;
    }
    uint8_t* b = (uint8_t*)malloc((size_t)n);
    if (!b) {
        fclose(f);
        return NULL;
    }
    size_t read = fread(b, 1, (size_t)n, f);
    fclose(f);
    if (read != (size_t)n) {
        free(b);
        return NULL;
    }
    *out_size = (size_t)n;
    return b;
}

int main(int argc, char** argv) {
    const char* ver = cctv_h5e_version();
    if (argc < 3) {
        fprintf(stderr, "cctv_h5e_decrypt — pure C11 hls_h5e TS decrypt\n"
                        "  %s\n"
                        "Usage: %s <enc.ts> <out.ts> [--pid 0x100]\n", ver, argv[0]);
        return 1;
    }

    uint16_t vpid = 0x100;
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc) {
            vpid = (uint16_t)strtoul(argv[++i], NULL, 0);
        }
    }

    size_t enc_size = 0;
    uint8_t* enc = h5e_read_all(argv[1], &enc_size);
    if (!enc) {
        fprintf(stderr, "cannot read %s\n", argv[1]);
        return 1;
    }

    uint8_t* out = NULL;
    size_t out_len = 0;
    int rc = cctv_h5e_decrypt_ts_alloc(enc, enc_size, &out, &out_len, vpid);
    free(enc); // 释放输入数据

    if (rc != 0 || !out) {
        fprintf(stderr, "decrypt failed rc=%d\n", rc);
        return 1;
    }

    FILE* of = fopen(argv[2], "wb");
    if (!of) {
        cctv_h5e_free(out);
        fprintf(stderr, "cannot write %s\n", argv[2]);
        return 1;
    }
    fwrite(out, 1, out_len, of);
    fclose(of);
    cctv_h5e_free(out);

    fprintf(stderr, "ok: %zu bytes -> %s (%s)\n", out_len, argv[2], ver);
    return 0;
}

#endif // CCTV_H5E_CLI
