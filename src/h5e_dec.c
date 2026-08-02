// =============================================================================
// cctv_h5e_decrypt.c
// Pure C11 decrypt for CCTV hls_h5e (new-mode) MPEG-TS
// =============================================================================
//
// Features:
// - Closed-form type5 stride F5 and type1 stride F1 (no lookup tables)
// - Type1 G transform with multi-header flip mask (01a8xx / 61exxx)
// - TEA-16 for type5; classic mode fallback before type25
// - EPB (00 00 03) grid alignment + 03 drop (matches official worker)
// - MPEG-TS PES rebuild with adaptation-field stuffing for length shrink
//
// Compile (CLI):
// gcc -std=c11 -Os -s -o dec cctv_h5e_decrypt.c
// =============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

// =============================================================================
// Dynamic Array Helpers (Replaces std::vector)
// =============================================================================

typedef struct {
    size_t *data;
    size_t size;
    size_t capacity;
} SizeTVec;

static void size_vec_init(SizeTVec *v) {
    v->data = NULL;
    v->size = 0;
    v->capacity = 0;
}

static void size_vec_free(SizeTVec *v) {
    free(v->data);
    v->data = NULL;
    v->size = 0;
    v->capacity = 0;
}

static bool size_vec_push(SizeTVec *v, size_t val) {
    if (v->size >= v->capacity) {
        size_t new_cap = v->capacity ? v->capacity * 2 : 16;
        size_t *new_data = realloc(v->data, new_cap * sizeof(size_t));
        if (!new_data) return false;
        v->data = new_data;
        v->capacity = new_cap;
    }
    v->data[v->size++] = val;
    return true;
}

typedef struct {
    uint8_t *data;
    size_t size;
    size_t capacity;
} ByteVec;

static void byte_vec_init(ByteVec *v) {
    v->data = NULL;
    v->size = 0;
    v->capacity = 0;
}

static void byte_vec_free(ByteVec *v) {
    free(v->data);
    v->data = NULL;
    v->size = 0;
    v->capacity = 0;
}

static bool byte_vec_push(ByteVec *v, const uint8_t *src, size_t len) {
    if (v->size + len > v->capacity) {
        size_t new_cap = v->capacity ? (v->capacity + len) * 2 : 256;
        uint8_t *new_data = realloc(v->data, new_cap);
        if (!new_data) return false;
        v->data = new_data;
        v->capacity = new_cap;
    }
    memcpy(v->data + v->size, src, len);
    v->size += len;
    return true;
}

// =============================================================================
// Constants & TEA Algorithm
// =============================================================================

static const uint16_t kType5F5Base[6] = {160, 192, 224, 256, 288, 320};

static void tea_decrypt_block(uint8_t out[8], const uint8_t in[8], const uint8_t key[16]) {
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

// =============================================================================
// Classic & Type5 Logic
// =============================================================================

static void decrypt_classic(uint8_t* nal, size_t len) {
    if (len < 40) return;
    const uint8_t* key = nal + 16;
    for (size_t j = 0; 32 + j * 80 + 8 <= len; j++) {
        size_t o = 32 + j * 80;
        tea_decrypt_block(nal + o, nal + o, key);
    }
}

static bool is_type25_enable(const uint8_t* nal, size_t len) {
    return len >= 4 && (nal[0] & 0x1f) == 25 && nal[2] == 0x01 && nal[3] == 0x09;
}

static uint32_t type5_stride_f5(const uint8_t* key16) {
    uint32_t le = (uint32_t)key16[0] | ((uint32_t)key16[1] << 8) | 
                  ((uint32_t)key16[2] << 16) | ((uint32_t)key16[3] << 24);
    unsigned idx = (unsigned)(le % 6u);
    return (uint32_t)kType5F5Base[idx] | (uint32_t)key16[idx];
}

static uint32_t type5_stride_from_nal(const uint8_t* nal, size_t len) {
    if (!nal || len < 11) return 0;
    uint8_t key[6];
    key[0] = nal[5]; key[1] = nal[6]; key[2] = nal[7]; key[3] = nal[8];
    key[4] = (len > 9) ? nal[9] : 0;
    key[5] = (len > 10) ? nal[10] : 0;
    return type5_stride_f5(key);
}

static size_t decrypt_type5_new(uint8_t* nal, size_t len, uint32_t stride) {
    if (!nal || len < 21 || stride < 8) return len;
    const uint8_t* key = nal + 5;

    SizeTVec epbs, r2e;
    size_vec_init(&epbs);
    size_vec_init(&r2e);

    // Build RBSP map (r2e)
    for (size_t i = 0; i + 2 < len; i++) {
        if (nal[i] == 0 && nal[i + 1] == 0 && nal[i + 2] == 3) {
            size_vec_push(&epbs, i);
            size_vec_push(&r2e, i);
            size_vec_push(&r2e, i + 1);
            i += 2;
        } else {
            size_vec_push(&r2e, i);
        }
    }
    // Handle remaining bytes
    for (size_t i = (len < 3 ? 0 : len - 2); i < len; i++) {
        size_vec_push(&r2e, i);
    }

    const size_t rbsp_len = r2e.size;
    uint8_t tmp[8];

    for (size_t k = 0;; k++) {
        size_t o = 64 + k * (size_t)stride;
        if (o + 16 > rbsp_len || o + 8 > rbsp_len) break;
        for (size_t b = 0; b < 8; b++) tmp[b] = nal[r2e.data[o + b]];
        tea_decrypt_block(tmp, tmp, key);
        for (size_t b = 0; b < 8; b++) nal[r2e.data[o + b]] = tmp[b];
    }

    size_t nlen = len;
    if (epbs.size > 0) {
        for (size_t i = epbs.size; i > 0; i--) {
            size_t e = epbs.data[i - 1];
            if (e + 2 < nlen && nal[e] == 0 && nal[e + 1] == 0 && nal[e + 2] == 3) {
                memmove(nal + e + 2, nal + e + 3, nlen - (e + 3));
                nlen--;
            }
        }
    }

    size_vec_free(&epbs);
    size_vec_free(&r2e);
    return nlen;
}

// =============================================================================
// Type1 Logic
// =============================================================================

static uint32_t type1_stride_f1(const uint8_t* nal, size_t len) {
    if (!nal || len < 7) return 0;
    return type5_stride_f5(nal + 1);
}

static int type1_fbit(uint32_t W) {
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

static bool type1_is_B_step(int s) {
    return s == 2 || s == 8 || s == 9 || s == 10;
}

static uint16_t type1_flip_mask_from_header(const uint8_t hdr[3]) {
    const uint8_t b0 = hdr[0], b1 = hdr[1], b2 = hdr[2];
    uint16_t m = 0;

    #define SETB(m, s) m = (uint16_t)(m | (uint16_t)(1u << (s)))

    if (b0 == 0x01 && b1 == 0xA8) {
        if ((b2 >> 7) & 1) SETB(m, 0);
        if ((b2 >> 6) & 1) SETB(m, 1);
        if (1 ^ ((b2 >> 5) & 1)) SETB(m, 2);
        if ((b2 >> 4) & 1) SETB(m, 3);
        if ((b2 >> 3) & 1) SETB(m, 4);
        if ((b2 >> 1) & 1) SETB(m, 6);
        if ((b2 >> 0) & 1) SETB(m, 7);
        SETB(m, 9);
        SETB(m, 12);
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

    // Slice-header family
    if ((b0 & 0x1f) == 1 && (b1 & 0xf0) == 0x90) {
        if ((b2 >> 7) & 1) SETB(m, 0);
        if ((b2 >> 6) & 1) SETB(m, 1);
        if (((b0 >> 0) & 1) ^ ((b2 >> 5) & 1)) SETB(m, 2);
        if ((b2 >> 4) & 1) SETB(m, 3);
        if ((b2 >> 3) & 1) SETB(m, 4);
        if ((b2 >> 2) & 1) SETB(m, 5);
        if ((b2 >> 1) & 1) SETB(m, 6);
        if ((b2 >> 0) & 1) SETB(m, 7);
        if ((b0 >> 0) & 1) {
            SETB(m, 9); SETB(m, 10); SETB(m, 11); SETB(m, 12); SETB(m, 14);
        }
        if (((b0 >> 0) & 1) ^ ((b0 >> 6) & 1)) SETB(m, 13);
        if ((b1 >> 0) & 1) SETB(m, 15);
        return m;
    }
    #undef SETB
    return 0;
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

static void type1_decrypt_block_nal(uint8_t blk[4], const uint8_t nal_hdr[3]) {
    const uint16_t X = (uint16_t)(blk[0] | (blk[1] << 8));
    const uint16_t Y = (uint16_t)(blk[2] | (blk[3] << 8));
    const uint16_t P1 = type1_G_flips(X, Y, type1_flip_mask_from_header(nal_hdr));
    blk[0] = (uint8_t)(P1 & 0xFF);
    blk[1] = (uint8_t)((P1 >> 8) & 0xFF);
    blk[2] = (uint8_t)(X & 0xFF);
    blk[3] = (uint8_t)((X >> 8) & 0xFF);
}

static size_t decrypt_type1_new(uint8_t* nal, size_t len, uint32_t stride, size_t start, size_t guard) {
    if (!nal || stride < 4 || len < 3) return len;
    const uint8_t hdr[3] = {nal[0], nal[1], nal[2]};

    SizeTVec epbs, r2e;
    size_vec_init(&epbs);
    size_vec_init(&r2e);

    for (size_t i = 0; i < len; ) {
        if (i + 2 < len && nal[i] == 0 && nal[i + 1] == 0 && nal[i + 2] == 3) {
            size_vec_push(&epbs, i);
            size_vec_push(&r2e, i);
            size_vec_push(&r2e, i + 1);
            i += 3;
        } else {
            size_vec_push(&r2e, i);
            i++;
        }
    }

    const size_t rbsp_len = r2e.size;
    for (size_t k = 0;; k++) {
        size_t o = start + k * (size_t)stride;
        if (o + guard > rbsp_len || o + 4 > rbsp_len) break;

        uint8_t blk[4];
        blk[0] = nal[r2e.data[o]];
        blk[1] = nal[r2e.data[o + 1]];
        blk[2] = nal[r2e.data[o + 2]];
        blk[3] = nal[r2e.data[o + 3]];

        type1_decrypt_block_nal(blk, hdr);

        nal[r2e.data[o]] = blk[0];
        nal[r2e.data[o + 1]] = blk[1];
        nal[r2e.data[o + 2]] = blk[2];
        nal[r2e.data[o + 3]] = blk[3];
    }

    size_t nlen = len;
    if (epbs.size > 0) {
        for (size_t i = epbs.size; i > 0; i--) {
            size_t e = epbs.data[i - 1];
            if (e + 2 < nlen && nal[e] == 0 && nal[e + 1] == 0 && nal[e + 2] == 3) {
                memmove(nal + e + 2, nal + e + 3, nlen - (e + 3));
                nlen--;
            }
        }
    }

    size_vec_free(&epbs);
    size_vec_free(&r2e);
    return nlen;
}

// =============================================================================
// Session & MPEG-TS
// =============================================================================

typedef struct {
    bool new_mode;
    size_t type1_start;
    size_t type1_guard;
    size_t type1_min_len;
} Session;

static void session_init(Session* s) {
    s->new_mode = false;
    s->type1_start = 64;
    s->type1_guard = 17;
    s->type1_min_len = 129;
}

static void session_on_nal(Session* s, uint8_t* nal, size_t* io_len) {
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
        if (S == 0) S = 511u;
        *io_len = decrypt_type1_new(nal, len, S, s->type1_start, s->type1_guard);
    }
}

// TS Helper Structures
typedef struct {
    size_t pkt_off;
    size_t pi;
    size_t payload_len;
} TSSpan;

typedef struct {
    TSSpan *data;
    size_t size;
    size_t capacity;
} SpanVec;

static void span_vec_init(SpanVec *v) { v->data = NULL; v->size = 0; v->capacity = 0; }
static void span_vec_free(SpanVec *v) { free(v->data); }
static bool span_vec_push(SpanVec *v, TSSpan val) {
    if (v->size >= v->capacity) {
        size_t nc = v->capacity ? v->capacity * 2 : 16;
        TSSpan *nd = realloc(v->data, nc * sizeof(TSSpan));
        if (!nd) return false;
        v->data = nd; v->capacity = nc;
    }
    v->data[v->size++] = val;
    return true;
}

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

        data[pkt_off + 3] = (data[pkt_off + 3] & 0xCF) | 0x30;
        data[pkt_off + 4] = (uint8_t)af_len;
        if (af_len > 0) {
            data[pkt_off + 5] = 0x00;
            memset(data + pkt_off + 6, 0xFF, af_len - 1);
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

        memset(data + pkt_off + 5 + af_len, 0xFF, add);
        data[pkt_off + 4] = (uint8_t)new_af_len;

        size_t new_pl = old_payload_len - add;
        memcpy(data + pkt_off + 5 + new_af_len, old_payload, new_pl);

        if (new_pl == 0) data[pkt_off + 3] = (data[pkt_off + 3] & 0xCF) | 0x20;
        else data[pkt_off + 3] = (data[pkt_off + 3] & 0xCF) | 0x30;
        return add;
    }
    return 0;
}

static void flush_buffer(Session* session, uint8_t* ts_data, size_t ts_len, ByteVec* pes, SpanVec* spans, size_t* nal_count) {
    if (pes->size == 0) return;

    size_t base_skip = 0;
    if (pes->size >= 9 && pes->data[0] == 0 && pes->data[1] == 0 && pes->data[2] == 1) {
        base_skip = 9 + pes->data[8];
    }
    if (base_skip > pes->size) {
        pes->size = 0; // Clear
        spans->size = 0;
        return;
    }

    uint8_t* pes_hdr = pes->data;
    size_t pes_hdr_len = base_skip;
    uint8_t* es = pes->data + base_skip;
    size_t es_len = pes->size - base_skip;

    SizeTVec starts, sc_lens;
    size_vec_init(&starts);
    size_vec_init(&sc_lens);

    size_t i = 0;
    while (i + 3 < es_len) {
        if (i + 4 <= es_len && es[i] == 0 && es[i+1] == 0 && es[i+2] == 0 && es[i+3] == 1) {
            size_vec_push(&starts, i);
            size_vec_push(&sc_lens, 4);
            i += 4;
        } else if (es[i] == 0 && es[i+1] == 0 && es[i+2] == 1) {
            size_vec_push(&starts, i);
            size_vec_push(&sc_lens, 3);
            i += 3;
        } else {
            i++;
        }
    }

    ByteVec new_es;
    byte_vec_init(&new_es);
    size_t cursor = 0;

    for (size_t idx = 0; idx < starts.size; idx++) {
        size_t pos = starts.data[idx];
        size_t sc_len = sc_lens.data[idx];
        size_t end = (idx + 1 < starts.size) ? starts.data[idx+1] : es_len;

        if (cursor < pos) byte_vec_push(&new_es, es + cursor, pos - cursor);
        byte_vec_push(&new_es, es + pos, sc_len);

        if (pos + sc_len >= end) {
            cursor = end;
            continue;
        }

        size_t nal_len = end - (pos + sc_len);
        // In-place modification requires copy
        uint8_t* nal_tmp = malloc(nal_len);
        if (nal_tmp) {
            memcpy(nal_tmp, es + pos + sc_len, nal_len);
            size_t nlen = nal_len;
            session_on_nal(session, nal_tmp, &nlen);
            (*nal_count)++;
            byte_vec_push(&new_es, nal_tmp, nlen);
            free(nal_tmp);
        } else {
            byte_vec_push(&new_es, es + pos + sc_len, nal_len);
        }
        cursor = end;
    }
    if (cursor < es_len) byte_vec_push(&new_es, es + cursor, es_len - cursor);

    ByteVec new_pes;
    byte_vec_init(&new_pes);
    byte_vec_push(&new_pes, pes_hdr, pes_hdr_len);
    byte_vec_push(&new_pes, new_es.data, new_es.size);

    size_t capacity = 0;
    for (size_t i = 0; i < spans->size; i++) capacity += spans->data[i].payload_len;

    if (capacity > new_pes.size) {
        size_t remaining = capacity - new_pes.size;
        for (size_t i = spans->size; i > 0 && remaining > 0; i--) {
            size_t got = expand_af_steal(ts_data, ts_len, spans->data[i-1].pkt_off, remaining);
            remaining -= got;
        }

        SpanVec new_spans;
        span_vec_init(&new_spans);
        for (size_t i = 0; i < spans->size; i++) {
            size_t pkt_off = spans->data[i].pkt_off;
            int afc = (ts_data[pkt_off + 3] & 0x30) >> 4;
            if (afc == 0 || afc == 2) continue;
            size_t pi = (afc == 1) ? 4 : (size_t)(5 + ts_data[pkt_off + 4]);
            if (pi >= 188) continue;
            TSSpan s = {pkt_off, pi, 188 - pi};
            span_vec_push(&new_spans, s);
        }
        span_vec_free(spans);
        *spans = new_spans;
    }

    size_t off = 0;
    for (size_t i = 0; i < spans->size; i++) {
        size_t pkt_off = spans->data[i].pkt_off;
        size_t pi = spans->data[i].pi;
        size_t pl = spans->data[i].payload_len;

        size_t chunk = new_pes.size - off;
        if (chunk > pl) chunk = pl;
        if (chunk > 0) memcpy(ts_data + pkt_off + pi, new_pes.data + off, chunk);
        if (chunk < pl) memset(ts_data + pkt_off + pi + chunk, 0xFF, pl - chunk);
        off += chunk;
    }

    size_vec_free(&starts);
    size_vec_free(&sc_lens);
    byte_vec_free(&new_es);
    byte_vec_free(&new_pes);

    pes->size = 0;
    spans->size = 0;
}

static size_t decrypt_ts_inplace(uint8_t* data, size_t len, Session* session, uint16_t vpid) {
    if (!data || len < 188) return 0;

    ByteVec pes;
    SpanVec spans;
    byte_vec_init(&pes);
    span_vec_init(&spans);
    size_t nal_count = 0;

    for (size_t off = 0; off + 188 <= len; off += 188) {
        if (data[off] != 0x47) continue;
        uint16_t pid = (uint16_t)(((data[off + 1] & 0x1f) << 8) | data[off + 2]);
        if (pid != vpid) continue;

        bool pusi = (data[off + 1] & 0x40) != 0;
        int afc = (data[off + 3] & 0x30) >> 4;
        if (afc == 0 || afc == 2) continue;

        size_t pi = (afc == 1) ? 4 : (size_t)(5 + data[off + 4]);
        if (pi >= 188) continue;

        if (pusi) flush_buffer(session, data, len, &pes, &spans, &nal_count);

        byte_vec_push(&pes, data + off + pi, 188 - pi);
        TSSpan sp = {off, pi, 188 - pi};
        span_vec_push(&spans, sp);
    }

    flush_buffer(session, data, len, &pes, &spans, &nal_count);

    byte_vec_free(&pes);
    span_vec_free(&spans);
    return nal_count;
}

// =============================================================================
// Public API
// =============================================================================

typedef Session cctv_h5e_session;

cctv_h5e_session* cctv_h5e_session_create(void) {
    cctv_h5e_session* s = malloc(sizeof(cctv_h5e_session));
    if (s) session_init(s);
    return s;
}

void cctv_h5e_session_destroy(cctv_h5e_session* s) { free(s); }

void cctv_h5e_session_reset(cctv_h5e_session* s) { if (s) s->new_mode = false; }

int cctv_h5e_decrypt_nal(cctv_h5e_session* s, uint8_t* nal, size_t* io_nal_len) {
    if (!s || !nal || !io_nal_len) return -1;
    session_on_nal(s, nal, io_nal_len);
    return 0;
}

int cctv_h5e_decrypt_ts(cctv_h5e_session* s, uint8_t* ts, size_t ts_len, uint16_t vpid) {
    if (!s || !ts) return -1;
    return (int)decrypt_ts_inplace(ts, ts_len, s, vpid);
}

int cctv_h5e_decrypt_ts_alloc(const uint8_t* ts_in, size_t ts_len, uint8_t** out_ts, size_t* out_len, uint16_t vpid) {
    if (!ts_in || !out_ts || !out_len) return -1;
    uint8_t* buf = malloc(ts_len);
    if (!buf) return -1;
    memcpy(buf, ts_in, ts_len);
    
    Session s;
    session_init(&s);
    decrypt_ts_inplace(buf, ts_len, &s, vpid);
    
    *out_ts = buf;
    *out_len = ts_len;
    return 0;
}

void cctv_h5e_free(void* p) { free(p); }

const char* cctv_h5e_version(void) { return "cctv_h5e pure C11 F5/F1+EPB+AF 1.0"; }

// =============================================================================
// CLI Entry
// =============================================================================

int main(int argc, char** argv) {
    const char* ver = cctv_h5e_version();
    if (argc < 3) {
        fprintf(stderr, "cctv_h5e_decrypt — pure C11 hls_h5e TS decrypt\n %s\nUsage: %s <enc.ts> <out.ts> [--pid 0x100]\n", ver, argv[0]);
        return 1;
    }

    uint16_t vpid = 0x100;
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc) {
            vpid = (uint16_t)strtoul(argv[++i], NULL, 0);
        }
    }

    FILE* fin = fopen(argv[1], "rb");
    if (!fin) { fprintf(stderr, "cannot read %s\n", argv[1]); return 1; }
    fseek(fin, 0, SEEK_END);
    long fsize = ftell(fin);
    fseek(fin, 0, SEEK_SET);
    uint8_t* enc = malloc(fsize);
    fread(enc, 1, fsize, fin);
    fclose(fin);

    uint8_t* out = NULL;
    size_t out_len = 0;
    int rc = cctv_h5e_decrypt_ts_alloc(enc, (size_t)fsize, &out, &out_len, vpid);
    free(enc);

    if (rc != 0 || !out) { fprintf(stderr, "decrypt failed\n"); return 1; }

    FILE* fout = fopen(argv[2], "wb");
    if (!fout) { cctv_h5e_free(out); fprintf(stderr, "cannot write %s\n", argv[2]); return 1; }
    fwrite(out, 1, out_len, fout);
    fclose(fout);
    cctv_h5e_free(out);

    fprintf(stderr, "ok: %zu bytes -> %s\n", out_len, argv[2]);
    return 0;
}
