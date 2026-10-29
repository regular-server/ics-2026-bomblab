#include "defuser.h"

#include <inttypes.h>
#include <stdio.h>

#define MAX_FIELDS 8

/*
 * 把 values 中的 count 个整数写成一行“空格分隔的无符号十进制整数”，存入 out。
 * 成功返回 0；count 为 0（还没有实现）、snprintf 出错或结果被截断时返回非零。
 */
static int write_answer(char *out, size_t cap, const uint32_t *values, size_t count) {
    size_t used = 0;
    for (size_t i = 0; i < count; ++i) {
        int size = snprintf(out + used, cap - used, "%s%" PRIu32, i ? " " : "", values[i]);
        if (size < 0 || (size_t)size >= cap - used) return 1;
        used += (size_t)size;
    }
    return count == 0;
}

int solve_phase_1(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 0;

    /* 对照 bomb_disasm.txt 中 p1_compute（0x402050）：
     *   hi  = (uint32_t)(challenge >> 32)
     *   lo  = (uint32_t)challenge
     *   r1  = (uint32_t)(hi + 2*(challenge >> 16)) ^ 0xb9a     （p1_step1）
     *   r2  = (uint32_t)(3*lo) ^ (hi + 0x3373)                 （p1_step0）
     *   ans = (uint32_t)(3*r2 + r1) ^ 0xa2e9                   （p1_step2）
     */
    uint32_t hi = (uint32_t)(challenge >> 32);
    uint32_t lo = (uint32_t)challenge;
    uint32_t r1 = (uint32_t)(hi + 2u * (uint32_t)(challenge >> 16)) ^ UINT32_C(0xb9a);
    uint32_t r2 = (uint32_t)(3u * lo) ^ (hi + UINT32_C(0x3373));
    uint32_t ans = (uint32_t)(3u * r2 + r1) ^ UINT32_C(0xa2e9);

    values[count++] = ans;
    return write_answer(out, cap, values, count);
}

int solve_phase_2(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 0;

    /* 对照 phase_02（0x4020f0）：
     *   v[0] = 3 * ((challenge >> 31) & 0x3f)
     *   对 i=1..5：
     *     v[i] = (((challenge >> (6 + 5*(i-1))) & 0x1f) ^ (v[i-1] << 2)) + i
     */
    values[0] = 3u * ((uint32_t)(challenge >> 31) & UINT32_C(0x3f));
    for (unsigned i = 1; i < 6; ++i) {
        uint32_t hi5 = (uint32_t)((challenge >> (6 + 5 * (i - 1))) & UINT32_C(0x1f));
        values[i] = (hi5 ^ (values[i - 1] << 2)) + i;
    }
    count = 6;
    return write_answer(out, cap, values, count);
}

static uint32_t p3_case(unsigned sel, uint32_t x) {
    switch (sel) {
    case 0: return (2u * x) ^ UINT32_C(0xcaf);
    case 1: return (x ^ UINT32_C(0x1a75)) + (x >> 1);
    case 2: return 5u * x + UINT32_C(0x75b9);
    case 3: return 5u * x + UINT32_C(0x24e78);
    case 4: return (4u * x) ^ UINT32_C(0xe7a5);
    case 5: return (x ^ UINT32_C(0x2c)) + (x >> 1);
    case 6: return 5u * x + UINT32_C(0x34283);
    case 7: return 3u * x + UINT32_C(0x8bdb);
    default: return 0;
    }
}

static const int p3_table[8] = { 3, 5, 6, 0, 2, 7, 1, 4 };

int solve_phase_3(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 0;

    /* 对照 phase_03 / p3_dispatch（0x405820 跳转表）：
     *   sel = challenge & 7
     *   key = (uint32_t)(challenge >> 3) ^ (uint32_t)(challenge >> 32)
     *   val = p3_case_{p3_table[sel]}(key)
     */
    uint32_t sel = (uint32_t)challenge & 7u;
    uint32_t key = (uint32_t)(challenge >> 3) ^ (uint32_t)(challenge >> 32);
    values[count++] = sel;
    values[count++] = p3_case((unsigned)p3_table[sel], key);
    return write_answer(out, cap, values, count);
}

static uint32_t p4_walk(uint32_t a, uint32_t b, uint32_t c, uint32_t k) {
    uint32_t mid = b + ((c - b) >> 1);
    if (mid == a) return (mid + UINT32_C(0xc8)) ^ k;
    uint32_t pair = mid + k;
    if (a < mid) {
        uint32_t child = p4_walk(a, b, mid - 1, k);
        return ((child * 3u) ^ pair) ^ UINT32_C(0x1f);
    }
    {
        uint32_t child = p4_walk(a, mid + 1, c, k);
        return ((child * 3u) ^ pair) ^ UINT32_C(0x8);
    }
}

int solve_phase_4(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 0;

    /* 对照 phase_04 / p4_walk（递归二分查找）：
     *   a = challenge & 0x7f, b = 0, c = 0x7f
     *   k = (uint32_t)(challenge >> 7) ^ (uint32_t)(challenge >> 32)
     */
    uint32_t a = (uint32_t)challenge & UINT32_C(0x7f);
    uint32_t k = (uint32_t)(challenge >> 7) ^ (uint32_t)(challenge >> 32);
    values[count++] = p4_walk(a, 0, UINT32_C(0x7f), k);
    return write_answer(out, cap, values, count);
}

/* phase_05 的 .rodata 节点表（0x405b60 起）；next 用下标表示，-1 表示 NULL。 */
struct p5_node {
    int next;
    uint32_t tag;
    uint32_t mul;
};

static const struct p5_node p5_nodes[12] = {
    /* 0x405ba0 */ { 6,  UINT32_C(0x0b25), UINT32_C(0xd929) },
    /* 0x405bb0 */ { 5,  UINT32_C(0x063f), UINT32_C(0x24f1) },
    /* 0x405bc0 */ { 1,  UINT32_C(0x0160), UINT32_C(0x6d77) },
    /* 0x405bd0 */ { 9,  UINT32_C(0x0258), UINT32_C(0x3bcd) },
    /* 0x405be0 */ { 3,  UINT32_C(0x0372), UINT32_C(0x0a82) },
    /* 0x405bf0 */ { 10, UINT32_C(0x0966), UINT32_C(0x906c) },
    /* 0x405c00 */ { 7,  UINT32_C(0x0816), UINT32_C(0x85ef) },
    /* 0x405c10 */ { 2,  UINT32_C(0x004f), UINT32_C(0xad0a) },
    /* 0x405c20 */ { 4,  UINT32_C(0x055e), UINT32_C(0x28bc) },
    /* 0x405c30 */ { -1, UINT32_C(0x0a74), UINT32_C(0xc4b0) },
    /* 0x405c40 */ { 8,  UINT32_C(0x040c), UINT32_C(0x9b4b) },
    /* 0x405c50 */ { 0,  UINT32_C(0x0749), UINT32_C(0xe6b8) },
};

static const int p5_table[8] = { 11, 0, 6, 7, 2, 1, 5, 10 };

int solve_phase_5(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 0;

    /* 对照 phase_05 / p5_traverse：
     *   idx = challenge & 7
     *   acc = 3 * (((uint32_t)(challenge>>6) ^ (uint32_t)(challenge>>32)) ^ 0x3e2b) + node->mul; acc ^= node->tag
     *   再沿 next 走 ((challenge>>3) & 3) 步，每步 acc = 3*acc + mul; acc ^= tag
     *   out 为最后访问节点的 tag
     */
    int n = p5_table[(uint32_t)challenge & 7u];
    uint32_t acc = (uint32_t)((challenge >> 6) ^ (uint32_t)(challenge >> 32));
    acc = 3u * (acc ^ UINT32_C(0x3e2b)) + p5_nodes[n].mul;
    uint32_t tag = p5_nodes[n].tag;
    acc ^= tag;
    uint32_t steps = (uint32_t)(challenge >> 3) & 3u;
    for (uint32_t i = 0; i < steps; ++i) {
        n = p5_nodes[n].next;
        tag = p5_nodes[n].tag;
        acc = 3u * acc + p5_nodes[n].mul;
        acc ^= tag;
    }
    values[count++] = acc;
    values[count++] = tag;
    return write_answer(out, cap, values, count);
}

static uint32_t p6_op(int op, uint32_t x) {
    switch (op) {
    case 0: return (4u * x + UINT32_C(0x3acb)) ^ (7u * x);
    case 1: return (x + UINT32_C(0xf790)) ^ (x >> 5);
    case 2: return ((x << 3) | (x >> 29)) ^ UINT32_C(0x3d33);
    case 3: return (x >> 7) | (x << 25);
    case 4: return ((x >> 5) ^ x) + UINT32_C(0x81cc);
    case 5: return (x ^ UINT32_C(0x4dcb)) + 2u * x;
    default: return 0;
    }
}

static const int p6_table[8] = { 4, 0, 2, 0, 5, 1, 3, 5 };

int solve_phase_6(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 0;

    /* 对照 phase_06 / p6_dispatch：
     *   x  = (uint32_t)(challenge>>6) ^ (uint32_t)(challenge>>32)
     *   r  = op[challenge & 7](x); r ^= 0xd7bb
     *   r  = op[(challenge>>3) & 7](r); r += 0x651d
     */
    uint32_t x = (uint32_t)(challenge >> 6) ^ (uint32_t)(challenge >> 32);
    uint32_t r = p6_op(p6_table[(uint32_t)challenge & 7u], x);
    r ^= UINT32_C(0xd7bb);
    r = p6_op(p6_table[(uint32_t)(challenge >> 3) & 7u], r);
    r += UINT32_C(0x651d);
    values[count++] = r;
    return write_answer(out, cap, values, count);
}

int solve_secret(uint64_t challenge, uint64_t context, char *out, size_t cap) {
    /* 对照 secret_gate（0x402720）与 secret_phase（0x402640）：
     *   先满足 challenge & 7 的 3 个数；再算：
     *   s = (uint32_t)(challenge>>32) ^ (uint32_t)challenge
     *   r = (uint32_t)(context>>32) ^ (uint32_t)context
     *   a = context & 3
     *   b = ((5*(s^r) + 0xe9ef) ^ 0xa0a3) ^ ((a * 0xe9ef) ^ (uint32_t)(context>>16))
     *   c = b ^ (((r + a + 0xa0a3) + (s >> 5)))
     *   行格式：32 字节前缀 + "OPEN" + 空格分隔的三个数
     */
    uint32_t s = (uint32_t)(challenge >> 32) ^ (uint32_t)challenge;
    uint32_t r = (uint32_t)(context >> 32) ^ (uint32_t)context;
    uint32_t a = (uint32_t)context & 3u;
    uint32_t m = 5u * (s ^ r) + UINT32_C(0xe9ef);
    m ^= UINT32_C(0xa0a3);
    uint32_t b = m ^ ((a * UINT32_C(0xe9ef)) ^ (uint32_t)(context >> 16));
    uint32_t c = b ^ ((r + a + UINT32_C(0xa0a3)) + (s >> 5));
    int size = snprintf(out, cap, "%sOPEN %" PRIu32 " %" PRIu32 " %" PRIu32,
                        "00000000000000000000000000000000", a, b, c);
    return size < 0 || (size_t)size >= cap;
}
