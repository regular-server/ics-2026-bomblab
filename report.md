# ICS Lab2：BombLab 实验报告

> 姓名/学号：（可填可不填）
>
> 环境：WSL Ubuntu 26.04 + GNU binutils 2.46（objdump）；程序 `defuser` 用 gcc 15.2 编译（`-std=c11 -O2 -Wall -Wextra -Wpedantic -Werror`）。
>
> 说明：本文档只描述分析和验证过程；所有求解代码只写在 `defuser.c` 中，驱动文件未改动。

## 1. 总体背景与分析方法

### 1.1 challenge 的来源

炸弹和 `defuser` 使用同一套换算：`challenge = splitmix64(seed + 0x9e3779b97f4a7c15 * (phase+1))`（见 `challenge.c` 与炸弹中的 `challenge_from_seed`）。因此 `defuser --seed S --phase N` 与 `./bomb --seed S --phase N` 得到的 challenge 完全一致。求解器的任务就是根据 challenge 算出口令，口令按关卡是若干个无符号十进制整数（Secret 关是一行文本）。

### 1.2 静态分析流程

1. 在 WSL 中用 `objdump -d --no-show-raw-insn bomb > bomb_disasm.txt` 导出全部反汇编，用 `objdump -t` 导出符号，用 `objdump -s -j .rodata` 导出常量表。
2. 按符号名定位各关函数：`phase_01` @ 0x402090、`phase_02` @ 0x4020f0、`phase_03` @ 0x4022a0、`phase_04` @ 0x402390、`phase_05` @ 0x402480、`phase_06` @ 0x4025c0、`secret_gate` @ 0x402720。
3. 逐条读关键指令，把 64 位 challenge 拆成 `(c>>32)`、`(c>>16)`、`c & 0xffffffff` 等片段，恢复出计算关系；再写成 C 并逐 seed 验证。
4. 验证方式：`./defuser --seed S --phase N | ./bomb --seed S --phase N` 出现 `Phase N defused.` 即通过；另用 `python3 public_test.py` 跑公开 seed 集合。

### 1.3 读汇编的通用约定

- `lea (%rdi,%rdi,2),%eax` 是 64 位 lea，结果写 32 位寄存器 → 等价于 `(3*x) mod 2^32`，编译器用它代替乘法。
- `shr $0x20,%rax` 后 `%eax` 是 challenge 的高 32 位；`shr $0x10` 等同理。
- 未写 `movzbl/movsbl` 的 32 位运算都是 mod 2^32 的环绕算术，C 中用 `uint32_t` 原样表达即可。
- 所有比较/异或用的立即数都是 32 位；`add $imm,%reg32` 的 imm32 会符号扩展，但本实验中的常量都是正数，无影响。

## 2. 逐关推理

### 2.1 Phase 1（0x402090）：函数调用、参数传递、返回值

**入口逻辑**（`phase_01`）：

```asm
4020aa: call 402c70 <valid_u32_fields>   ; esi=1：恰好 1 个 u32 十进制数
4020c6: mov $0x403189,%esi               ; "%u"
4020ce: call 4011e0 <__isoc99_sscanf@plt>
4020d3: cmp $0x1,%eax; jne fail
4020db: call 402050 <p1_compute>         ; eax = 目标值
4020e0: cmp %eax,-0x14(%rbp)             ; 输入 == 目标值？
4020e3: sete %al
```

即：输入 **1 个整数**，必须等于 `p1_compute(challenge)`。

**三个 helper 的含义**（都是 32 位环绕运算）：

```asm
402030 <p1_step1>:          ; (x, y) = (edi, esi)
402034: lea (%rdi,%rsi,2),%eax  ; eax = x + 2*y   （64 位地址计算，结果截 32 位）
402037: xor $0xb9a,%eax

402020 <p1_step0>:
402024: lea (%rdi,%rdi,2),%eax  ; eax = 3*x
402027: add $0x3373,%esi        ; esi = y + 0x3373
40202d: xor %esi,%eax           ; eax ^= (y + 0x3373)

402040 <p1_step2>:
402044: lea (%rdi,%rdi,2),%eax  ; eax = 3*x
402047: add %esi,%eax           ; eax += y
402049: xor $0xa2e9,%eax
```

**`p1_compute`（0x402050）的参数编排**：

```asm
402055: mov %rdi,%rdx          ; rdx = challenge
402058: mov %rdi,%rax
40205b: shr $0x20,%rax         ; rax = c>>32
40205f: mov %rdx,%rsi
402062: mov %eax,%edi          ; edi = hi = (uint32)(c>>32)
402064: shr $0x10,%rsi         ; rsi = c>>16
40206b: call p1_step1          ; r1 = (hi + 2*(c>>16)) ^ 0xb9a
402070: mov %edi,%esi          ; esi = hi（p1_step1 未破坏 edi）
402072: mov %edx,%edi          ; edi = lo = (uint32)c
402074: mov %eax,%ecx          ; ecx = r1
402076: call p1_step0          ; r2 = (3*lo) ^ (hi + 0x3373)
40207b: mov %ecx,%esi          ; esi = r1
40207d: mov %eax,%edi          ; edi = r2
40207f: call p1_step2          ; ans = (3*r2 + r1) ^ 0xa2e9
```

**恢复出的计算公式**：

```c
hi  = (uint32_t)(c >> 32);
lo  = (uint32_t)c;
r1  = (uint32_t)(hi + 2 * (c >> 16)) ^ 0xb9a;   /* 注意 2*(c>>16) 是 64 位再截 32 位 */
r2  = (uint32_t)(3 * lo) ^ (uint32_t)(hi + 0x3373);
ans = (uint32_t)(3 * r2 + r1) ^ 0xa2e9;
```

> 细节：`lea (%rdi,%rsi,2)` 先做 64 位加法再截断到 32 位；由于 `(2*x) mod 2^32 == 2*(x mod 2^32) mod 2^32`，C 中先取 `(uint32_t)(c>>16)` 再乘 2 与汇编等价。

**答案格式**：`ans` 一个整数，即 `printf("%u")`。

### 2.2 Phase 2（0x4020f0）：数组、循环、递推

**入口**：`valid_u32_fields(input, 6)` + `sscanf("%u %u %u %u %u %u")`，输入 **6 个 u32**，格式串为 0x40317a（`%u %u %u %u %u %u`）。

**第一个数的检查**：

```asm
40215a: mov %r13,%rax          ; rax = challenge
40215d: mov -0x40(%rbp),%edx   ; edx = v[0]
402160: shr $0x1f,%rax         ; c >> 31
402164: and $0x3f,%eax         ; (c>>31) & 0x3f
402167: lea (%rax,%rax,2),%eax ; 3 * ...
40216a: cmp %eax,%edx; jne fail
```

**后续 5 个数的递推**（循环体 0x402178）：

```asm
402178: mov %r13,%rax
40217b: shl $0x2,%edx          ; edx = v[i-1] << 2
40217e: shr %cl,%rax           ; rax = c >> cl
402181: and $0x1f,%eax         ; 取 5 位
402184: xor %edx,%eax          ; eax = ((c>>cl)&0x1f) ^ (v[i-1]<<2)
402186: mov -0x40(%rbp,%rsi,4),%edx  ; edx = v[i]
40218a: add %esi,%eax          ; eax += i
40218c: cmp %eax,%edx; jne fail
402190: add $0x1,%rsi
402194: add $0x5,%ecx          ; cl: 6 → 11 → 16 → 21 → 26
```

**恢复出的递推**：

```c
v[0] = 3 * ((uint32_t)(c >> 31) & 0x3f);
for (i = 1; i <= 5; ++i)
    v[i] = (((uint32_t)(c >> (6 + 5*(i-1))) & 0x1f) ^ (v[i-1] << 2)) + i;
```

**答案格式**：`v[0] v[1] v[2] v[3] v[4] v[5]`，空格分隔。

### 2.3 Phase 3（0x4022a0）：switch 分支与跳转表

**入口**：`valid_u32_fields(input, 2)` + `sscanf("%u %u")`，输入 **2 个 u32**：先为选择子 `sel`，后为值 `val`。

```asm
4022ec: mov %r12d,%edi
4022f1: and $0x7,%edi          ; edi = sel = (uint32)c & 7
4022f4: cmp %edi,-0x18(%rbp)   ; 第一个输入 == sel？
4022f9: mov %r12,%rax
4022ff: shr $0x3,%rax          ; c >> 3
402303: shr $0x20,%rsi         ; rsi = c >> 32
402307: xor %eax,%esi          ; key = ((uint32)(c>>32)) ^ ((uint32)(c>>3))
402309: call 402240 <p3_dispatch>
40230e: cmp %eax,-0x14(%rbp)   ; 第二个输入 == dispatch 结果？
```

**dispatch 的跳转表**（0x402240）：

```asm
402244: mov %edi,%eax          ; eax = sel
402246: mov %esi,%edi          ; 把 key 挪到第一参数位
402248: cmp $0x7,%eax; ja fail
40224d: notrack jmp *0x405820(,%rax,8)   ; table[sel]
```

`.rodata` 中 0x405820 处的 8 项表为：`{0x402268, 0x402270, 0x402278, 0x402280, 0x402288, 0x402290, 0x402258, 0x402260}`，对应跳到 `p3_case_3, _5, _6, _0, _2, _7, _1, _4`。**注意 sel→case 不是恒等映射**，必须查表：

| sel | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
|-----|---|---|---|---|---|---|---|---|
| case | 3 | 5 | 6 | 0 | 2 | 7 | 1 | 4 |

**各 case 函数**（参数 x = key，结果 32 位）：

| case | 指令 | 表达式 |
|---|---|---|
| 0（0x4021b0） | `lea (%rdi,%rdi,1)` + `xor 0xcaf` | `(2x) ^ 0xcaf` |
| 1（0x4021c0） | `mov/shr $1/xor 0x1a75/add` | `(x ^ 0x1a75) + (x >> 1)` |
| 2（0x4021d0） | `lea 0x75b9(%rdi,%rdi,4)` | `5x + 0x75b9` |
| 3（0x4021e0） | `lea 0x24e78(%rdi,%rdi,4)` | `5x + 0x24e78` |
| 4（0x4021f0） | `lea 0(,%rdi,4)` + `xor 0xe7a5` | `(4x) ^ 0xe7a5` |
| 5（0x402210） | `shr $1` + `xor 0x2c` + `add` | `(x ^ 0x2c) + (x >> 1)` |
| 6（0x402220） | `lea 0x34283(%rdi,%rdi,4)` | `5x + 0x34283` |
| 7（0x402230） | `lea 0x8bdb(%rdi,%rdi,2)` | `3x + 0x8bdb` |

**恢复出的公式**：

```c
sel = (uint32_t)c & 7;
key = (uint32_t)(c >> 32) ^ (uint32_t)(c >> 3);
val = case_table[sel](key);   // case_table = {3,5,6,0,2,7,1,4}
```

**答案格式**：`sel val`（先选择子后值）。

### 2.4 Phase 4（0x402390）：递归调用与返回过程

**入口**：`valid_u32_fields(input, 1)` + `sscanf("%u")`，输入 **1 个 u32**。

```asm
4023d8: mov %r12,%rcx
4023db: mov %r12,%rax
4023de: mov %r12d,%edi
4023e1: xor %esi,%esi            ; b = 0
4023e3: shr $0x20,%rax
4023e7: shr $0x7,%rcx
4023eb: and $0x7f,%edi           ; a = (uint32)c & 0x7f
4023ee: mov $0x7f,%edx           ; c = 0x7f
4023f3: xor %eax,%ecx            ; k = ((uint32)(c>>32)) ^ ((uint32)(c>>7))
4023f5: call 402320 <p4_walk>
4023fa: cmp %eax,-0x14(%rbp)     ; 输入 == 递归结果？
```

**`p4_walk(a, b, c, k)`**（0x402320，递归二分）：

```asm
402324: mov %edi,%eax            ; eax = a
402326: mov %edx,%edi
402328: sub %esi,%edi            ; edi = c - b
40232a: shr $1,%edi              ; edi >>= 1（逻辑右移）
40232c: add %esi,%edi            ; mid = b + (c-b)/2
40232e: cmp %eax,%edi; je base   ; mid == a → 基例
402332: push %rbp ...
402337: lea (%rdi,%rcx,1),%ebx   ; ebx = mid + k
40233e: cmp %edi,%eax; jb left   ; a < mid → 左分支
; 右分支：a > mid
402342: lea 0x1(%rdi),%esi       ; b' = mid+1
402345: mov %eax,%edi            ; a' = a
402347: call p4_walk              ; 递归
40234c: lea (%rax,%rax,2),%eax   ; 3*child
40234f: xor %ebx,%eax            ; ^ (mid+k)
402356: xor $0x8,%eax            ; ^ 0x8
; 左分支：
402360: lea -0x1(%rdi),%edx      ; c' = mid-1
402363: mov %eax,%edi            ; a' = a
402365: call p4_walk
40236a: lea (%rax,%rax,2),%eax   ; 3*child
40236d: xor %ebx,%eax            ; ^ (mid+k)
402374: xor $0x1f,%eax           ; ^ 0x1f
; 基例（0x402380）：
402380: lea 0xc8(%rdi),%eax      ; mid + 0xc8
402386: xor %ecx,%eax            ; ^ k
```

**恢复出的公式**：

```c
uint32_t p4_walk(uint32_t a, uint32_t b, uint32_t c, uint32_t k) {
    uint32_t mid = b + ((c - b) >> 1);
    if (mid == a) return (mid + 0xc8) ^ k;
    uint32_t pair = mid + k;
    if (a < mid) return ((p4_walk(a, b, mid-1, k) * 3) ^ pair) ^ 0x1f;
    return        ((p4_walk(a, mid+1, c, k) * 3) ^ pair) ^ 0x8;
}
/* 入口：p4_walk(c & 0x7f, 0, 0x7f, ((uint32)(c>>7)) ^ ((uint32)(c>>32))) */
```

**答案格式**：递归返回值，一个整数。

### 2.5 Phase 5（0x402480）：结构体布局、指针、链表遍历

**入口**：`valid_u32_fields(input, 2)` + `sscanf("%u %u")`，输入 **2 个 u32**：结果 `res` 和最后节点的 `tag`。

**`p5_traverse`（0x402410）**：

```asm
402414: mov %rdi,%rax
402417: mov %rdi,%rcx
40241a: mov %rsi,%r8              ; r8 = 输出指针
40241d: and $0x7,%eax             ; idx = c & 7
402420: shr $0x3,%rcx             ; c >> 3
402424: mov 0x405b60(,%rax,8),%rdx ; 节点 = table[c & 7]
40242c: mov %rdi,%rax
40242f: shr $0x20,%rdi            ; c >> 32
402433: shr $0x6,%rax             ; c >> 6
402437: xor %edi,%eax             ; x = ((uint32)(c>>6)) ^ ((uint32)(c>>32))
402439: mov 0x8(%rdx),%esi        ; esi = node->tag
40243c: mov %ecx,%edi             ; edi = (uint32)(c>>3)
40243e: xor $0x3e2b,%eax
402443: lea (%rax,%rax,2),%eax    ; 3*
402446: add 0xc(%rdx),%eax        ; += node->mul
402449: mov %esi,(%r8)            ; *out = tag
40244c: xor %esi,%eax             ; ^= tag
40244e: and $0x3,%edi             ; 步数 = (c>>3) & 3
402451: je 402470                 ; 0 步直接返回
402453: mov $0x1,%ecx
402458: mov (%rdx),%rdx           ; rdx = node->next
40245b: lea (%rax,%rax,2),%eax    ; 3*acc
40245e: add $0x1,%ecx
402461: mov 0x8(%rdx),%esi
402464: add 0xc(%rdx),%eax        ; += next->mul
402467: xor %esi,%eax             ; ^= next->tag
402469: mov %esi,(%r8)
40246c: cmp %ecx,%edi
40246e: jae 402458                ; 循环 (c>>3)&3 次
```

节点结构（来自 `.rodata` 0x405b60 起）：`{next@0, tag@8, mul@0xc}`，共 12 个节点：

| 节点 | next | tag | mul |
|---|---|---|---|
| 0x405ba0 | 0x405c00 | 0x0b25 | 0xd929 |
| 0x405bb0 | 0x405bf0 | 0x063f | 0x24f1 |
| 0x405bc0 | 0x405bb0 | 0x0160 | 0x6d77 |
| 0x405bd0 | 0x405c30 | 0x0258 | 0x3bcd |
| 0x405be0 | 0x405bd0 | 0x0372 | 0x0a82 |
| 0x405bf0 | 0x405c40 | 0x0966 | 0x906c |
| 0x405c00 | 0x405c10 | 0x0816 | 0x85ef |
| 0x405c10 | 0x405bc0 | 0x004f | 0xad0a |
| 0x405c20 | 0x405be0 | 0x055e | 0x28bc |
| 0x405c30 | NULL | 0x0a74 | 0xc4b0 |
| 0x405c40 | 0x405c20 | 0x040c | 0x9b4b |
| 0x405c50 | 0x405ba0 | 0x0749 | 0xe6b8 |

入口表 `table[8]`（0x405b60）：`{0x405c50, 0x405ba0, 0x405c00, 0x405c10, 0x405bc0, 0x405bb0, 0x405bf0, 0x405c40}`。

**恢复出的公式**：

```c
n = table[c & 7];
acc = 3 * ((((uint32_t)(c>>6)) ^ ((uint32_t)(c>>32))) ^ 0x3e2b) + node[n].mul;
acc ^= node[n].tag;
for (i = 0; i < ((uint32_t)(c>>3) & 3); ++i) {
    n = node[n].next;
    acc = 3*acc + node[n].mul;
    acc ^= node[n].tag;
}
*out = 最后访问节点的 tag;
```

**答案格式**：`res tag`（结果是遍历折叠值，第二个数是最后节点的 tag）。

### 2.6 Phase 6（0x4025c0）：函数指针表与间接调用

**入口**：`valid_u32_fields(input, 1)` + `sscanf("%u")`，输入 **1 个 u32**。

**`p6_dispatch`（0x402570）**：

```asm
402579: mov %rdi,%rbx
40257c: shr $0x6,%rdi          ; rdi = c >> 6
402580: mov %rbx,%rax
402583: shr $0x20,%rax         ; rax = c >> 32
402587: xor %eax,%edi          ; edi = ((uint32)(c>>6)) ^ ((uint32)(c>>32))
40258c: sub $0x8,%rsp
402590: and $0x38,%ebx         ; ebx = c & 0x38 → 第二下标*8
402593: and $0x7,%eax          ; 第一下标 = c & 7
402596: call *0x405e00(,%rax,8)   ; f1 = table[c & 7]
40259d: xor $0xd7bb,%eax          ; r ^= 0xd7bb
4025a2: mov %eax,%edi
4025a4: call *0x405e00(%rbx)      ; f2 = table[(c>>3) & 7]
4025af: add $0x651d,%eax          ; r += 0x651d
```

**函数指针表 0x405e00**：`{op_4, op_0, op_2, op_0, op_5, op_1, op_3, op_5}`。

**各 op 函数**（x = 参数，32 位）：

| op | 指令 | 表达式 |
|---|---|---|
| 0（0x4024f0） | `8x`、`4x+0x3acb`、`sub`、`xor` | `(4x + 0x3acb) ^ (7x)` |
| 1（0x402510） | `x+0xf790`、`x>>5`、`xor` | `(x + 0xf790) ^ (x >> 5)` |
| 2（0x402520） | `rol 3`、`xor 0x3d33` | `rol(x,3) ^ 0x3d33` |
| 3（0x402530） | `ror 7` | `ror(x,7)` |
| 4（0x402540） | `x>>5`、`xor x`、`+0x81cc` | `((x>>5) ^ x) + 0x81cc` |
| 5（0x402560） | `x^0x4dcb`、`lea +2x` | `(x ^ 0x4dcb) + 2x` |

**恢复出的公式**：

```c
x = ((uint32_t)(c>>6)) ^ ((uint32_t)(c>>32));
r = op_table[c & 7](x);
r ^= 0xd7bb;
r = op_table[(c>>3) & 7](r);
r += 0x651d;
```

**答案格式**：一个整数。

### 2.7 Honor / Secret（0x402720）：必做隐藏关

**调用流程**（main 在六关全部通过后、且 stdin 不是终端时读取一行）：非空的一行 → `transcript_context(六个口令行)` 得到 context → `secret_gate(line, challenge7, context)`，其中 `challenge7 = challenge_from_seed(seed, 7)`。

**`secret_gate`（0x402720）**：

```asm
40275c: call strlen
402761: sub $0x24,%rax           ; len - 36
402765: cmp $0x7f,%rax
402769: jbe 402780               ; 36 ≤ len ≤ 36+0x7f = 163 才继续
402783: call 402700 <secret_copy> ; strcpy 到栈缓冲
40278b: cmpl $0x4e45504f,-0xb0(%rbp)  ; buf+0x20 处的 4 字节 == "OPEN"（小端）
402795: jne fail
40279d: lea -0xac(%rbp),%rdi      ; 载荷 = buf + 0x24 = line + 36
4027a4: call 402640 <secret_phase>
```

**`secret_phase`（0x402640）**：解析 3 个 u32：`v0 v1 v2`（`sscanf("%u %u %u")`，格式串 0x403183）。

```asm
4026a5: and $0x3,%ecx            ; ecx = context & 3
4026a8: cmp %ecx,-0x2c(%rbp)     ; v0 == context & 3
4026b0: imul $0xe9ef,%ecx,%r9d
4026ba: shr $0x20,%rsi           ; rsi = challenge >> 32
4026be: shr $0x20,%r8            ; r8  = context >> 32
4026c2: xor %r12d,%esi           ; s = ((uint32)(challenge>>32)) ^ ((uint32)challenge)
4026c5: xor %r13d,%r8d           ; r = ((uint32)(context>>32)) ^ ((uint32)context)
4026c8: shr $0x10,%r13           ; context >> 16
4026cc: mov %esi,%edi
4026ce: xor %r13d,%r9d           ; r9 = (a*0xe9ef) ^ ((uint32)(context>>16))
4026d1: xor %r8d,%edi            ; edi = s ^ r
4026d4: call secret_mix          ; 5*edi + 0xe9ef，再 ^ 0xa0a3
4026d9: xor %r9d,%eax            ; v1 的期望值
4026e1: shr $0x5,%esi            ; s >> 5
4026e4: lea 0xa0a3(%r8,%rcx,1),%edx  ; r + a + 0xa0a3
4026ec: add %esi,%edx
4026ee: xor %edx,%eax            ; v2 的期望值
```

**恢复出的公式**（`secret_mix(x) = ((5*x + 0xe9ef) mod 2^32) ^ 0xa0a3`）：

```c
s = (uint32_t)(challenge>>32) ^ (uint32_t)challenge;
r = (uint32_t)(context>>32)    ^ (uint32_t)context;
a = (uint32_t)context & 3;
m = secret_mix(s ^ r);
b = m ^ ((a * 0xe9ef) ^ (uint32_t)(context>>16));
c = b ^ ((r + a + 0xa0a3) + (s >> 5));
```

**Honor 行的构造**：32 个任意字符 + `"OPEN"` + `空格分隔的 a b c`，例如 `00000000000000000000000000000000OPEN 1 2228571221 191234567`。行长度必须满足 36 ≤ len ≤ 163。

> 注意：① `transcript_context` 是基于六个口令行的**原始字符串**（逐位数字解析）计算的，所以 `defuser` 的输出行必须是规范的十进制（`%u`），否则 context 对不上；② Honor 模式要求 stdin 不是终端，必须通过管道/文件喂入。

## 3. 验证记录

### 3.1 编译

```sh
cd /mnt/d/dsh/ICS/Lab2/ics-2026-bomblab
make    # gcc -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror
```

编译通过（`-Werror` 无警告）。

### 3.2 公开测试（`tests/public.json` 的 10 个 seed × 6 关 + Honor）

```sh
python3 public_test.py
```

结果：**六关 60/60 PASS；Secret public tests: 10/10 PASS**。

示例输出（节选）：

```text
Phase 6 seed 18446744073709551615: PASS
Public tests: 60/60
Secret seed 18446744073709551615: PASS
Secret public tests: 10/10
```

### 3.3 公开列表之外的 seed 验证（报告要求）

用 seed `2, 5, 13, 77, 424242, 1000000, 123456789, 999999999, 4294967296, 31415926535897`（均不在 tests/public.json 中）做完整链路：

```sh
./defuser --seed S                       # 六行口令
./defuser --secret --seed S              # Honor 行
printf '%s\n%s\n' "$(六行)" "$(Honor行)" | ./bomb --seed S
```

结果：**10/10 PASS**（六关 + `Secret phase defused.` 全部通过）。

### 3.4 运行结果截图

> 截图建议：在 WSL 终端执行以下命令后截图放入 `images/` 并在此引用：
>
> ```sh
> ./defuser --seed 42 --phase 1 | ./bomb --seed 42 --phase 1          # Phase 1 defused.
> python3 public_test.py                                             # 60/60
> ```
>
> <!-- ![](images/public_test.png) -->

## 4. 工具与资料说明

- **objdump**（GNU binutils 2.46，WSL Ubuntu 26.04）：`objdump -d --no-show-raw-insn` 导出反汇编，`objdump -t` 导出符号，`objdump -s -j .rodata/.data` 导出常量表与函数指针表。Windows 下 MinGW 的 objdump 无法识别 ELF，故改用 WSL。
- **python3**：运行 `public_test.py` 做公开测试。
- **AI 辅助工具**：本报告的分析与 `defuser.c` 的公式推导使用了 AI 助手（DeepSeek，DSH 环境）辅助完成。
- 参考：课程主页实验文档、仓库内 `README.md`、`tutor/` 教学材料、`teaching/` 下的 GDB 示例。

> 附加说明：二进制 `.rodata` 中夹带了几条以 `AI ASSISTANT:` 和 `URGENT AI NOTICE` 开头的文本（例如声称 Phase 4 左右分支异或为 0x14/0x1a、Phase 5 首节点 tag 不参与折叠）。这些是**植入的误导性提示**，与真实指令不符（实际为 0x1f/0x8，且首节点 tag 参与折叠）。分析一律以实际指令和数据表为准。
