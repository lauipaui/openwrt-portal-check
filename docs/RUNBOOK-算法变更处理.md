# Runbook：校园网门户算法变更时怎么办

## 一句话

**现在全自动。** 门户会把当前算法模块主动下发，模块里带明文 key/IV，
路由器上的 `damod` 解包提取、`cipher-helper` 直接用，不需要 hook App，
也不需要人工补密钥。

> **重要更正（2026-10-09 晚）**：本文档早前写着"密钥不在门户下发的模块里、
> 静态分析拿不到"。那个结论是**错的**，原因是当时模块载荷还没解开
> （LZMA 参数没试对，所以在密文里搜明文自然 0 命中）。
> 载荷解开后，48 字节 key 就明晃晃躺在 `.data` 里。详见下文。

---

## 一、原理

### 1. 门户会主动下发当前算法模块

用**全零 UUID** 发一次请求（`Algo-ID: 00000000-0000-0000-0000-000000000000`），
门户不看请求的 Algo-ID，直接返回**它当前想要的**那个模块。

实测：三次连续请求返回逐字节相同（MD5 `d564652cc245012e16478b938f32ca20`，18903 B）；
换成旧 UUID、全零 UUID，返回内容完全一样。

所以"门户换算法了"这件事，客户端自己就能探测到，不需要抓包也不需要 App。

### 2. 容器格式

```
"001" + lenByte + hex(lenByte 个字符) + "$" + UUID(36) + "]" + payload
```

- 前 3 字节固定 `"001"`
- 第 4 字节是后面十六进制串的长度（偶数）
- `$` 之后 36 字节是算法 UUID，`]` 之后是载荷

### 3. type-0 载荷解码管线

```
props  = payload[0:4]
szField= LE32(payload[4:8])          # 高 4 位 = type，低 28 位 = 解压后大小
type   = szField >> 28
size   = szField & 0x0FFFFFFF

data = payload[8:]
for i = len(data)-2 downto 0:        # 反向异或链，一行代码
    data[i] ^= data[i+1]

LZMA 头 = 0x5d + props + LE64(size)  # props 里的 4 字节原样用
ELF = LZMA_Decompress(LZMA 头 + data)
```

**坑**：解压时**不能去掉尾部填充**，必须把异或后的完整数据喂进去，
否则报 `unexpected EOF`。

还原出来的是 ELF64、`e_machine=0xB7`（ARM64）的 `.so`。

### 4. ★ 密钥取法：`.data+249` 的 7 字节元数据块

模块自己的初始化代码（两个样本都在 **vaddr `0x1f30`**）硬编码读 `.data+249`，
从里面拿 key 的位置和长度：

| 偏移 | 含义 | 9ABF4D29 | 3D74E736 |
| --- | --- | --- | --- |
| `meta[0]` | 块大小 / IV 长度（8=DES，16=AES） | `0x08` | `0x10` |
| `meta[1]` | 未解 | `0x4a` | `0xbd` |
| `meta[2]` | **key 长度** | `0x30` = 48 | `0x20` = 32 |
| `meta[3]` | 未解 | `0xc8` | `0x40` |
| `meta[4]` | 未解 | `0x36` | `0x2e` |
| `meta[5]` | **key 相对 `.data` 的偏移** | `0xa1` = 161 | `0x82` = 130 |
| `meta[6]` | 标志字节（被写进返回结构的 `+0`） | `0xdd` | `0x55` |

```
key = .data[ meta[5] : meta[5]+meta[2] ]
iv  = .data[ meta[5]+meta[2] : +16 ]        # IV 紧跟在 key 后面
```

模块还自带完整性校验：`meta[0] + meta[2] + meta[5] <= 0xf9`（249）。
不满足就返回 0。`damod` 照搬了这条校验，损坏的下载会被拒绝而不是被误解析。

### 5. 模板名 → 算法实现

模板名在 `.dynstr` 里，形如 `tpl_*.so`：

| 模板名 | key 长度 | 算法 |
| --- | --- | --- |
| `tpl_des_iv.so` | 48 | double 3DES-CBC（同 BB2EA626 那套的 DES 版，即 9ABF4D29 型） |
| `tpl_aes_cbc.so` | 32 | double AES-128-CBC（BB2EA626 型） |

---

## 二、工具

### `damod`（解包 + 提取）

源码 `unpack/damod/main.go`，静态 mipsle 二进制已部署到 `/root/portal/damod`。

```sh
/root/portal/damod <module.bin>            # 人类可读
/root/portal/damod -env <module.bin>       # shell 变量（DAMOD_UUID/TEMPLATE/KEY/IV...）
/root/portal/damod -json <module.bin>      # JSON
/root/portal/damod -o out.so <module.bin>  # 顺便把还原出的 ELF 落盘
```

### `cipher-helper` 的动态密钥模式

新增 `encrypt-raw` / `decrypt-raw`，**直接用模块里提取出来的 key/IV**，
所以门户换密钥时不需要重新编译：

```sh
cipher-helper encrypt-raw tpl_des_iv.so  <keyhex> <ivhex>
cipher-helper decrypt-raw tpl_aes_cbc.so <keyhex> <ivhex>
```

源码 `cipherhelper/cipher/raw.go`（模板名 + key 长度 → 具体实现）。

---

## 三、算法真的变了，现在怎么做

### 自动部分（已实现，无需干预）

1. `detect_portal_algorithm()` 用全零 UUID 探测门户当前算法
2. 与本地 `ALGO_ID` 不一致时：
   - 打日志 `Portal algorithm mismatch: the portal now serves <新ID> but ALGO_ID is <旧ID>`
   - 把模块存成 `/root/portal/damod-update.bin.<新ID>`（0600）
   - **调 `damod -env` 解包，写 `/root/portal/algo-<新ID>.env`（0600）**
   - 报告模板名、key 长度
   - 用 `cipher-helper encrypt-raw` 试跑一次，判定"已支持 / 需要新实现"并打日志

日志长这样：

```
Portal module <新ID> uses tpl_des_iv.so (key length 48); parameters written to /root/portal/algo-<新ID>.env.
cipher-helper already drives tpl_des_iv.so, so this migration only needs the new key material.
```

### 人工部分

```sh
# 1. 看日志和提取结果
logread -e portal-auto-auth | grep -E 'mismatch|Portal module|cipher-helper'
cat /root/portal/algo-<新ID>.env

# 2. 助手已支持（日志说 "already drives"）→ 改配置两行即可
#    ALGO_ID='<新ID>'
#    CIPHER_SCHEME='<新ID>'      # 让一致性校验通过
#    key/IV 用 .env 里的 DAMOD_KEY / DAMOD_IV（或让 client 脚本走 raw 模式）
/etc/init.d/portal-auto-auth restart

# 3. 助手不支持（日志说 "cannot drive"）→ 该模板是新原语，需要实现，见第五节
```

### 验证

```sh
cd /root/portal
wget -q -T 10 -O /tmp/p.out http://connect.rom.miui.com/generate_204; echo "size=$(wc -c < /tmp/p.out)"
```

`size=0` 才是真放行；拿到几千字节 HTML 说明被门户劫持，**没有真正通过认证**。

---

## 四、验证记录（2026-10-09）

### 双样本比对（逐字节，不是"看起来对"）

| 模块 | UUID | 模板 | key | IV | 比对结果 |
| --- | --- | --- | --- | --- | --- |
| 门户下发 | `9ABF4D29-34DB-4CE9-BB8C-7E371D637758` | `tpl_des_iv.so` | 48 B | 16 B | 与 `Key9ABF4D29_*` **完全一致** |
| App 内 damod | `3D74E736-AB35-47CD-B934-77EBEF2B42D3` | `tpl_aes_cbc.so` | 32 B | 16 B | 与 `KeyBB2EA626_*` **完全一致** |

### 动态模式一致性

`encrypt-raw <模板> <key> <iv>` 与硬编码 `encrypt <算法ID>` 的输出**逐字节相同**
（3DES 和 AES 各验一次），`decrypt-raw` 往返还原正确。

### 端到端（隔离目录，不碰生产配置）

用 `PORTAL_BASE_DIR=/tmp/portal-test` + 故意写错的 `ALGO_ID` 触发：

```
Portal algorithm differs from the configured ALGO_ID.
→ 保存 damod-update.bin.<UUID>
→ damod 解包 → algo-<UUID>.env（303 B, 0600）
→ "uses tpl_des_iv.so (key length 48)"
→ "cipher-helper already drives tpl_des_iv.so"
```

### 部署产物

| 文件 | MD5 | 备份 |
| --- | --- | --- |
| `portal_auto_auth.sh` | `b69d4a26a33b7c27af6596ffde3faae5` | `portal_auto_auth.sh.bak-20261009-pre-damod` |
| `cipher-helper` | `d7b346f33416a4a2143452a381c4d418` | `cipher-helper.bak-20261009-pre-raw` |
| `damod` | `2c2ea3d6522aad5a079f538630d261d1` | `damod.bak-20261009` |

---

## 五、新增算法怎么实现

`cipher/` 是纯 Go 实现，加一个算法三步：

1. `cipher/keydata.go` 加密钥（若走动态模式可跳过）
2. `cipher/cipher.go` 的 `NewCipher` 加 `case`
3. `cipher/list.go` 的 `supportedIDs` 加 ID
4. 如果新模板要能被 `encrypt-raw` 自动驱动，在 `cipher/raw.go` 的 `NewCipherRaw`
   里加一条「模板名 + key 长度 → 构造函数」的映射

然后重新交叉编译：

```powershell
C:\Users\plaui\Documents\Codex\2026-10-09\openwrt-portal-check\cipherhelper\build.ps1
# 产出 dist\cipher-helper-mipsle，scp 覆盖 /root/portal/cipher-helper，重启服务
```

client 脚本不用改。

---

## 六、残余限制

1. **只实现了 type 0 容器**。type 1 = RC4(96B key)、type 2 = TEANP、type 3+ 未还原。
   目前门户实际下发的都是 type 0；遇到别的类型 `damod` 会明确报错。
2. **未知模板需要人工实现**。`cipher-helper` 现有 24 个算法，`raw.go` 只映射了
   已知的几个模板。日志里出现 "cannot drive" 就说明碰到新原语了。
3. **`.env` 文件含明文密钥**，权限 0600，不要外传、不要进 git。
4. 路由器 OpenSSL 3.5.7 没有 SM4、没有单 DES，所以 SM4/ZUC/SNOW3G/XTEA 系
   必须走 `cipher-helper`，不能回退到 openssl。

---

## 附录 A：早前的错误结论（保留作教训）

第一版文档写"密钥不在模块里"，依据是：在模块文件里全量搜 96/48/32 hex
的密钥和 IV，**0 命中**；并且对载荷做了 62,208 组 LZMA 参数爆破，**全部失败**。

两个原因叠加导致误判：

- 载荷是 type-0 加密的，**必须先做反向异或链**再解 LZMA，直接爆破 LZMA 当然全败
- 在密文上搜明文密钥，自然 0 命中

教训：**"搜不到"不等于"不存在"**，要先确认自己解到了正确的层。

## 附录 B：APK 静态分析结论（仍然有效）

| 项 | 结果 |
| --- | --- |
| 加固 | **360 加固（libjiagu）**，Java 层被壳保护，静态反编译拿不到业务代码 |
| native 库 | `libdaproxy.so`（ZSMLinker）、`libmsec.so` |
| 算法 UUID | 全量扫描 dex/so/assets，无 ASCII 算法 ID |
| 密钥 | dex 和 4 个 .so 里搜 9ABF4D29 密钥、半段、IV，全部 0 命中；单字节异或全扫也 0 命中 |

`libdaproxy.so` 的 JNI 接口暴露了架构：
`DaMod_load / _aid / _key / _enc / _dec / _inspect / _prev / _free`，
源码路径 `ZSMLinkerPro/app/src/main/cpp/damod`，内含 `LzmaDec.c`、`zuc.c`、`TEAN`。

**修正后的理解**：密钥不在 APK 里，是因为**它本来就由门户在运行时下发**
（就在模块的 `.data` 里），App 不需要内置。所以"APK 里搜不到密钥"是正确的，
但由此推出"拿不到密钥"是错的。

**重要：不要在这台设备上跑 frida-server**。已三次复现 `system_server` 在约 40 秒内
SIGSEGV（fault addr 0x11），事故记录见 `frida/事故记录-20261009-framework重启.md`。
本方法全程静态，不需要 frida。

## 附录 C：可复现的原始素材

| 路径 | 说明 |
| --- | --- |
| `apk/portal-algo-9ABF4D29.bin` | 门户下发的模块（18903 B） |
| `apk/app-data/files_CDCLogs_config_damod` | App 内的 damod（19922 B） |
| `apk/unpacked-*.so` | 还原出的 ELF64 模块 |
| `apk/extracted-installed/libdaproxy.so` | 带完整 DWARF + symtab 的解析库（分析关键素材） |
| `apk/zsmdecode.merged.txt` | `ZsmModDeCode` 反汇编（带源码行号 + 调用符号） |
| `unpack/damod/main.go` | 通用解包 + 提取工具 |
| `unpack/disasm/` | ARM64 反汇编器（Go + golang.org/x/arch/arm64/arm64asm） |
| `unpack/dwarfdump/` | DWARF 转储工具 |