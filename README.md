# openwrt-portal-check

OpenWrt 校园网（CNDATA / 天翼校园）门户自动认证的研究记录与工具集。

在这个网络上，路由器需要按门户规定的算法对认证请求做加密，门户换算法时客户端
就得跟着换。这个仓库记录了**怎么发现算法变更、怎么把新算法模块拆开、怎么把里面
的密钥取出来**，以及配套的工具。

## 关键结论

**门户会把当前算法模块主动下发，模块里带明文密钥。**

用全零 UUID 发一次请求（`Algo-ID: 00000000-0000-0000-0000-000000000000`），
门户不看请求里的 Algo-ID，直接返回它当前想要的模块。于是：

- 算法变更 → 客户端自己就能探测到
- 加密方式 → 模块 `.dynstr` 里的模板名（`tpl_des_iv.so` / `tpl_aes_cbc.so` …）
- 密钥 / IV → 模块 `.data` 里，位置由模块自己的一小段元数据给出

所以**不需要 hook App、不需要 Frida、不需要动态脱壳**。

### 模块格式

```
容器:  "001" + lenByte + hex(lenByte) + "$" + UUID(36) + "]" + payload

type-0 载荷:
  props   = payload[0:4]
  szField = LE32(payload[4:8])     # 高 4 位 type，低 28 位解压后大小
  data    = payload[8:]
  for i = len(data)-2 downto 0: data[i] ^= data[i+1]      # 反向异或链
  LZMA 头 = 0x5d + props + LE64(size)                     # 注意别去掉尾部填充
  → ELF64 / ARM64
```

### 密钥取法

模块的初始化代码硬编码读 `.data+249` 的 7 字节元数据块：

| 偏移 | 含义 |
| --- | --- |
| `meta[0]` | 块大小 / IV 长度（8=DES，16=AES） |
| `meta[2]` | key 长度（48=double 3DES，32=double AES） |
| `meta[5]` | key 相对 `.data` 的偏移 |
| `meta[6]` | 标志字节 |

```
key = .data[ meta[5] : meta[5]+meta[2] ]
iv  = .data[ meta[5]+meta[2] : +16 ]
```

模块自带校验 `meta[0]+meta[2]+meta[5] <= 0xf9`，工具照搬了这条。

## 目录结构

```
cipherhelper/     门户加解密助手（纯 Go，24 个已知算法 + 动态密钥模式）
  cipher/         各算法实现
  cipher/raw.go   模板名 + key/IV → 具体实现（门户换密钥时不用重编译）
router/           路由器侧的认证脚本
tools/damod/      模块解包 + 密钥提取（核心工具）
tools/disasm/     ARM64 反汇编器（Go + golang.org/x/arch）
tools/dwarf/      DWARF 转储辅助
tools/type0/      最早的 type-0 解包原型
tools/brute/      LZMA 参数搜索器（用于还原载荷管线）
docs/             Runbook 与部署记录
```

## 工具用法

### damod —— 解包模块、提取密钥

```sh
damod <module.bin>            # 人类可读
damod -env <module.bin>       # shell 变量（DAMOD_UUID/TEMPLATE/KEY/IV...）
damod -json <module.bin>      # JSON
damod -o out.so <module.bin>  # 顺便把还原出的 ELF 落盘
```

输出示例：

```
uuid        9ABF4D29-34DB-4CE9-BB8C-7E371D637758
template    tpl_des_iv.so
algorithm   double-3des-cbc
block_size  8   key_len 48   key_off 161
key         <48 字节>
iv          <16 字节>
```

### cipher-helper —— 加解密

```sh
cipher-helper encrypt <algo-id>                      # stdin → 大写 hex
cipher-helper decrypt <algo-id>
cipher-helper check   <algo-id>
cipher-helper list

cipher-helper encrypt-raw <template> <keyhex> [ivhex]   # 用模块里提取的密钥
cipher-helper decrypt-raw <template> <keyhex> [ivhex]
```

`*-raw` 模式是关键：门户换了密钥，只要有新模块，不用重新编译助手。

交叉编译到 OpenWrt（MT7621 / mipsle softfloat）：

```powershell
cipherhelper\build.ps1
```

## 密钥政策（重要）

**本仓库不包含任何真实密钥。**

- `cipherhelper/cipher/keydata.go` 只有**变量声明**，没有值
- 真实密钥放在本地 `cipherhelper/cipher/keydata_local.go`，该文件被 `.gitignore` 排除
- 也可以完全不用静态表：用 `damod` 从门户模块提取 key/IV，再走 `cipher-helper encrypt-raw`

要自己跑起来，二选一：

```go
// cipherhelper/cipher/keydata_local.go
package cipher

func init() {
    Key9ABF4D29_Key = []byte{0x63, 0x73, /* ... */}
    Key9ABF4D29_IV  = []byte{0x77, 0x2d, /* ... */}
}
```

或者：

```sh
damod -env /root/portal/damod-update.bin.<UUID>
cipher-helper encrypt-raw tpl_des_iv.so "$DAMOD_KEY" "$DAMOD_IV"
```

## 门户换算法时的流程

1. 路由器脚本用全零 UUID 探测，发现 `ALGO_ID` 与门户当前不一致
2. 把模块存到 `damod-update.bin.<新UUID>`
3. 调 `damod -env` 解包，写 `algo-<新UUID>.env`
4. 报告模板名和 key 长度，并用 `cipher-helper encrypt-raw` 试跑，判定"已支持 / 需要新实现"
5. 已支持 → 改配置里的 `ALGO_ID` / `CIPHER_SCHEME` 即可

细节见 `docs/RUNBOOK-算法变更处理.md`。

## 已知限制

- 只实现了 **type 0** 容器。type 1 = RC4(96B key)、type 2 = TEANP、type 3+ 未还原
- 未知模板需要人工实现新原语
- `damod` 提取出的 `.env` 含明文密钥，注意权限（0600）和清理

## 免责声明

本项目仅用于学习、研究和在自己有权限的网络中排查连接问题。
使用者需自行确认并承担所在网络的使用条款与合规责任。

## License

见 `LICENSE`。