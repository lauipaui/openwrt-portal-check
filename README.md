# openwrt-portal-check

OpenWrt 校园网（CNDATA / 天翼校园）门户自动认证的研究记录与工具集。

在这个网络上，路由器需要按门户规定的算法对认证请求做加密，门户换算法时客户端
就得跟着换。这个仓库记录了**怎么发现算法变更、怎么把新算法模块拆开、怎么把里面
的密钥取出来**，以及配套的工具。

## 2026-10-10 安全实现

新调度器已接通 **受限数据配置 → 模块验证 → 候选 raw 认证 → 独立 HTTP204 → 配置/会话激活 → 保活**。
无私有静态密钥的公开构建会安全拒绝check/encrypt；list不代表就绪。
必须一起部署新helper、damod和两个脚本。旧单引号配置按数据兼容，更新规范化为JSON，网络内容绝不source/eval。

部署接口、信任白名单、回滚边界和公开回归见 [安全修复说明](docs/SECURITY-2026-10-10.md)。

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
damod -env <module.bin>       # 旧数据导出，禁止source网络派生输出；新调度器用-json（DAMOD_UUID/TEMPLATE/KEY/IV...）
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
damod -json /root/portal/damod-update.bin.<UUID> > private-module.json
# 新调度器通过候选数据配置加载，禁止source/eval下载的配置。
```

## 门户换算法时的流程

1. 私有临时目录下载新模块，下载/容器/UUID/解压/节表/模板校验失败关闭。
2. 使用 `damod -json` 制作候选参数，验证能力及加解密；不信任旧非空缓存。
3. 候选 `ALGO_ID` 与 raw key/IV 直接进入 ticket/auth 请求，真实认证且严格 HTTP204 成功后才激活。
4. 成功后进入保活；失败不改活动配置与本地会话；写入错误按已持有的状态回滚，保留并发外部编辑。
5. 未知模板/容器类型不会自动启用。多文件断电回滚仍需部署备份。

历史分析见 `docs/RUNBOOK-算法变更处理.md`；当前执行步骤与测试以 [安全修复说明](docs/SECURITY-2026-10-10.md) 为准。

## 已知限制

- 只实现了 **type 0** 容器。type 1 = RC4(96B key)、type 2 = TEANP、type 3+ 未还原
- 未知模板需要人工实现新原语
- `damod` 提取出的 `.env` 含明文密钥，注意权限（0600）和清理

## 免责声明

本项目仅用于学习、研究和在自己有权限的网络中排查连接问题。
使用者需自行确认并承担所在网络的使用条款与合规责任。

## License

见 `LICENSE`。