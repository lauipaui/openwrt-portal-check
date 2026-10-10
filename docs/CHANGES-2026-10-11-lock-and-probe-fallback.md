# 2026-10-11 单实例锁与备用探测

针对线上巡检发现的两个隐患。只改 `router/` 下的 shell 脚本，不涉及 `cipher-helper` / `damod`，
所以部署时只需要替换脚本，不用重新交叉编译。

## 1. 单实例锁迁到 tmpfs，并校验持有者

**问题**：锁目录原来在 `/root/portal/.portal-auto-auth.lock`（闪存）。断电或被 SIGKILL 后锁会残留，
下次开机时 `kill -0 <旧 PID>` 只要碰巧撞上别的进程，脚本就误判“已有实例在运行”并退出；
procd 的 `respawn 3600 5 5` 重试 5 次后永久放弃，之后没有任何东西会把它拉起来。

**修复**（`portal_auto_auth.with-damod.sh`）：

- 锁目录改为 `/var/run/portal-auto-auth.lock`（tmpfs，重启必清）。`/var/run` 不可写时回退到 `$PORTAL_BASE_DIR`。
  可用 `PORTAL_LOCK_ROOT` 覆盖。
- 新增 `lock_holder_alive`：PID 存活**并且** `/proc/<pid>/cmdline` 含 `portal_auto_auth` 才算持有者；
  PID 回收给无关进程、或 PID 恰好是自己，都按陈旧锁回收。无 `/proc` 的环境退化为只检查 `kill -0`。
- `once` / `keep` / `refresh` / `algo` 与常驻服务仍然互斥，行为不变。

部署后旧位置 `/root/portal/.portal-auto-auth.lock` 不再使用，可手动删除（需先停服务）。

## 2. 备用连通性探测

**问题**：在线判定只依赖 `http://connect.rom.miui.com/generate_204` 一个站点。该站点自身不可达时，
脚本会误判为“被门户拦截/断网”，每轮都立即重新认证，可能把正常会话踢掉。`campus-check` 同样只有一个探测点。

**修复**：

- `probe_online` 先探主地址；失败则依次探备用地址，**任一**返回严格 HTTP 204 即视为在线。
  门户会拦截所有明文 HTTP 探测，因此备用地址只有在真的能上网时才会成功，不会把被劫持误判成在线。
- 默认备用：`http://connectivitycheck.platform.hicloud.com/generate_204`、`http://wifi.vivo.com.cn/generate_204`
  （2026-10-11 在路由器上用 `cipher-helper probe` 实测均为 204）。
- 环境变量：
  - `PORTAL_PROBE_FALLBACK_URLS`：空格分隔的备用列表；设为空字符串则关闭备用。
  - 显式设置了 `PORTAL_PROBE_URL` 且未设置 `PORTAL_PROBE_FALLBACK_URLS` 时，**不使用内置备用**
    （使用者指定了探针，就只用他指定的；`tests/regression.cjs` 也依赖这一点）。
- 备用列表只接受 `http(s)://` 且仅含 `A-Za-z0-9._~:/%+=-` 的 URL，其余丢弃（不含通配符，后续不加引号的分词是安全的）。
- 主探针失败而备用成功时只记一条日志（`... fallback probe returned 204 ...`），恢复时再记一条，不会每分钟刷屏。
- `campus-check` 同样处理：主探针**请求失败**时才试备用（主探针被门户页面应答仍判 `CAPTIVE_PORTAL`）；
  命中备用时状态为 `ONLINE`，`detail=http_204_empty_body_via_fallback`。变量为 `CAMPUS_CHECK_FALLBACK_URLS`，规则同上。
  `router/campus-check` 与 `router/campus-check.init` 是首次纳入仓库的线上文件（改动前 MD5 与线上一致）。

**代价**：真正断网（所有探针都超时）时，一次探测最长耗时由 1×超时 变为 3×超时（默认 10s → 30s）。
被门户 302 拦截时应答是即时的，不受影响。

## 已知限制

- `candidate-activate`（算法/端点迁移时的候选验证）仍只用主探测地址：它在认证之后才探测，
  需要改 Go 的 helper 才能传入多个地址，本次未动。主探针恰好故障时迁移会被保守地回滚，下一轮重试。
- `campus-check` 里的 DNS 自检仍固定解析 `openwrt.org`。

## 验证

```sh
sh -n router/portal_auto_auth.with-damod.sh
sh -n router/campus-check
sh tests/backoff.sh
sh tests/state-transition.sh
sh tests/probe-fallback.sh      # 新增：默认/显式地址/列表校验/恢复日志
sh tests/lock.sh                # 新增：tmpfs 路径、陈旧锁、PID 回收、活跃持有者、回退目录
node tests/regression.cjs
```

2026-10-11 在 Windows(Git sh) 与目标路由器(BusyBox ash, OpenWrt 25.12.2) 上均通过。
另做了变异验证：去掉 cmdline 校验、锁放回闪存、去掉备用循环、去掉 URL 校验、显式地址仍带默认备用，
这 5 种改动都会使对应测试失败。

行尾：仓库新增 `.gitattributes`，把 `*.sh`、`*.cjs`、`router/*` 固定为 LF。Windows 上 `core.autocrlf=true`
会把工作区检出成 CRLF，直接部署会让路由器上的 `sh` 报错。
