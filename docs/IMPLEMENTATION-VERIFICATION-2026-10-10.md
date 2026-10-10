# 独立实现线程验收报告（2026-10-10，未提交）

## 实际 Git / 隔离状态

- worktree：C:\Users\plaui\Documents\Codex\portal-audit-fix-wt
- 实现分支：fix/portal-audit-20261010
- 基础：origin/main；HEAD / 基准：f154b6dcbe01cee6164f3f12ff103c9570b603b4
- 所有源码修改保留为未提交工作区diff；没有commit、push、PR或merge。
- 没有连接路由器，没有读取/复制真实密钥或凭据；已检查本worktree不存在keydata_local.go。
- 范围仅router、cipherhelper、tools/damod、tests、相关README/docs和.gitignore。

## 实现摘要

1. 旧单引号配置安全按数据解析，所有既有字段白名单保留；新写入为JSON。网络内容不source/eval；URL可信主机、路径、协议和控制字符校验。
2. 静态密钥就绪检查拒绝缺失、零密钥和错误长度；保留原keydata_local.go的init赋值模式。raw模板精确白名单，DES16受控拒绝；恶意输入不产生CLI panic/密文。
3. Go实现既有ticket/auth/keep协议，XML请求转义、响应唯一根/直接必要字段校验，正确处理实体和CDATA。保持旧Error-Code/Sub-Error HTTP协议，不猜造XML成功字段。
4. 自动算法/端点候选真正进入raw认证；严格204联网确认后才发布配置和会话，失败保留旧本地状态。成功迁移直接进入在线保活状态；未更新时不重置60/120/240/300退避。
5. 坏下载/解包失败关闭；只发布已验证模块，下一次重新下载替换坏缓存；不靠缓存非空判断有效。
6. 统一有界net/http，无跳转假在线，正确处理chunked；删除不完整nc后备与共享/tmp诊断输出。随机私有临时文件、原子写入拒绝软链接。
7. 受控容器/解压/节表/模板边界；声明字典最多16MiB，已知实际输出最多1MiB，固定xz读取器实际字典不会超过有界输出（最低4096）。
8. Linux写入flock互斥。事务所有失败/并发分支统一回滚自己仍持有的值，保留外部修改，并明确报告不完整回滚。
9. 保留路由器local-time语义：shell传date +%z所得±HHMM；直接Go调用以2秒/32字节上限执行同一date命令，非法或无法确定时区安全失败，不静默UTC。

## 红到绿证据

- 静态公开构建：原24算法接受未初始化密钥/部分panic，raw DES16 panic、未知模板子串匹配；修复后对应回归通过。
- 退避原实际值60/60/60/60；修复后60/120/240/300。
- 非XML HTML端点fixture原被XML directives拒绝；修复后唯一字段安全提取且恶意/重复拒绝。
- 16MiB声明字典小输出fixture原被2MiB上限拒绝；修复后通过，超限声明/输出仍拒绝。
- 成功迁移后原run_loop状态auth=1、failures=1、next=0、sleep=60；修复后auth=0、failures=0、next_keep已设，按probe_interval进入在线状态。
- 配置/XML/HTTP/候选/时区新边界先添加缺失接口失败回归，再实现转绿。

## 最终本机验证

工作目录为上述独立worktree（Go模块使用-C切换至其子目录）；GOPATH=C:\Users\plaui\Documents\Codex\tools\gopath，GOPROXY=off，GOSUMDB=off，GOFLAGS=-mod=readonly。

| 命令 | 结果 |
|---|---|
| go -C cipherhelper test -count=1 ./... | PASS，最后一轮main 1.632s、cipher 0.597s |
| go -C cipherhelper vet ./... | PASS，无诊断 |
| go -C tools/damod test -count=1 ./... | PASS；加强种子后再次PASS 4.311s |
| go -C tools/damod vet ./... | PASS，无诊断 |
| sh -n router/portal_auto_auth.with-damod.sh | PASS（Git sh，不代表真实BusyBox ash） |
| sh -n router/portal_client_openssl.helper.sh | PASS（同上） |
| sh tests/backoff.sh | PASS：退避及配置/算法激活返回码 |
| sh tests/state-transition.sh | PASS：两条失败入口在迁移成功后转在线、不误退避 |
| node tests/regression.cjs | PASS：真实helper+damod+shell+独立Node DES fixture，loopback端到端 |
| tools/damod: go test -run '^$' -fuzz FuzzELFSectionTable -fuzztime 3s -parallel 1 | PASS，加强有效ELF种子后2272执行 |
| tools/damod: go test -run '^$' -fuzz FuzzUntrustedContainer -fuzztime 3s -parallel 1 | PASS，加强完整合成模块种子后46973执行 |
| git diff --check | PASS |

Node端到端覆盖截断下载→完整下载替换坏缓存、未授权候选拒绝、空200回滚、raw ticket/auth/keep、学校字段/密码XML转义/MD5、真实chunked、204/空200/302、注入无marker、非XML HTML端点候选激活。

**明确SKIP：** TestSymlinkOutputRejected 在Windows因“required privilege is not held”无法创建链接；没有把该项记为通过。需主线程在Linux/OpenWrt补测。

## 最终 mipsle softfloat 产物

CGO_ENABLED=0、GOOS=linux、GOARCH=mipsle、GOMIPS=softfloat，使用go build -trimpath -ldflags='-s -w'。
构建包含最终审查的 ELF 节名资源预算、旧 9ABF4D29 填充兼容和 keep TLS 降级修复。

- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\cipherhelper\dist\cipher-helper-mipsle
  - 7405783字节
  - SHA256 CEE290D38BF1E634E817A03BA6B7C897179908A688F0B8EB11B70F654642A735
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\tools\damod\dist\damod-mipsle
  - 2425047字节
  - SHA256 01198E8410C0E2A48663026EDBA9F4F2A4674943FDEF70E0415CE663BC64A429

构建产物被.gitignore忽略，不含真实静态keydata。

## 主线程最终验收与部署状态

- 主线程独立重跑两模块 test/vet、两脚本 sh -n、backoff/state-transition、Node 端到端回归及 git diff --check，结果为 MAIN_FINAL_REGRESSION_ALL_PASS。
- 两个 fuzz 短跑通过：ELF section table 1074 次、untrusted container 19558 次。
- 最终 mipsle 产物已在 OpenWrt 私有暂存目录按 release.sha256 校验；真实旧配置 self-test、真实模块 key/IV 与旧 damod 对照、候选 self-test、Linux 软链接拒绝、真实 keep、严格 HTTP204 与独立 HTTPS204 全部通过。
- 最终暂存验收标记为 FINAL_STAGE_ALL_PASS_PRODUCTION_UNCHANGED；生产文件和服务在暂存阶段未改变。正式切换仍须单独执行新鲜备份、原子替换、真实 auth/keep/204 验证及失败回滚。
- 跨多个配置/会话文件不是断电原子事务；硬断电/SIGKILL发布中途需部署备份恢复。候选认证对运营商远端旧会话的影响不能靠本地回滚保证。
- 用户手工编辑应停服务；最终比较与rename之间仍有无法消除的非协作编辑竞态。遇到外部变化不覆盖用户值，必要时报告不完整回滚。
- 原协议HTTP模块没有新增签名，白名单不消除链路MITM；未知类型/模板拒绝自动启用。
- GOMEMLIMIT=6MiB为GC软目标，不是RSS硬限；设备 /usr/bin/time -v 已测 final 阶段 keep 5964KiB、HTTPS204 8692KiB，但不代表所有未来输入的上限。

## 完整修改文件清单（含本报告）
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\.gitignore
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\cipherhelper\build.ps1
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\cipherhelper\cipher\cipher.go
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\cipherhelper\cipher\compat_test.go
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\cipherhelper\cipher\raw.go
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\cipherhelper\cipher\readiness.go
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\cipherhelper\cipher\safety_test.go
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\cipherhelper\client_test.go
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\cipherhelper\client.go
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\cipherhelper\command.go
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\cipherhelper\config_test.go
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\cipherhelper\config.go
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\cipherhelper\http_test.go
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\cipherhelper\http.go
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\cipherhelper\lock_linux.go
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\cipherhelper\lock_other.go
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\cipherhelper\main.go
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\cipherhelper\migration_test.go
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\cipherhelper\migration.go
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\cipherhelper\review_regression_test.go
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\cipherhelper\timezone_test.go
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\cipherhelper\timezone.go
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\cipherhelper\xml_test.go
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\cipherhelper\xml.go
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\docs\IMPLEMENTATION-VERIFICATION-2026-10-10.md
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\docs\SECURITY-2026-10-10.md
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\README.md
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\router\portal_auto_auth.with-damod.sh
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\router\portal_client_openssl.helper.sh
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\tests\backoff.sh
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\tests\regression.cjs
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\tests\state-transition.sh
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\tools\damod\fixture_test.go
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\tools\damod\main_test.go
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\tools\damod\section_names_test.go
- C:\Users\plaui\Documents\Codex\portal-audit-fix-wt\tools\damod\main.go
