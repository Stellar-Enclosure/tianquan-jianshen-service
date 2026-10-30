# Stellar Enclosure Tianquan-Jianshen 权限平台

[English](README.md) | [中文](README.zh-CN.md)

Tianquan-Jianshen 是一个租户隔离的权限控制面与运行时鉴权系统，统一管理应用、资源清单、
角色 DAG、角色分配、约束、用户级激活角色集合、授权快照、审计证据，以及
Yuheng/Tianshu 发布和服务发现。当前 Maven 能力位于独立 `tianquan-jianshen-service` 仓库，
React 管理台与 SDK 分别由 `tianquan-jianshen-web`、`web-sdk` 维护。

## 功能入口

| 领域 | 当前功能 |
|---|---|
| IAM 目录 | 业务/应用准入、用户、组织、岗位及人员归属 |
| 授权治理 | 资源 Manifest、权限映射、角色 DAG/继承、用户角色分配与资源授权 |
| 约束与激活 | 职责分离、先决条件、基数约束及用户级多角色激活 |
| 运行时决策 | 功能、操作、数据、字段权限与参与记录判定，授权快照与 Fence |
| 管理与运维 | 管理策略、授权模拟/变更影响分析、审计、Mutation 重试与 CI 资源注册 |

主要管理 API 位于 `/api/tianquan-jianshen/v1`，授权上下文入口位于 `/api/v1/auth`，内部运行时决策位于 `/internal/v1/authorization`。Jianshen 负责 USER 授权；登录、Token 签发和 SERVICE Scope 属于 Shoubing 的职责。

延后执行的数据范围证明使用独立 POST `/internal/v1/authorization/execution-grants:decide-scopes` 与 SDK `HttpExecutionAuthorizationClient.decideScopes`。除显式启用 execution-grants 外，对应 system/purpose policy 必须设置 `scoped-decisions: true`（默认关闭），调用 SERVICE 需要独立的 `service:authorization:execution-scopes` 及当前已激活资源策略。响应封装原有十三字段执行决策、内部 `rbac3UserId`、快照时间和该策略必需权限的当前 DataScopeDecision；数据范围的 subjectId 是 RBAC 用户 ID，不能与外部身份 sub 混用。合同与 SDK 核对 tenant/用户/权限键/版本/时间，拒绝不明字段、类型强转、缺少布尔标志和错误 ID 数组，并保持原执行接口解码与响应不变。Memory 等消费者仍需独立 purpose 和精确 owner/scope 绑定；不得从普通执行许可、组织子树标志或任意 team 字符串推导额外权限。该能力不会注册、激活或授予权限，真实目录与 IAM 仍需部署验收。

## 一、不可变业务语义

1. **不需要审批。** 权限变更是受身份、授权、幂等、并发和审计约束的直接命令，
   Tianquan-Jianshen 不建立审批单、审批人或审批状态机。
2. **轮岗属于业务定义。** 排班、轮岗和当班规则由业务系统决定；权限平台只提供
   “激活角色集合”的语义接口，不维护轮岗流程。
3. **登录不选择角色。** Tianquan-Shoubing 负责登录并签发 USER Access/Refresh Token；Tianquan-Jianshen
   不创建或管理人员 Session。Bootstrap 返回候选角色，随后由激活接口一次性替换
   用户级激活集合。
4. **支持同时激活多个角色。** 对每个被选角色先解析唯一最顶级角色，再纳入该根
   角色的全部后代角色和所有权限；多个根族权限按确定性代数合并。
5. **同一 APP 下互斥根角色不能同时激活。** 这会造成 APP 授权上下文歧义，系统
   在变更前校验 DSD/互斥约束，并原子拒绝整个集合，不做部分成功。
6. **无独立测试模块。** `contract/core/starter/gateway-adapter/admin` 各自在
   `src/test` 下维护单元或模块集成测试，不创建 `tianquan-jianshen-test`。

## 二、模块与依赖边界

| 模块                                         | 职责                               | 强制边界                          |
|--------------------------------------------|----------------------------------|-------------------------------|
| `stellar-enclosure-tianquan-jianshen-contract`        | 稳定 DTO、枚举、Manifest、Decision 合同   | 不依赖 Spring 运行时和持久化            |
| `stellar-enclosure-tianquan-jianshen-core`            | 角色图、激活算法、权限代数、约束规则               | 纯 Java，不访问 I/O/HTTP/Redis/JPA |
| `stellar-enclosure-tianquan-jianshen-starter`         | 业务服务侧 PEP、Tianquan-Shoubing JWT 校验、用户授权快照读取    | 不依赖 Admin，只消费合同与 Core         |
| `stellar-enclosure-tianquan-jianshen-gateway-adapter` | Yuheng 热路径认证与授权                 | 不通过 HTTP 调 Admin，不访问 SQL      |
| `stellar-enclosure-tianquan-jianshen-admin`           | 控制面、认证、持久化、Worker、Tianshu/Yuheng 集成 | 仅服务端使用，不被 Starter 引入          |
| [Jianshen React SDK](https://github.com/Stellar-Enclosure/web-sdk/tree/main/packages/stellar-enclosure-tianquan-jianshen-react-sdk) | 类型化授权状态、角色激活和 UI Guard | 位于独立 web-sdk npm workspace，通过 Cookie/BFF 访问，不保存 Access Token |
| [tianquan-jianshen-web](https://github.com/Stellar-Enclosure/tianquan-jianshen-web) | 权限过滤后的管理台 | 独立 Node 仓库，静态 Vite SPA，仅使用本地组件注册表 |

前五个模块是本 reactor 的 Maven 子模块；本仓库不包含前端 `package.json` 或 npm workspace。
不存在 `tianquan-jianshen-test` Artifact，也没有
聚合运行时库。

## 三、关键执行链路

```text
不可变 Resource Manifest
  -> 校验/影响分析/幂等激活
  -> 角色、权限、约束、分配变更
  -> Mutation Journal + Fail-Closed Fence
  -> PostgreSQL Worker 领取任务
  -> 生成不可变授权快照并原子发布到专用 Redis
  -> Fence 开放
  -> Starter / Yuheng 校验 JWT 与精确版本
  -> Function + Data + Field + Participation 决策
```

```text
Tianquan-Jianshen Admin Definition Report（Tianshu v3 bizCode + appCode）-> Yuheng Admin
Tianquan-Jianshen Admin HTTP_PROVIDER Lease（同一 bizCode + appCode）-> Tianshu
Yuheng Release -> Tianshu 配置投影 -> Yuheng Engine
Yuheng Engine -> 从 Tianshu 获取 Tianquan-Jianshen 实例 -> 路由请求
```

Definition、Lease、Release 是三项独立状态，任何一项未知或不一致都不能被合并解释
为“可路由”。进程存活也不等于 Yuheng 已可路由。

## 四、OAuth Resource 授权边界

Tianquan-Jianshen 只负责 USER 授权。Tianquan-Shoubing 为精确的
`bizCode + appCode + environment` Resource 签发或刷新 USER Token 之前，由
Tianquan-Shoubing 目录与 Tianquan-Jianshen 应用准入策略共同确认用户的 Tenant 成员关系。
认证完成后，下游 Starter 执行该用户的接口、数据、字段、参与和激活角色策略。USER Token
只携带身份类 Claim，因此权限变更仍通过 Tianquan-Jianshen 的 Snapshot 与 Fence 规则生效。

Tianquan-Jianshen 不拥有 SERVICE principal、Service Grant 或 Service Scope。
Tianquan-Shoubing 依据精确的来源 Client、目标 Resource、Tenant 和 Scope 集合授权
`client_credentials`。已验证的 SERVICE 请求只有在 Token 携带该操作要求的
Tianquan-Shoubing Scope 时才在本地放行，且绝不进入 Tianquan-Jianshen 的用户决策路径。
因此被允许进入 `permission/tianquan-shoubing@prod` 的用户，除非
`permission/tianquan-jianshen@prod` 自身的应用准入决策也通过，否则拿不到该目标的 Token；
而服务到服务的访问完全由 Tianquan-Shoubing Service Grant 治理。

Tianquan-Jianshen Admin 通过 Spring OAuth2 Client，使用 Tianquan-Shoubing 管理的 app ID
和一次性 Secret 取得 Tianshu Audience 的 PLATFORM SERVICE Token。Tianshu 绑定 Token 的
Audience、Scope、来源、实例、重放状态和租约有效期，不使用第二套注册凭据。Tianquan-Shoubing
V6 必须与兼容的 Tianshu/RBAC 发布一起应用；由于旧的服务权限和不注册即可访问的路径已被
有意移除，回退只能采用协调一致的前向修复。

## 五、Tianshu 配置 scope、服务 scope 与 Yuheng 文档中心

配置 scope 与服务 scope 是两个不同的身份空间：

- 配置资源身份为 `bizCode + appCode + env + resourceName`；命名空间绑定只控制可见性，
  不属于资源身份。Tianquan-Jianshen 以 `CONFIG_CLIENT` Lease 拉取 YAML 策略文档，只接受通过校验
  且版本单调递增的快照。
- 服务 scope 为 `bizCode + appCode + env + namespace + serviceKind + protocol +
  serviceName + group + version`。Tianquan-Jianshen 以独立的 `HTTP_PROVIDER` Lease 注册服务，
  Yuheng 从该 scope 获取未过期实例并路由到 advertised host/port。

两类 Lease 可以使用同一个 Instance ID，但 Lease 凭据和状态互相独立。启动时必须先
取得 `CONFIG_CLIENT` Lease 并达到 `READY`，再由 Tianquan-Jianshen 发布门闩把根 HTTP Server
发布为 `HTTP_PROVIDER`。Definition 上报与两类 Lease 也相互独立。Spring MVC Mapping
和现有 Yuheng 注解共同生成 Yuheng Interface Catalog；它是唯一接口文档中心。
Yuheng Release 必须由操作者显式发布，Tianquan-Jianshen 不自动发布 Release。

| Tianshu Key | 默认值 | 合法范围 |
| --- | ---: | ---: |
| `tianquan-jianshen.maximum-active-roots` | 16 | 1..32 |

该 Key 只控制最大激活根角色数。它以 `refreshable = false` 的 `@DdcValue` 占位符被消费，
因此新值需要重启才生效；同一设置在本地绑定为
`egon.tianquan-jianshen.maximum-active-roots`。Tianquan-Shoubing 负责固定五分钟 USER Access Token 与稳定
Refresh Token 的生命周期。Tianquan-Jianshen 不再有 Token/Session 超时 Key，也不存在跨 Key
超时发布顺序。

合法更新通过不可变 Snapshot 原子替换，只影响之后执行的角色激活命令；不会改写
Tianquan-Shoubing 已签发的 Token 或已提交的激活集合。非法值产生 FAILED ACK，但继续使用
Last-Known-Good Policy 和旧版本/Checksum；恢复必须发布更高的合法版本。

运维必须分别观察五项事实：Tianshu Config Client、Yuheng Definition、未过期的 Tianshu
HTTP Provider Lease、显式 Yuheng Release/Engine Consistency、真实 Routed Request。
状态与指标只暴露版本、状态、指纹和错误码，不暴露配置原值、Lease 凭据、密码、
Token、私钥、Hash 或首个管理员 Bootstrap Secret。

## 六、角色激活规则摘要

- 输入是用户级**完整目标角色集合**，不是增量追加；必须携带预期 `authVersion`，
  服务端在用户授权行锁内完成 CAS。
- 子角色输入先映射到唯一顶级根；一个角色存在多个根、出现环或超过深度上限时
  直接拒绝。
- 每个根展开完整后代族；同一族重复输入被归一化，结果与输入顺序无关。
- 一个用户可以激活多个 APP 的多个根，也可以激活同 APP 中没有互斥关系的
  多个根；同 APP 的互斥组合被拒绝。
- 激活前验证 Assignment 证据、DSD、先决角色、禁用/过期状态和最大激活根数。
- 激活成功后生成新的不可变快照；响应不确定时客户端用
  `GET /auth/role-activations` 恢复，而不是盲目重放。

## 七、权限决策摘要

最终决策按固定顺序执行：身份与 Tenant/APP 边界、User/Tenant/Policy
精确版本、Fence、Function Permission、Data Scope、Field Rule、Participation 与
Operation SOD。任何必需数据缺失、版本不一致、Redis/密钥不可用或规则无法解析，
均 Fail Closed。

权限合并满足交换律、结合律和幂等性；字段规则按稳定键排序，敏感字段默认
`NONE`，不能因规则缺失自动放宽。Yuheng 热路径只做一次决策，不访问 PostgreSQL，
也不回调 Admin HTTP 接口。

## 八、首次管理员初始化

清洁环境通过 Admin 可执行制品内两个显式一次性命令完成权限初始化，不提供绕过目录
激活的 HTTP 管理员入口，也不会在应用启动或普通 CI 中自动执行。完整输入、数据库
身份校验和恢复约束见 [B0/B1 操作文档](docs/permission-catalog-bootstrap.md)。先完成已批准
的迁移和 IdP/META B0，再执行 RBAC B0，建立完整 scope、producer owner 和有限机器授权：

```bash
java -jar stellar-enclosure-tianquan-jianshen-admin/target/stellar-enclosure-tianquan-jianshen-admin-exec.jar \
  bootstrap-permission-catalog \
  --command-file /absolute/private/rbac-catalog-command.json \
  --receipt-file /absolute/private/rbac-catalog-receipt.json
```

首次 FULL Manifest 登记、来源回执、READY、发布资格检查和完整集合激活完成后，执行
B1，为指定 IdP subject 的新角色授予明确列出的 ACTIVE permissionCode：

```bash
java -jar stellar-enclosure-tianquan-jianshen-admin/target/stellar-enclosure-tianquan-jianshen-admin-exec.jar \
  bootstrap-permission-admin \
  --command-file /absolute/private/rbac-admin-command.json \
  --receipt-file /absolute/private/rbac-admin-receipt.json
```

命令、数据库连接和密码文件必须处于执行用户拥有的 `0700` 目录，文件权限为 `0600`，
使用绝对规范路径。每次连接检查实际数据库名称、OID、owner、current_user 和 schema；
不从 YAML、环境变量或系统属性回退连接配置，不创建数据库或执行迁移。B0 不写资源、
权限、角色或用户。B1 拒绝未激活、未知、禁用、退役和通配权限，单事务写入新角色、
DIRECT Assignment、字符授权、authVersion/policyVersion、审计和 Outbox。可选角色激活
要求当前 APP 无活跃角色，并保留其它 APP 的活跃角色及既有撤销状态。

每个 scope 的 B1 只能首次初始化一次；另一个 operation 不能扩权。超时、提交结果不明
或本地回执写入失败时，保留原 command/operationId 重试，从数据库审计恢复原回执，
不会重建角色或重新授权。旧 `bootstrap-platform-admin` 不建立新目录及字符授权，不再
作为该清洁环境权限初始化流程。

## 九、构建与验证

后端要求 Java 25 与 Maven Wrapper。先按[仓库构建说明](README.md#build)准备跨仓库依赖，再在 `tianquan-jianshen-service` 根目录执行：

当前源码的 Outbox 分片上下文与迁移适配使用已选定的 `0.0.2-SNAPSHOT` API，父 POM 已明确仲裁该版本；应使用对应源码 reactor 或先完成发布，不依赖本地旧 `0.0.1` 缓存碰巧可用。其余平台合同仍为 `0.0.1`。

```bash
./mvnw -B -ntp \
  -pl :stellar-enclosure-tianquan-jianshen-contract,:stellar-enclosure-tianquan-jianshen-core,:stellar-enclosure-tianquan-jianshen-starter,:stellar-enclosure-tianquan-jianshen-gateway-adapter,:stellar-enclosure-tianquan-jianshen-admin \
  -am clean verify
```

前端构建、资源报告与浏览器测试命令见 [tianquan-jianshen-web](https://github.com/Stellar-Enclosure/tianquan-jianshen-web)。Yuheng Biz Gateway 不在本 reactor 中；后端构建与静态检查不会自动启动项目、数据库或前端服务。

验证脚本位于本仓库的 `scripts/verification/`，在 `tianquan-jianshen-service` 根目录执行。以下静态/配置检查不执行外部访问：

```bash
scripts/verification/verify-static.sh --verify
scripts/verification/verify-local-dependencies.sh --check-config
scripts/verification/prepare-tianquan-jianshen-fixture.sh --check-config
scripts/verification/verify-yuheng-tianshu-topology.sh --check-config
scripts/verification/cleanup-tianquan-jianshen-fixture.sh --check-config
```

真实拓扑验证要求操作者预先启动两个 Admin 实例，并显式提供不同端口、Instance ID、
Build ID、Snowflake machine-id、Tianshu/Yuheng 地址、Release ID 和专用 Tenant。脚本在
故障切换点暂停，由操作者改变外部状态；脚本本身不停止进程。

## 十、文档入口

- [架构、算法与设计模式](docs/architecture.md)
- [API 与 Manifest 合同](docs/api-and-manifest.md)
- [运维手册](docs/operations-runbook.md)
- [安全与信任边界](docs/security-boundaries.md)
- [验证证据模板](docs/verification-evidence-template.md)

CI/单测/静态扫描只能证明源码和隔离环境内的行为，不能冒充用户实际部署中的
PostgreSQL、Redis、Tianshu、Yuheng 或多进程拓扑证据。真实验证结果必须按证据模板
记录环境、命令、退出码、Release、Schema、Redis 前缀和清理结果。

## 独立仓库发布

发布范围、前置配置、校验与发布命令见 [仓库 README](README.md#publish-to-maven-central)。应用和测试示例不发布到 Maven Central，前端站点保持 `private: true`。
