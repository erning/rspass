# rspass — 设计文档

一个简化版的命令行敏感信息管理器，仅以 [age](https://age-encryption.org/) 为加密后端。
定位是 [gopass](https://github.com/gopasspw/gopass) 的极简替代：保留目录树 + 单文件加密的存储模型，去掉 GPG / OpenPGP 后端、剪贴板、模板、TOTP 等所有非核心功能。

---

## 1. 目标 / 非目标

### 目标

- 单一二进制，无运行时外部依赖（`age` CLI 不需要安装）
- 存储结构与 gopass 兼容：每条 secret 是一个独立 `.age` 文件，便于 git 同步
- 多 store，多 recipient，目录粒度的 recipient 控制
- 长期持有解密 identity 的内存 agent，避免反复输入 passphrase
- 只暴露最小命令集：`show` / `edit` / `list` / `agent`

### 非目标

- GPG / 其他加密后端
- 剪贴板复制、模板、TOTP、二维码、密码生成器
- 通过 `RSPASS_PASSPHRASE` 等环境变量做无人值守解密（CI 场景请使用未加密 identity 文件 + 文件权限）
- Web UI / GUI
- 跨用户的密钥分发协议（recipients 文件随 git 走，分发是用户责任）

---

## 2. 架构总览

```
┌───────────────┐         ┌──────────────────┐
│ rspass CLI    │ ──────▶ │ rspass-agent     │   (同一 binary, 内部子命令)
│ (show / edit) │  unix   │  内存 keychain   │
│               │  socket │  解密 identity   │
└──────┬────────┘         └──────────────────┘
       │
       │ 直接读写
       ▼
┌──────────────────────────────────────┐
│ Store 目录                           │
│   secrets/                           │
│     api.age                          │
│     db/prod.age                      │
│   .age-recipients                    │
└──────────────────────────────────────┘
```

- CLI 与 agent 是同一个 binary，agent 通过隐藏子命令 `__agent-daemon` 启动
- CLI 与 agent 都复用同一套 age 加解密封装（`crypto.rs`）；agent 负责用内存中的 identity 执行按请求解密，不向 CLI 导出 identity
- agent 对 `show` / `edit` 完全 opt-in，不会因普通解密被自动启动；`agent start` / `agent add` 可显式启动 daemon
- 非 agent 路径下按配置中的 identity 顺序尝试解密：先无 prompt 尝试明文 identity，再对 scrypt / 加密 SSH identity 逐个 prompt passphrase

---

## 3. CLI 表面

```
rspass show <PATH>          # 解密并输出全文到 stdout
rspass edit <PATH>          # 解密 → tempfile → $EDITOR → 重新加密
rspass list [PREFIX]        # gopass 风格的树形列表（别名：ls）
rspass agent start          # 启动 daemon (幂等)
rspass agent stop           # 关闭 daemon
rspass agent status         # 进程状态、socket 路径、已加载 identity 数
rspass agent ls             # 列出已加载 identity 的路径与公钥
rspass agent add [PATH]     # 解密并加入内存；无参时加载 config 中全部
rspass agent rm <PATH>      # 按 identity 文件路径移除
```

### 路径语法

```
[MOUNT/]REL/PATH[/TO/SECRET]
```

- `work/db/prod`  → mount `work`，文件 `<work.path>/db/prod.age`
- `api/openai` → root mount `""`，文件 `<root.path>/api/openai.age`
- 路径按 `mounts` 的 key 做路径组件前缀匹配；如果多个 mount 都匹配，选择**最长路径组件前缀**
- mount `""` 表示 root store，匹配所有没有被更长 mount 捕获的相对路径
- 不存在匹配的 mount → 退出码 1
- secret path 必须是相对路径，拒绝绝对路径、空组件、`.`、`..`
- store root 先 canonicalize；解析后的目标路径必须位于 canonical store root 内
- symlink 可以存在，但不能越出 store root：
  - `show`：canonicalize `<abs>.age` 后必须仍在 canonical store root 内
  - `edit` 新建：canonicalize 目标父目录后必须仍在 canonical store root 内

### 退出码

| Code | 含义 |
|---|---|
| 0 | 成功 |
| 1 | 通用错误（参数、I/O、解析） |
| 2 | 解密失败（找不到匹配 identity） |
| 3 | Passphrase 取消（Ctrl+C / EOF；空回车不算取消，只跳过当前 identity） |
| 4 | Agent 通信失败（仅 `agent` 子命令；`show` / `edit` 连不上 agent 走本地回退，不触发此码） |

---

## 4. 存储布局

每个 store 是一个目录，结构示例：

```
~/.local/share/rspass/personal/
├── .age-recipients              # store 根 recipients
├── api/
│   ├── .age-recipients          # 子目录可覆盖（不继承）
│   ├── openai.age
│   └── anthropic.age
├── db/
│   ├── prod.age
│   └── staging.age
└── notes.age
```

- 文件名直接对应路径，`.age` 后缀不在 CLI 输入里出现
- 目录与 `.age-recipients` 文件随 git 同步（项目本身不内置 git 子命令）
- 不存在的中间目录在 `edit` 时按需创建

---

## 5. 配置文件

路径：`~/.config/rspass/config.yaml`（XDG_CONFIG_HOME 优先）

```yaml
mounts:
  "": ~/.local/share/rspass/personal
  "work": "${HOME}/work-secrets"
  "literal": '\${HOME}/not-expanded'

identities:
  - ~/.config/rspass/identity.txt
  - "${HOME}/.config/rspass/work.txt"
```

字段说明：

| 字段 | 类型 | 说明 |
|---|---|---|
| `mounts` | map<string,string> | key 是 CLI 路径 mount 前缀，value 是 store 目录路径 |
| `mounts.""` | string | root store；匹配所有没有被更长 mount 捕获的相对路径 |
| `mounts.<mount>` | string | 绝对或带 `~` 的目录路径 |
| `identities` | array<string> | identity 文件路径列表，**顺序决定解密尝试顺序**，所以保留为数组 |

- mount key 必须唯一；非空 mount 不能包含空组件、`.`、`..`，不能以 `/` 开头或结尾
- mount key **允许包含 `/`** 表示多段前缀，例如 `team/shared: ~/team-vault`；路径解析时按完整组件序列做最长前缀匹配（`team/shared/foo` 命中 `team/shared`，`team/foo` 不命中）
- `""` root mount 可选
- `mounts` 整体允许为空；此时 `agent` 子命令仍可用（管理 identity），但 `show` / `edit` 等需要 mount 解析的命令会因找不到匹配 mount 而退出码 1
- store 在 Rust 侧加载后按 mount 组件长度降序保存，路径解析时做最长前缀匹配；`""` 永远最后匹配
- 无配置文件时打印一段示例并退出（不自动创建）

### 路径展开

路径展开只作用于：
- `mounts` 的 value
- `identities` 的 item
- 命令行中表示本机文件路径的参数（例如 `rspass agent add PATH` / `agent rm PATH`）

展开顺序：
1. 先由 YAML parser 得到字符串
2. rspass 再做 path expansion

支持：
- 开头的 `~` 和 `~/`
- `${VAR}`，变量名必须匹配 `[A-Za-z_][A-Za-z0-9_]*`
- `\~` 表示字面量 `~`
- `\$` 表示字面量 `$`

转义规则（精确语义）：
- 扫描从左到右；仅当 `\` 后紧跟 `~` 或 `$` 时构成转义对，emit 第二个字符并前进 2 位
- 否则 `\` 原样保留（包括 `\\`、`\n`、`\a` 等，都不做任何转义处理）
- 例：`\\~` 按规则扫描：pos 0 `\` 后面是 `\` 不是转义对 → emit `\`；pos 1 `\~` 是转义对 → emit `~`；结果 `\~`
- 想得到字面的 `\` 就直接写 `\`，不存在 `\\` 变 `\` 的规则

不支持：
- 裸 `$VAR`
- `${VAR:-default}` 等 shell parameter expansion
- `~user`
- glob / command substitution

错误：
- 未定义变量 → 配置错误
- `${` 未闭合、变量名非法 → 配置错误

YAML 书写建议：
- 普通变量路径用双引号：`"${HOME}/work-secrets"`
- 需要保留反斜杠转义时用单引号：`'\${HOME}/literal'`
- 反斜杠转义由 rspass 处理，不是 YAML 处理。YAML 单引号字符串**不**解释反斜杠，恰好让 `\$` / `\~` 原样到达 rspass，再由 rspass 转成字面量；YAML 双引号字符串会先解释反斜杠（`"\$"` → `$`），所以转义场景必须用单引号

YAML 选用理由：手写体验比 TOML 更紧凑，对这种小配置最友好。依赖用社区维护的 `serde_yaml_ng`（原 `serde_yaml` 已 archive）。

---

## 6. Recipients

### `.age-recipients` 文件格式

采用 age `-R` / `--recipients-file` 风格：

```
# 整行注释
# 空行忽略

# alice laptop
age1abcde...

# work ssh key
ssh-ed25519 AAAA... user@host
ssh-rsa AAAA... user@host
```

- 每行一个 recipient
- 支持 `age1...`（X25519）和 `ssh-ed25519` / `ssh-rsa` 两种 SSH 类型（依赖 `age` crate 的 `ssh` feature）
- trim 后为空 → 忽略
- trim 后以 `#` 开头 → 整行注释，忽略
- `age1...` 行：取第一个 whitespace-delimited token 作为 recipient，**后面部分（`# 注释`、自由文本等）全部丢弃**。这保持与 gopass 等包装器常见写法 `age1xyz # alice@laptop` 兼容（age X25519 pubkey 本身不含空格，所以截断是无损的）
- SSH 行：整行原样交给 `age::ssh::Recipient::from_str`，因为 SSH pubkey 的尾部 `user@host` 是格式的一部分，不是可裁的"注释"；SSH 行**不支持** `#` 尾注释，需要备注就在前一行写 `# note` 整行注释

### 解析规则

加密某个 secret `<store>/a/b/c.age` 时：

1. 从 `<store>/a/b/` 起向上 walk
2. 遇到第一个 `.age-recipients` 即停止，使用其内容
3. 走到 store root（包含 store root 自己）都没有 → 报错
4. **覆盖语义**，不与上层叠加；想要叠加请用户自行复制

`show` / 解密**不读** `.age-recipients`；解密只用 identities。

---

## 7. Identities

### Identity 文件

是 age 标准的 identity file 格式，文本行：

```
# 注释
# created: ...
# public key: age1...
AGE-SECRET-KEY-1XXX...
```

支持的两种形态：

1. **明文**（plaintext age identity 文件）— 直接按行解析
2. **scrypt 加密** — 整个文件是一个 age-encrypted blob，明文是上述 identity 文件；解锁需要 passphrase

也允许 SSH 私钥路径（`~/.ssh/id_ed25519` 等），由 `age` crate 的 SSH feature 解析；同样可能需要 passphrase。

### 单文件多 key

age identity 文件天然支持多个 `AGE-SECRET-KEY-1...` 行，每行一个独立 key。
- 一个 identity **文件** = config `identities` 数组的一项
- 一个文件里可能有多把 key
- 解锁/加载/驱逐都以**文件**为单位
- `agent ls` 输出每个文件下的所有公钥

### 解密策略

针对一个待解密 `.age` 文件：

1. **agent 中的所有 identity** → 先尝试（无 passphrase 代价）
2. **agent 中没有的 on-disk identity**：
   - 明文 identity → 直接读取
   - scrypt identity / 加密 SSH identity → 按 config 顺序逐个 prompt passphrase 并尝试
   - **去重**：agent 已加载过的 identity 文件路径在本地回退中跳过；另外 age 库按 file header 的 stanza 公钥匹配，公钥重复的 identity 实际解密只尝试一次。因此即使 config 里某 identity 与 agent 里的重合，也不会造成重复 prompt
3. 一旦某个 identity 成功解密即停止
4. Passphrase prompt 的输入语义（适用于本地回退中所有加密 identity）：
   - **Ctrl+C / Ctrl+D（EOF）** → 整体放弃，退出码 3
   - **空输入（直接回车）** → 跳过当前 identity，继续尝试下一个加密 identity
   - 边缘情况：age 本身不禁止用空字符串作为 scrypt 的 passphrase（虽然这等同于明文储存，无安全收益）。rspass 的语义里"空输入"始终代表"跳过"，**不会**真把空串送给 age；如果用户确有这样的文件，请把它从 scrypt 转回明文 identity 文件再使用
5. age 库内部按 file header 的 stanza 比对公钥，未匹配的 identity 不会真做解密尝试，所以明文 identity "全部丢进去"开销可忽略

**为什么仍然保留 `agent add`：**

agent 在 rspass 中扮演**预解锁缓存**角色——用户显式把已解锁的 identity 放进 daemon 内存，后续 `show` / `edit` 通过 `decrypt` op 直接利用，避免反复 prompt passphrase。agent 不是必须运行的，运行后只是更省事，类似 `ssh` 与 `ssh-agent` 的关系。

- 不启 agent 时：`show` / `edit` 走 §7 的本地回退路径，按 config 顺序逐个 prompt 加密 identity
- 启了 agent 但目标 secret 没有匹配 identity → agent 返回 `no_matching_identity`，CLI 继续走本地回退
- 多个加密 identity 都可能匹配失败时，按 config 顺序 prompt；用户可通过调整 `identities` 顺序降低打扰

**例外：明文 identity 永远自动加入解密尝试。**

---

## 8. Agent

### 进程模型

- 同一 binary，通过隐藏子命令 `__agent-daemon` 进入 agent 主循环
- `agent start` / `agent add` 在 socket 不存在或不响应时 fork+detach 出 daemon
- daemon 父进程（CLI）立即返回；子进程 setsid、关闭 stdio
- 内存中的 identity 没有 TTL，没有 idle eviction，**直到 `agent stop` / `agent rm` 才清除**

### Socket 路径

per-user agent，路径查找规则：

1. 优先 `$RSPASS_AGENT_SOCK`
2. 其次 `$XDG_RUNTIME_DIR/rspass/agent.sock`
3. 回退 `$TMPDIR/rspass-agent.$UID/agent.sock`（macOS 默认走这条；Linux 在 systemd-logind 缺失场景——容器、最简 ssh、Alpine 等——也回退到这里）
4. `$TMPDIR` 也未设 → 报错提示用户设置 `RSPASS_AGENT_SOCK`、`XDG_RUNTIME_DIR` 或 `TMPDIR`

> 路径不按 shell session 或 PID 区分，全用户唯一一个 socket。macOS / Linux 走同一套规则，不再区分平台分支。

权限要求：
- 父目录权限 `0700`
- socket 文件 `0600`
- 连接时 daemon 用 `getpeereid` 校验 UID == 自身，否则拒绝
- daemon 启动时如已有同名 socket 且能 ping → 退出（不重复启动）；否则 unlink 后重建

### 协议

JSON-line（每个请求 / 响应一行 JSON），UTF-8。

请求：
```json
{"op": "add",    "path": "/abs/path/identity.txt", "identity_data": "AGE-SECRET-KEY-1..."}
{"op": "remove", "path": "/abs/path"}
{"op": "list"}
{"op": "decrypt", "ciphertext": "<base64 age bytes>", "context": "work/db/prod"}  // context 仅供 agent.log，agent 不验证
{"op": "status"}
{"op": "stop"}
```

响应（成功）：
```json
{"ok": true, "data": ...}
```

响应（失败）：
```json
{"ok": false, "error": "human readable", "code": "scrypt_failed"}
```

`decrypt` 请求只返回解密结果或失败原因，不返回 identity：

```json
{"ok": true, "data": {"plaintext": "<base64 plaintext bytes>"}}
{"ok": false, "error": "no matching identity", "code": "no_matching_identity"}
```

`decrypt` 的 `context` 字段是 CLI 传入的人类可读 secret 路径（例如 `work/db/prod`），仅用于 agent 写入 `agent.log` 时定位 secret，daemon 不做任何验证。客户端可省略或撒谎，安全模型不依赖它。daemon 也对 ciphertext 设大小上限（默认 16 MiB），超出直接拒绝以避免本地 DoS。

`list` 响应形态：

```json
{"ok": true, "data": {"identities": [
  {"path": "/abs/identity.txt", "pubkeys": ["age1abc...", "age1def..."]},
  {"path": "/abs/work.txt",     "pubkeys": ["age1zyx..."]}
]}}
```

CLI 端 `agent ls` 把这个结构格式化成本节末尾的文本输出。

> **安全权衡**：同 UID 进程仍可请求 agent 解密它能读取的 ciphertext；但 agent 不导出私钥，`agent stop` / `agent rm` 后该能力消失，避免把长期 identity 永久交给任意客户端。
> `agent add` 是解锁后的 identity 进入 daemon 的唯一入口；进入后只留在 daemon 内存中，后续协议不提供导出操作。

### `agent add PATH` 流程

1. 解析 `PATH`（按 §5 的路径展开规则处理，再绝对化）
2. 读文件首字节判断格式：
   - 以 `age-encryption.org/v1` 开头 → scrypt 包裹的 age 文件
   - 否则 → 明文 identity（或 SSH 私钥）
3. 如果是 scrypt：CLI 在自己进程中 prompt passphrase（通过 `/dev/tty`），尝试解密；成功后把明文 identity 字符串发送给 daemon
4. 如果是明文：直接把文件内容发送给 daemon
5. daemon 校验、去重（按 path 唯一；同 path 再次 add 直接覆盖旧条目，**与原文件是 scrypt 还是明文无关**——只关心最终解锁后的 identity 内容；覆盖时发出警告日志）、加入内存

### `agent add`（无参）流程

等价于对 `config.identities` 里的每一项依次 `agent add <path>`，加上以下 UX 规则：

1. 开头打印 `Loading N identities from config.identities...`
2. 对每个 identity：
   - 打印 `[i/N] <path>`
   - 若是明文 identity → 静默加载
   - 若是 scrypt / 加密 SSH → prompt passphrase
     - **空输入（直接回车）** → 跳过该 identity，继续下一个
     - **Ctrl+C / EOF** → 立刻中止剩余加载，退出码 3
     - passphrase 错误 → 打印 `wrong passphrase, skipping <path>`，继续下一个（不视为致命）
3. 结束时打印 summary：`loaded X/N (skipped Y, failed Z)`
4. X ≥ 1 则退出 0；X == 0 则退出码 1（没加载到任何 identity，视为失败）

### `agent ls` 输出示例

```
/Users/erning/.config/rspass/identity.txt
  age1qrstuvwx...                                     # public key 1
  age1mnopqrst...                                     # public key 2

/Users/erning/.config/rspass/work.txt
  age1zyxwvuts...
```

### `agent rm <PATH>`

- `PATH` 解析为绝对 identity 文件路径
- 移除该文件对应的所有 key
- 找不到 → 退出码 1

### 没有 agent 的回退

- `show` / `edit`：直接按 §7 解密策略走（明文 identity 自动尝试，加密 identity 按 config 顺序 prompt）
- 如果所有可用 identity 都不能解密 → 提示用户检查 identity 配置，或用 `rspass agent add <path>` 预加载常用加密 identity

---

## 9. 命令详解

### 9.1 `show <PATH>`

```
1. 解析 mount/path → 绝对文件路径 <abs>.age
2. 文件不存在 → 退出码 1，"secret not found: <PATH>"
3. 收集 identity:
   - try connect agent → decrypt(ciphertext)
   - 如果 agent 成功，直接得到 plaintext → 跳到 step 6
   - 如果 agent 不可用或 no_matching_identity，继续本地解密回退
4. 本地解密回退：
   - 先用 config.identities 中的明文 identity 尝试无 prompt 解密
   - 如果失败，再按 config.identities 顺序逐个处理加密 identity：
     - prompt passphrase（详细输入语义见 §7 解密策略 step 4）
       - 空输入 → 跳过该 identity，继续下一个
       - Ctrl+C / EOF → 整体退出码 3
     - 解锁 identity
     - 用该 identity 尝试解密
5. 解密失败 → 退出码 2，"no matching identity"
6. plaintext 写入 stdout（保留尾部换行原貌）
```

### 9.2 `edit <PATH>`

```
1. 解析 mount/path → 绝对文件路径 <abs>.age
2. 如果文件存在 → 同 show 的步骤 3-5 取得 plaintext
   如果文件不存在 → plaintext = "" (新建)
3. walk-up 找 .age-recipients：从 `parent(<abs>.age)` 起向上到 store root（逐级向上查找，**不依赖 <abs>.age 本身存在**，所以新文件也适用）
   找不到 → 退出码 1，"no .age-recipients found for <PATH>"
4. mkdtemp 在 $TMPDIR 创建 0700 目录，临时文件名使用 secret path 的 basename，不追加 `.txt`
   open tempfile (O_CREAT|O_EXCL, mode 0600)，写入 plaintext
   > 用 basename 是为了保留扩展名给编辑器做语法高亮（`api/openai.yaml` → yaml 模式）。外层目录 `0700` 已遮蔽其他 UID；同 UID 攻击者本来就有更强能力（ptrace、`/proc` 读内存），所以 basename 可见不扩大攻击面。接受此权衡
5. spawn $EDITOR (fallback: $VISUAL → "vi") on the tempfile, wait
6. 读回 modified
7. modified == plaintext → 不写盘，打印 "no changes"，退出 0
8. mkdir -p parent(<abs>.age)，中间**新建**的目录 mode 设为 `0700`（已存在的目录不改权限）；canonicalize parent 并确认仍在 canonical store root 内
9. 用步骤 3 的 recipients 加密 modified
10. 原子写入：
    - tmp 与目标文件同目录，文件名 `.<target>.tmp.<pid>`
    - open tmp (O_WRONLY|O_CREAT|O_EXCL, mode 0600)
    - write encrypted bytes, fsync(fd), rename(tmp, <abs>.age), fsync(parent dir)
11. best-effort cleanup: unlink tempfile, rmdir tempdir；不承诺安全擦除
12. 退出 0
```

异常：
- 编辑器非 0 退出 → 不写盘，**保留 tempfile 并打印路径**，提示 "editor exited non-zero, aborted; tempfile kept at <path>"，避免丢失用户正在编辑的内容
- 加密失败（recipients 解析错误等）→ tempfile 保留并打印路径，便于人工恢复
- 原子写失败 → 尽量清理同目录 tmp；tempfile 保留并打印路径，便于人工恢复
- 这三类异常统一保留 tempfile；正常结束（step 11）或未改动（step 7）才 best-effort 清理

### 9.3 Agent 子命令

均直接对应 §8 的协议；`add` / `start` 在 socket 不可用时触发 fork。

### 9.4 `list [PREFIX]` (alias: `ls`)

gopass 风格的树形列表，仅读取文件名，不做任何解密。别名 `ls` 与 gopass CLI 一致。

```
1. 解析 PREFIX：
   - 无参或空串 → 列出所有 mount，用统一的 "rspass" 顶级标签，每个 mount 作为顶级分支（带绝对路径注释），mount key 按字母序排列（root mount `""` 最先）
   - 非空 PREFIX → 走 §3 的最长组件前缀 mount 匹配，允许尾随 `/`；rel 部分可以为空（正好命中 mount）或指向某个子目录；最终指向文件系统里的一个目录
2. 顶级 label：
   - 列所有 mount 时：顶端固定是 `rspass`；下一层每个 mount 显示为 `<name> (<abs path>)`；root mount 的 name 显示为 `.` 以保持视觉对齐
   - 列 PREFIX 时：**不加 `rspass` 顶端**，直接把 `<PREFIX>/ (<abs path>)` 作为树根（与 `gopass list <prefix>` 一致）
3. 目录遍历：
   - 忽略以 `.` 开头的条目（`.age-recipients`、`.git/` 等）
   - 以 `.age` 结尾的文件作为 secret 叶子，去掉后缀显示
   - 其他文件忽略
   - 空目录（递归后没有 `.age` 子项）不输出
4. 排序：同级目录在前、文件在后，各自内部按字母序
5. 渲染：每层 4 字符缩进；非末项用 `├── ` + `│   `，末项用 `└── ` + `    `；目录叶子附 `/`
6. PREFIX 解析失败：不存在的目录 → 退出码 1 并提示；前缀是 secret 文件（不是目录）→ 提示使用 `show`

示例输出：

    rspass
    ├── . (/Users/erning/.local/share/rspass)
    │   └── notes
    └── ai (/Users/erning/projects/gopass-ai)
        └── dashscope/
            └── api/
                └── key
```

---

## 10. 加密细节

### 加密参数

- 由 `age` crate 决定（X25519 + ChaCha20-Poly1305 + HKDF-SHA256），不暴露任何 tweak
- **不使用 ASCII armor**，写入二进制 `.age`：与 `age` CLI、gopass、pass 默认行为一致，避免迁移时格式不匹配；armored 输出在 git diff 里也仍然不可读（base64 一段大字符串），没有可读性收益
- 但解密时**接受** armored 输入（开 `armor` feature 自动检测），方便从其他工具迁移

### 文件原子性

写：
```
1. mkdir -p parent(<abs>.age)，新建目录 mode `0700`（已存在的不改）
2. canonicalize parent 并确认仍在 canonical store root 内
3. open 同目录 `.<target>.tmp.<pid>` (O_WRONLY|O_CREAT|O_EXCL, mode 0600)
4. write encrypted bytes
5. fsync(fd)
6. rename(tmp, <abs>.age)
7. fsync(parent dir)
```

崩溃中段不会留下损坏的目标文件；可能残留同目录 `.tmp` 文件。tmp 名包含 PID，后续写入不会固定撞上同一个残留文件；仍使用 `O_EXCL` 防碰撞。

### Passphrase Prompt

- 通过 `/dev/tty` 直接读，不走 stdin / stdout
- 关闭回显
- Ctrl+C / EOF → 退出码 3；空输入（直接回车）**不**算取消，由调用方（§7 / §9.1）解释为"跳过当前 identity"
- 实现使用 `rpassword` crate

---

## 11. 错误处理与日志

- 内部使用 `thiserror` 定义 `RspassError`，CLI 边界统一映射到 exit code；`anyhow` 只用于附加上下文，不直接决定退出码
- `RspassError -> ExitCode`：
  - `Usage` / `Config` / `Path` / `Io` / `Recipients` / `Editor` / `CryptoFormat` → 1
  - `NoMatchingIdentity` → 2
  - `PassphraseCancelled` → 3（仅 Ctrl+C / EOF；空回车视为"跳过该 identity"，不抛此错误）
  - `AgentUnavailable` / `AgentProtocol` / `AgentRejected` → 4
- agent `decrypt` 返回 `no_matching_identity` 不算 agent 通信失败；CLI 继续本地 identity 回退，只有本地也失败时退出码 2
- agent socket 连接失败、超时、JSON 解析失败、peer credential 校验失败 → 退出码 4；但 `show` / `edit` 中连接 agent 失败只表示 agent 不可用，继续本地回退，不立即退出 4
- 打印规则：
  - CLI 默认只打印一行 human-readable error 到 stderr，不打印 backtrace
  - `-v` 打印错误链和 debug 日志
  - passphrase 取消只打印简短信息，不打印内部错误链
- daemon 内部错误写到 socket 父目录下的 `agent.log`，自动 rotate（按大小，1 MB × 3）
- agent 日志**不持久化**：socket 父目录通常在 `$XDG_RUNTIME_DIR`（logout / 重启即清）或 `$TMPDIR`（多数系统重启清理），`agent.log` 生命周期与之一致。需要长期保留请用户自行 `tail -F` 重定向到持久位置
- CLI 默认安静，`-v` 打开 debug 日志到 stderr

---

## 12. 项目结构

```
rspass/
├── Cargo.toml
├── DESIGN.md                    # 本文档
├── README.md
└── src/
    ├── main.rs                  # clap 入口、子命令分发
    ├── config.rs                # config.yaml 加载、store/identity 查找
    ├── path.rs                  # mount/path 解析、文件系统映射
    ├── recipients.rs            # walk-up .age-recipients、解析 age + ssh
    ├── identity.rs              # 加载 identity 文件、scrypt 检测
    ├── crypto.rs                # encrypt/decrypt 包装
    ├── tty.rs                   # /dev/tty passphrase prompt
    ├── agent/
    │   ├── mod.rs
    │   ├── proto.rs             # JSON 协议
    │   ├── socket.rs            # socket 路径、getpeereid
    │   ├── client.rs
    │   ├── server.rs            # daemon 主循环
    │   └── spawn.rs             # fork+detach
    └── cmd/
        ├── show.rs
        ├── edit.rs
        └── agent.rs
```

### 主要依赖

| Crate | 用途 |
|---|---|
| `age` (0.11+, features: `ssh`, `armor`) | 核心加解密 |
| `clap` (4.x, derive) | CLI 解析 |
| `serde` + `serde_yaml_ng` | 配置 |
| `rpassword` | passphrase prompt |
| `rustix` | `getpeereid`、文件 mode、`fork`/`setsid` |
| `dirs` | XDG / macOS 配置目录 |
| `tempfile` | 编辑用临时目录 |
| `serde_json` | agent 协议 |
| `anyhow` + `thiserror` | 错误 |
| `zeroize` | 解密后明文/identity buffer 显式清零 |
| `tracing` + `tracing-subscriber` | CLI `-v` debug 日志与 daemon `agent.log` |

### 实现顺序（按可独立验证的小步走）

1. `config.rs` + `path.rs` — 解析 `work/db/prod` 到绝对路径，单元测试覆盖
2. `recipients.rs` — walk-up + 解析 age/ssh 行
3. `identity.rs` (明文部分) + `crypto.rs` + `cmd/show.rs` — 跑通"`age` CLI 手动加密 → `rspass show` 解密"
4. `tty.rs` + scrypt 解析 — `show` 支持按 config 顺序 prompt 加密 identity
5. `cmd/edit.rs` — 含新文件、原子写、tempfile 清理
6. `agent/proto.rs` + `agent/server.rs` + `agent/socket.rs` — daemon 能跑 + JSON 通信
7. `agent/spawn.rs` + `agent/client.rs` + `cmd/agent.rs` — 完整 `agent {start,stop,status,add,rm,ls}`
8. `show` / `edit` 接 agent client — 优先调用 agent `decrypt`，失败后走本地 identity 回退

每步一个 git commit。

---

## 13. 显式不做的事 / 未来可能扩展

- **`init <store>`**：v1 不做，用户手动 `mkdir` + 写 `.age-recipients` + 改 config
- **`find` / `grep`**：v1 不做；用 shell `find` / `rg` 直接对 store 目录足够
- **`rm` / `mv` / `cp`**：v1 不做；用 shell 直接操作（recipients 不变，无需重加密）
- **重加密（rotate）**：v1 不做；recipients 变更后用户得自己 `show` + `edit` 触发重写。未来可加 `rspass reencrypt <store>` 批量化
- **Git 集成**：v1 不做；用户自己在 store 目录里 `git init` / `git commit`
- **导出 / 导入 gopass store**：v1 不做（gopass 用 GPG，需要单独工具转换）
- **Windows**：v1 不支持（agent socket 在 Windows 上需要 named pipe 改写）

---

## 14. 安全姿态声明

- **威胁模型**：保护静态文件（备份泄露、git remote 泄露、丢失的设备）。**不**抵御本机同 UID 的攻击者
- **agent 进程的内存**可被同 UID ptrace / `/proc` 读取；如不可接受请不要使用 agent，改为每次输入 passphrase
- **明文 secret 的 plaintext** 在 `show` 时进入 stdout，用户负责终端 / 管道下游的安全（截屏、剪贴板、shell history）
- **temp 文件**在 `edit` 中只做 best-effort 删除，不承诺安全擦除；swap / journal / editor backup / filesystem snapshot 等可能保留明文残留
  - 实操建议：把 `$EDITOR` 配成抑制落盘的形式，例如：
    - `EDITOR='vim -n -c "set noundofile nobackup nowritebackup"'`（`-n` 禁 swap，`noundofile` 禁 undo 文件，`nobackup`/`nowritebackup` 禁备份文件）
    - `EDITOR='nvim -n -c "set noundofile nobackup nowritebackup"'`
    - Emacs 使用者：`(setq auto-save-default nil make-backup-files nil create-lockfiles nil)`
  - 上述仅减少磁盘残留，不能消除 OS 级 swap / fs snapshot；全面防护需要配合加密 swap、关闭 fs snapshot 等系统层手段
- **`.age-recipients`** 文件**不加密**，公钥列表对任何能读 store 的人可见。用户名 / 邮箱不要出现在公钥注释里如果需要保密
