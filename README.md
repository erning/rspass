# rspass

极简命令行敏感信息管理器，仅以 [age](https://age-encryption.org/) 为加密后端。

定位是 [gopass](https://github.com/gopasspw/gopass) 的轻量替代——保留"目录树 + 单文件加密"的存储模型，去掉 GPG、剪贴板、模板、TOTP、密码生成器等所有非核心功能。完整设计规格见 [`docs/DESIGN.md`](docs/DESIGN.md)。

## 特性

- 单二进制，运行时无外部依赖（不需要安装 `age` CLI）
- gopass 兼容的存储布局：每条 secret 一个独立 `.age` 文件，直接 git 同步
- 多 store、多 recipient，目录级 recipient 覆盖
- 可选的内存 agent：预解锁 identity 避免反复输入 passphrase
- 命令集最小：`show` / `edit` / `list` / `config` / `agent`

**显式不做**：GPG、剪贴板、模板、TOTP、密码生成器、Web UI、Windows 支持。详见 [`docs/DESIGN.md` §1](docs/DESIGN.md)。

## 安装

从源码编译：

```sh
cargo build --release
install -m 755 target/release/rspass ~/.local/bin/
```

或者从 [GitHub Releases](https://github.com/erning/rspass/releases) 下载预编译二进制（`linux-x86_64` / `linux-aarch64` / `macos-aarch64` / `macos-x86_64`）。

## 快速上手

```sh
# 1. 生成一把 age 密钥
age-keygen -o ~/.config/rspass/identity.txt
# 输出里包含 "# public key: age1..."，把 age1... 那串记下来

# 2. 建 store 目录并声明 recipient
mkdir -p ~/.local/share/rspass/personal
echo 'age1...' > ~/.local/share/rspass/personal/.age-recipients

# 3. 写配置
cat > ~/.config/rspass/config.yaml <<'YAML'
mounts:
  "": ~/.local/share/rspass/personal
identities:
  - ~/.config/rspass/identity.txt
YAML

# 4. 使用
rspass edit db/prod          # 打开 $EDITOR，保存后加密写入
rspass show db/prod          # 解密到 stdout
rspass list                  # 树形列出全部 secret
```

## 配置

`~/.config/rspass/config.yaml`（遵循 `XDG_CONFIG_HOME`；可用 `-c PATH` 临时覆盖）：

```yaml
mounts:
  "":        ~/.local/share/rspass/personal   # root mount
  "work":    ~/work-secrets
  "team/db": /shared/team-db                  # mount key 允许多段

identities:
  - ~/.config/rspass/identity.txt
  - ~/.config/rspass/work.txt                 # 按顺序尝试解密
```

- **路径语法**：`[MOUNT/]REL/PATH`，按 mount key 的路径组件做**最长前缀**匹配；`""` 是可选的 root mount
- **identities**：支持明文 age identity、scrypt 加密 age、未加密 SSH 私钥、加密 SSH 私钥；列表顺序决定本地回退的尝试顺序
- **include**：主 config 可以 `include:` 子文件拆分，加载顺序为 `[main, include...]`，`mounts` / `identities` 首次出现者胜出
- **路径展开**：支持 `~`、`${VAR}`；转义用 `\~` / `\$`；详见 [`docs/DESIGN.md` §5](docs/DESIGN.md)

用 `rspass config` 打印合并后的有效配置（展开 `include:`）。

## Recipients

每个 store 在根目录放一个 `.age-recipients`，每行一个公钥：

```
# alice laptop
age1abcde...

# work ssh key
ssh-ed25519 AAAA... user@host
```

支持 `age1...` (X25519) 和 `ssh-ed25519` / `ssh-rsa`。加密一条 secret 时，从它所在目录向上 walk 到 store root，**使用第一个遇到的 `.age-recipients`**（不与上层叠加）。子目录想沿用父目录就别建本地文件；想覆盖就在本目录再建一个。

## Agent

agent 是**可选**的内存 keychain，只存放已解锁的 identity，通过 Unix socket 协议接受 `decrypt` 请求。identity 一旦加入，**没有 TTL 也不 idle evict**，直到 `agent stop` / `agent rm` 才清除。协议不提供导出操作。

```sh
rspass agent start        # 启动 daemon（幂等）
rspass agent add          # 加载 config.identities 全部（scrypt/加密 SSH 会 prompt）
rspass agent add PATH     # 加载单个 identity
rspass agent ls           # 列出已加载身份和公钥
rspass agent status       # socket 路径、PID、身份数
rspass agent rm PATH      # 移除
rspass agent stop         # 关闭 daemon
```

- 不运行 agent 时，`show` / `edit` 按 `config.identities` 顺序在本地尝试并按需 prompt passphrase
- 运行 agent 后，`show` / `edit` 先请求 agent 解密；`no_matching_identity` 或连不上时自动回退到本地（不会因为 agent 挂掉而失败）
- Socket 在 `$RSPASS_AGENT_SOCK` → `$XDG_RUNTIME_DIR/rspass/agent.sock` → `$TMPDIR/rspass-agent.$UID/agent.sock` 依次查找
- 安全模型：父目录 `0700` + socket `0600` + `getpeereid` UID 校验。详见 [`docs/DESIGN.md` §8](docs/DESIGN.md)

## 退出码

| Code | 含义 |
|---|---|
| 0 | 成功 |
| 1 | 通用错误（参数、I/O、配置、编辑器） |
| 2 | 解密失败（找不到匹配 identity） |
| 3 | Passphrase 取消（Ctrl+C / EOF；空回车**不**算取消，只跳过当前 identity） |
| 4 | Agent 通信失败（仅 `agent` 子命令；`show` / `edit` 连不上 agent 会回退，不触发此码） |

## 日志

通过 `tracing` 输出到 stderr，默认级别 `warn`。用 `RUST_LOG` 控制：

```sh
RUST_LOG=debug rspass show foo       # 全部 debug
RUST_LOG=rspass=info rspass show foo # 只看 rspass 自己的 info+
```

## 安全姿态

- **威胁模型**：保护静态文件（备份泄露、git remote 泄露、设备丢失）
- **不**抵御本机同 UID 的攻击者（ptrace、`/proc` 读内存都能绕过 agent）
- `show` 输出的 plaintext 进 stdout，下游（终端、管道、shell history）安全由用户负责
- `edit` 的临时文件只做 best-effort 清理；需要避免 swap / undo / backup 残留请自行配置编辑器（具体建议见 [`docs/DESIGN.md` §14](docs/DESIGN.md)）

## 文档

- [`docs/DESIGN.md`](docs/DESIGN.md) — 完整规格（14 节）
- [`docs/RELEASING.md`](docs/RELEASING.md) — 发布流程
- [`AGENTS.md`](AGENTS.md) — 给 AI 代理的开发指引

## License

MIT OR Apache-2.0
