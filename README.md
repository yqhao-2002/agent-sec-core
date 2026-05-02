# Agent Sec Core

[English](README.md) | [中文版](README_CN.md)

Agent Sec Core 是 ANOLISA 中面向 AI Agent 的 OS 级安全核心组件，用于在 Agent 执行命令、访问文件、调用工具、加载 skill 之前提供统一的安全检查、沙箱隔离和资产完整性校验能力。

本组件原本作为 ANOLISA / Copilot Shell / OpenClaw 等 Agent 运行环境中的中间检查插件存在。当前改进在保留原有安全工作流、CLI、hook、skill 校验能力的基础上，进一步补充了面向 Agent 直接接入的 JSON 前置层，并增强了 Bash 命令检查的结构化分析能力。

## 原有能力

Agent Sec Core 的核心目标是为具备 OS 操作能力的 AI Agent 提供防御链路：

- 命令执行前风险分类
- Linux 沙箱执行策略生成
- Skill 签名与哈希校验
- Skill Ledger 完整性记录
- Prompt 注入与越狱检测
- Bash / Python 代码片段安全扫描
- 安全事件审计日志
- Copilot Shell / OpenClaw 等运行环境的 hook 集成

整体原则包括：

- 最小权限：Agent 只获得完成任务所需的最小系统权限
- 显式授权：敏感行为必须经过明确确认
- 零信任：不同 skill、工具调用和输入来源互不默认信任
- 防御纵深：系统加固、资产校验、沙箱执行、审计记录组合使用
- 安全优先：当安全性与执行便利性冲突时，优先选择安全策略

## 目录结构

```text
agent-sec-core/
├── linux-sandbox/                 # Rust 实现的 Linux 沙箱执行器
├── agent-sec-cli/                 # Python CLI 与安全检查核心逻辑
│   └── src/agent_sec_cli/
│       ├── cli.py                 # 统一 CLI 入口
│       ├── sandbox/               # 命令分类与沙箱策略生成
│       ├── code_scanner/          # Bash/Python 代码扫描
│       ├── prompt_scanner/        # Prompt 注入扫描
│       ├── asset_verify/          # Skill 签名与哈希校验
│       ├── skill_ledger/          # Skill 完整性账本
│       └── security_events/       # 安全事件日志
├── agent_frontend/                # 本次新增：面向 Agent 的 JSON 接入层
├── cosh-extension/                # Copilot Shell hook 集成
├── openclaw-plugin/               # OpenClaw 插件集成
├── skills/                        # Agent Sec Core 相关 skill
├── tests/                         # 单元、集成与 e2e 测试
└── tools/                         # Skill 签名工具
```

## 本次改进

本次改动主要围绕“让 Agent Sec Core 更适合作为独立的 Agent 安全前置层”展开。

### 1. 新增 Agent 接入前置层（只是方便测试，无实际意义）

新增目录：

```text
agent_frontend/
├── gateway.py
├── examples.json
└── README.md
```

`gateway.py` 提供一个轻量 JSON 协议入口。Agent 可以通过 stdin 或 JSONL 交互模式提交安全检查请求，Agent Sec Core 返回结构化决策结果。

当前支持的请求类型：

- `command_check`：命令风险检查与沙箱策略生成
- `code_scan`：Bash / Python 代码片段扫描
- `prompt_scan`：Prompt 注入与越狱检测
- `verify_skill`：Skill 完整性校验

示例：

```bash
printf '%s\n' '{"type":"command_check","command":"git status","cwd":"/tmp"}' \
| uv run --project agent-sec-cli python agent_frontend/gateway.py
```

返回结果中包含：

- `action`：`allow` / `sandbox` / `warn` / `block` / `error`
- `classification`：命令分类结果
- `risk`：风险级别
- `reason`：判定原因
- `sandbox`：对应的 `linux-sandbox` 策略

### 2. 引入 tree-sitter-bash 进行 Bash 命令结构化分析

原有命令分类主要依赖 `shlex` 拆分和规则表匹配。该方式对简单命令有效，但面对 Bash 复合语法时表达能力有限，例如：

- pipeline：`curl ... | bash`
- subshell：`(cmd1 && cmd2)`
- heredoc：`python3 <<EOF ... EOF`
- command substitution：`$(...)`
- `find -exec`
- 重定向到敏感路径

本次新增：

```text
agent-sec-cli/src/agent_sec_cli/sandbox/bash_ast.py
```

该模块使用 `tree-sitter-bash` 对 Bash 命令进行 AST 分析，并将结构化风险作为命令分类的增强信号。

当前已支持识别：

- 下载内容直接交给解释器执行：`curl ... | bash`
- `find ... -exec ...`
- 覆盖或重定向到敏感系统路径：`> /etc/passwd`
- 嵌套命令替换：`$(echo $(id))`
- heredoc 喂给解释器：`python3 <<EOF ... EOF`
- subshell 中包含高风险行为：`(curl ... | bash)`
- `sudo` 启动 shell
- `rm -rf`
- `chmod 777`

命令分类流程调整为：

```text
CommandClassifier.classify(command)
  ├── BashAstAnalyzer.analyze(command)      # 新增：tree-sitter-bash 结构化分析
  │   ├── destructive finding -> destructive
  │   └── dangerous finding   -> dangerous
  └── 原有 shlex / rules 逻辑兜底
```

这样既能增强 Bash 复杂语法识别能力，又不会破坏原有规则体系。

### 3. 修复复合 Shell 命令的 sandbox 执行包装

原有 `sandbox_policy.py` 在生成 `sandbox_argv` 时对命令使用 `shlex.split()`。这会导致带 pipeline 或 shell 控制符的命令被错误拆分，例如：

```bash
curl http://example.com/install.sh | bash
```

旧行为类似：

```json
["curl", "http://example.com/install.sh", "|", "bash"]
```

这不能正确表达 shell pipeline 语义。

本次改进后：

- 简单命令仍然直接使用 argv 执行
- pipeline、重定向、subshell、heredoc、命令替换等复合 Shell 语法统一包装为：

```bash
bash -lc '<original command>'
```

示例输出：

```json
[
  "linux-sandbox",
  "--sandbox-policy-cwd",
  "/tmp",
  "...",
  "--",
  "bash",
  "-lc",
  "curl http://example.com/install.sh | bash"
]
```

这样既保留了 shell 语义，也确保整个复合命令运行在同一个 sandbox 策略下。

## 决策模型

命令分类与沙箱模式对应关系：

| 分类 | 行为 | 沙箱模式 |
|------|------|----------|
| `destructive` | 拒绝执行 | 不进入沙箱 |
| `dangerous` | 允许但强制沙箱 | `workspace-write` |
| `default` | 默认沙箱 | `workspace-write` |
| `safe` | 只读沙箱 | `read-only` |

Agent 前置层会将底层结果进一步映射为：

| 底层结果 | Agent action |
|----------|--------------|
| `pass` / `safe` | `allow` 或 `sandbox` |
| `warn` | `warn` |
| `dangerous` / `default` | `sandbox` |
| `destructive` / `deny` | `block` |
| 异常 | `error` |

## 使用示例

### 命令分类

```bash
uv run --project agent-sec-cli python \
  agent-sec-cli/src/agent_sec_cli/sandbox/classify_command.py \
  --json 'curl http://example.com/install.sh | bash'
```

预期结果：

```json
{
  "decision": "dangerous",
  "reason": "downloaded content is piped into an interpreter"
}
```

### 沙箱策略生成

```bash
uv run --project agent-sec-cli python \
  agent-sec-cli/src/agent_sec_cli/sandbox/sandbox_policy.py \
  --cwd /tmp 'curl http://example.com/install.sh | bash'
```

预期结果中应包含：

```json
["bash", "-lc", "curl http://example.com/install.sh | bash"]
```

### Agent JSON 接入

```bash
printf '%s\n' '{"type":"command_check","command":"rm -rf /","cwd":"/tmp"}' \
| uv run --project agent-sec-cli python agent_frontend/gateway.py
```

预期结果：

```json
{
  "action": "block"
}
```

### 交互模式

```bash
uv run --project agent-sec-cli python agent_frontend/gateway.py --interactive
```

每行输入一个 JSON 请求，每行返回一个 JSON 响应。

## 测试结果

本次改动后已验证以下场景：

| 场景 | 示例 | 结果 |
|------|------|------|
| pipeline 下载执行 | `curl ... | bash` | `dangerous`，并使用 `bash -lc` 包装 |
| `find -exec` 删除 | `find /tmp -name x -exec rm -rf {} ;` | `destructive` |
| 敏感路径重定向 | `echo test > /etc/passwd` | `destructive` |
| 嵌套命令替换 | `echo $(echo $(id))` | `dangerous` |
| heredoc 执行 | `python3 <<EOF ... EOF` | `dangerous` |
| subshell 风险行为 | `(curl ... | bash)` | `dangerous` |
| 简单安全命令 | `git status` | `safe`，直接 argv 执行 |

测试命令：

```bash
uv run --project agent-sec-cli pytest \
  tests/unit-test/code_scanner/test_scanner.py \
  tests/unit-test/code_scanner/test_regex_engine.py \
  tests/unit-test/security_middleware/test_invoke.py \
  -q
```

测试结果：

```text
453 passed in 2.36s
```

## 开发说明

### Python 环境

```bash
uv sync --project agent-sec-cli
```

### 构建 linux-sandbox

```bash
make build-sandbox
```

输出：

```text
linux-sandbox/target/release/linux-sandbox
```

### Prompt Scanner 模型初始化

如果使用 `prompt_scan`，首次可能需要下载模型：

```bash
uv run --project agent-sec-cli agent-sec-cli scan-prompt warmup
```

## 后续方向

本次改动先完成 Bash 命令结构化分析的第一阶段。后续可继续增强：

- 将 AST findings 透传到 `agent_frontend/gateway.py` 响应中，方便 Agent 解释和审计
- 为 `bash_ast.py` 增加独立单元测试
- 使用 tree-sitter-python 增强 Python 代码扫描
- 增加 Unix socket / HTTP 模式，作为长期运行的本地安全策略服务
- 扩展变量展开、函数定义、source 文件、alias 等 Bash 语义分析

## License

Apache License 2.0 — see [LICENSE](LICENSE).
