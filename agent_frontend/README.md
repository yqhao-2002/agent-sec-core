# Agent Frontend

This directory contains a simple agent-facing frontend for Agent Sec Core.

It is not a web UI. It is a lightweight integration entrypoint that lets an
agent send structured security-check requests and receive structured decisions
back as JSON.

## Goals

- Provide one stable JSON protocol for agent integrations
- Reuse existing Agent Sec Core engines directly
- Support single-shot invocation and line-delimited interactive sessions
- Return decisions that are easy for an agent runtime to consume

## Supported request types

- `command_check`
  - Classify a shell command
  - Generate a sandbox policy preview
- `code_scan`
  - Scan bash or python code
- `prompt_scan`
  - Scan prompt text for injection or jailbreak attempts
- `verify_skill`
  - Verify one skill or the configured skill roots

## Quick start

Single request from stdin:

```bash
/home/hush/.local/bin/uv run --project agent-sec-cli python agent_frontend/gateway.py <<'EOF'
{
  "type": "command_check",
  "command": "git status",
  "cwd": "/tmp"
}
EOF
```

Interactive JSONL mode:

```bash
/home/hush/.local/bin/uv run --project agent-sec-cli python agent_frontend/gateway.py --interactive
```

Then send one JSON object per line.

## Decision model

The gateway normalizes results into these actions:

- `allow`
- `sandbox`
- `warn`
- `block`
- `error`

For command checks:

- `destructive` -> `block`
- `dangerous` -> `sandbox`
- `safe` -> `sandbox`
- `default` -> `sandbox`

For code and prompt scans:

- `pass` -> `allow`
- `warn` -> `warn`
- `deny` -> `block`
- `error` -> `error`

## Prompt scanner note

`prompt_scan` uses the existing prompt scanner in `agent-sec-cli`. If the local
ML model has not been downloaded yet, the gateway returns an `error` response
with the warmup command:

```bash
/home/hush/.local/bin/uv run --project agent-sec-cli agent-sec-cli scan-prompt warmup
```

## Request examples

See [examples.json](/home/hush/agent-sec-core/agent_frontend/examples.json).
