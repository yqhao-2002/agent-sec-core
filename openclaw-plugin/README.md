# agent-sec OpenClaw Plugin

OpenClaw security plugin that hooks into the agent lifecycle via `agent-sec-cli`, providing code scanning, skill integrity verification and prompt analysis.

---

## Prerequisites

| Dependency     | Version   | Check                        |
|----------------|-----------|------------------------------|
| Node.js        | >= 20     | `node --version`             |
| npm            | >= 10     | `npm --version`              |
| OpenClaw       | >= 0.8.0  | `openclaw --version`         |
| agent-sec-cli  | (latest)  | `agent-sec-cli --help`       |
| jq             | >= 1.6    | `jq --version`               |

---

## Project Structure

```
openclaw-plugin/
├── src/                        # TypeScript source
│   ├── index.ts                # Plugin entry point (definePluginEntry)
│   ├── types.ts                # SecurityCapability interface
│   ├── utils.ts                # CLI invocation utility (callAgentSecCli)
│   └── capabilities/           # One file per security capability
│       ├── skill-ledger.ts     #   before_tool_call 
│       ├── code-scan.ts        #   before_tool_call hook
│       └── prompt-scan.ts      #   before_dispatch hook
├── tests/                      # Test utilities (not compiled into dist/)
│   ├── test-harness.ts         # Mock OpenClaw API for local testing
│   ├── smoke-test.ts           # Smoke test for all capabilities
│   └── unit/                   # Unit tests
│       ├── code-scan.test.ts   #   code-scan handler tests
│       └── skill-ledger-test.ts #  skill-ledger handler tests
├── scripts/
│   └── deploy.sh               # Deployment and registration script
├── dist/                       # Compiled JS output (gitignored)
├── openclaw.plugin.json        # Plugin manifest
├── package.json
└── tsconfig.json
```

---

## Build

### Install Dependencies

```bash
cd src/agent-sec-core/openclaw-plugin
npm install
```

### Compile TypeScript

```bash
npm run build
```

This runs `tsc --project tsconfig.json` and outputs compiled JS to `dist/`.

### Verify Build Output

```bash
ls dist/
# Expected: capabilities/  index.js  index.d.ts  types.js  types.d.ts  utils.js  utils.d.ts
```

> **Note:** Test files in `tests/` are excluded from `dist/` since they live outside `src/`.

---

## Deploy to OpenClaw

### Option A: Deploy from Source (Development)

Point `deploy.sh` directly at the source directory:

```bash
# Build first
npm run build

# Deploy — pass the plugin directory as argument
./scripts/deploy.sh "$(pwd)"
```

### Option B: Deploy from Packaged Tarball

```bash
# Create tarball
npm run pack
# Output: agent-sec-openclaw-plugin-0.3.0.tgz

# Extract to target directory
mkdir -p /opt/agent-sec/openclaw-plugin
tar -xzf agent-sec-openclaw-plugin-0.3.0.tgz \
    --strip-components=1 \
    -C /opt/agent-sec/openclaw-plugin

# Deploy
./scripts/deploy.sh /opt/agent-sec/openclaw-plugin
```

### Option C: Install via Makefile (Development/Testing)

```bash
# From agent-sec-core root directory
cd src/agent-sec-core

# Build the plugin
make build-openclaw-plugin

# Install files to /opt/agent-sec/openclaw-plugin/
sudo make install-openclaw-plugin

# Register the plugin with OpenClaw
sudo /opt/agent-sec/openclaw-plugin/scripts/deploy.sh /opt/agent-sec/openclaw-plugin

# Restart gateway to load the plugin
openclaw gateway restart
```

> **Note:** `make install-openclaw-plugin` only copies files. You must run `deploy.sh` separately to register the plugin.

---

## What `deploy.sh` Does

The deployment script performs these steps:

1. **Pre-checks** — Verifies `openclaw` and `agent-sec-cli` are in PATH; validates `openclaw.plugin.json` and `dist/` exist
2. **Plugin installation** — Runs `openclaw plugins install <path> --force --dangerously-force-unsafe-install` to register the plugin
3. **User guidance** — Displays instructions to restart the OpenClaw gateway (does NOT restart automatically)

> **Important:** `deploy.sh` only registers the plugin with OpenClaw config. It does **NOT** start/stop/restart the gateway service.
> 
> To restart the gateway:
> ```bash
> openclaw gateway restart  # Recommended: OpenClaw CLI
> # Or
> systemctl --user restart openclaw-gateway-dev.service  # If using systemd user service
> ```

### Custom Config Path

```bash
OPENCLAW_CONFIG=~/.openclaw-dev/openclaw.json ./scripts/deploy.sh "$(pwd)"
```

---

## Verify Installation

After deployment, verify the plugin is loaded:

```bash
openclaw plugins inspect agent-sec
```

Expected output:

```
Agent Security
id: agent-sec
Security hooks powered by agent-sec-cli

Status: loaded
Version: 0.3.0
Source: ~/path/to/openclaw-plugin/dist/index.js

Typed hooks:
before_dispatch (priority 190)
before_tool_call (priority 80)
before_tool_call (priority 0)
```

---

## Testing

### Smoke Test (Mock Mode)

Runs all capabilities against mock events without requiring a real `agent-sec-cli` installation:

```bash
npm run smoke
```

### Smoke Test (Live Mode)

Runs against the real `agent-sec-cli` binary:

```bash
AGENT_SEC_LIVE=1 npm run smoke
```

---

## Plugin Capabilities

| Capability         | Hook                  | Priority | Behavior                                             |
|--------------------|-----------------------|----------|------------------------------------------------------|
| `prompt-scan`      | `before_dispatch`     | 190      | Scans inbound messages for prompt injection attacks   |
| `code-scan`        | `before_tool_call`    | 0 (default) | Scans tool commands for security issues              |
| `skill-ledger`     | `before_tool_call`    | 80       | Checks skill integrity when SKILL.md is read         |

### Configuring `skill-ledger`

The `skill-ledger` capability checks skill integrity by invoking `agent-sec-cli skill-ledger check` when the agent reads a `SKILL.md` file. It automatically initializes signing keys on first use.

**Prerequisites**: `agent-sec-cli skill-ledger check` must be available. Signing keys are auto-initialized (no passphrase) if not present.

---

## Upgrade

To upgrade the plugin to a new version:

### Development Environment

```bash
cd src/agent-sec-core/openclaw-plugin

# Pull latest changes
git pull

# Rebuild
npm install
npm run build

# Re-register plugin (updates to new version)
./scripts/deploy.sh "$(pwd)"

# Restart gateway
openclaw gateway restart
```

### Production Environment (Installed via Makefile)

```bash
cd src/agent-sec-core

# Rebuild and install files
make build-openclaw-plugin
sudo make install-openclaw-plugin

# Re-register plugin
sudo /opt/agent-sec/openclaw-plugin/scripts/deploy.sh /opt/agent-sec/openclaw-plugin

# Restart gateway
openclaw gateway restart
```

The `openclaw plugins install --force` command automatically updates the plugin to the new version. Other plugins are unaffected.
