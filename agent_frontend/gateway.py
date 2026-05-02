#!/usr/bin/env python3
"""Simple agent-facing frontend for Agent Sec Core."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CLI_SRC = ROOT / "agent-sec-cli" / "src"
if str(CLI_SRC) not in sys.path:
    sys.path.insert(0, str(CLI_SRC))

from agent_sec_cli.asset_verify import run_verification
from agent_sec_cli.code_scanner.models import Language
from agent_sec_cli.code_scanner.scanner import scan as scan_code
from agent_sec_cli.prompt_scanner.config import ScanMode
from agent_sec_cli.prompt_scanner.scanner import PromptScanner
from agent_sec_cli.sandbox.classify_command import CommandClassifier
from agent_sec_cli.sandbox.sandbox_policy import generate_sandbox_policy


def _ok_response(request_type: str, action: str, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": True,
        "type": request_type,
        "action": action,
        "result": result,
    }


def _error_response(request_type: str, message: str) -> dict[str, Any]:
    return {
        "ok": False,
        "type": request_type,
        "action": "error",
        "error": message,
    }


def _risk_from_command_decision(decision: str) -> str:
    mapping = {
        "destructive": "critical",
        "dangerous": "high",
        "default": "medium",
        "safe": "low",
    }
    return mapping.get(decision, "unknown")


def _action_from_scan_verdict(verdict: str) -> str:
    mapping = {
        "pass": "allow",
        "warn": "warn",
        "deny": "block",
        "error": "error",
    }
    return mapping.get(verdict, "error")


def handle_command_check(payload: dict[str, Any]) -> dict[str, Any]:
    command = str(payload.get("command", "")).strip()
    cwd = str(payload.get("cwd", "")).strip() or str(Path.cwd())
    if not command:
        return _error_response("command_check", "missing required field: command")

    classification = CommandClassifier().classify(command)
    sandbox = generate_sandbox_policy(command, cwd)

    decision = classification["decision"]
    action = "block" if decision == "destructive" else "sandbox"
    result = {
        "command": command,
        "cwd": cwd,
        "classification": decision,
        "risk": _risk_from_command_decision(decision),
        "reason": classification.get("reason", ""),
        "additional_permissions": classification.get("additional_permissions"),
        "sandbox": sandbox,
    }
    return _ok_response("command_check", action, result)


def handle_code_scan(payload: dict[str, Any]) -> dict[str, Any]:
    code = str(payload.get("code", ""))
    language_raw = str(payload.get("language", "bash")).lower()
    if not code.strip():
        return _error_response("code_scan", "missing required field: code")
    if language_raw not in ("bash", "python"):
        return _error_response("code_scan", "language must be 'bash' or 'python'")

    language = Language(language_raw)
    result = scan_code(code, language)
    verdict = result.verdict.value
    return _ok_response(
        "code_scan",
        _action_from_scan_verdict(verdict),
        {
            "verdict": verdict,
            "summary": result.summary,
            "language": result.language.value,
            "elapsed_ms": result.elapsed_ms,
            "findings": [f.model_dump() for f in result.findings],
            "engine_version": result.engine_version,
        },
    )


def handle_prompt_scan(payload: dict[str, Any]) -> dict[str, Any]:
    text = str(payload.get("text", ""))
    mode_raw = str(payload.get("mode", "standard")).lower()
    source = str(payload.get("source", "user_input")).strip() or "user_input"
    if not text.strip():
        return _error_response("prompt_scan", "missing required field: text")

    try:
        mode = ScanMode(mode_raw)
    except ValueError:
        return _error_response("prompt_scan", "mode must be one of: fast, standard, strict")

    scanner = PromptScanner(mode=mode)
    result = scanner.scan(text, source=source)
    normalized = result.to_dict()
    return _ok_response(
        "prompt_scan",
        _action_from_scan_verdict(normalized["verdict"]),
        normalized,
    )


def handle_verify_skill(payload: dict[str, Any]) -> dict[str, Any]:
    skill = payload.get("skill")
    skill_path = str(skill).strip() if skill is not None else None
    ok = run_verification(skill_path)
    action = "allow" if ok else "block"
    return _ok_response(
        "verify_skill",
        action,
        {
            "verified": ok,
            "skill": skill_path,
        },
    )


def dispatch(payload: dict[str, Any]) -> dict[str, Any]:
    request_type = str(payload.get("type", "")).strip()
    if not request_type:
        return _error_response("unknown", "missing required field: type")

    try:
        if request_type == "command_check":
            return handle_command_check(payload)
        if request_type == "code_scan":
            return handle_code_scan(payload)
        if request_type == "prompt_scan":
            return handle_prompt_scan(payload)
        if request_type == "verify_skill":
            return handle_verify_skill(payload)
        return _error_response(request_type, f"unsupported request type: {request_type}")
    except Exception as exc:  # pragma: no cover - defensive gateway wrapper
        return _error_response(request_type, str(exc))


def _print_json(obj: dict[str, Any]) -> None:
    print(json.dumps(obj, ensure_ascii=False))


def run_single() -> int:
    raw = sys.stdin.read().strip()
    if not raw:
        _print_json(_error_response("unknown", "empty stdin"))
        return 1
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        _print_json(_error_response("unknown", f"invalid JSON: {exc}"))
        return 1
    response = dispatch(payload)
    _print_json(response)
    return 0 if response.get("ok") else 1


def run_interactive() -> int:
    for line in sys.stdin:
        raw = line.strip()
        if not raw:
            continue
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            _print_json(_error_response("unknown", f"invalid JSON: {exc}"))
            continue
        _print_json(dispatch(payload))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Agent-facing frontend for Agent Sec Core")
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Read one JSON request per line from stdin and emit one JSON response per line",
    )
    args = parser.parse_args()
    return run_interactive() if args.interactive else run_single()


if __name__ == "__main__":
    raise SystemExit(main())
