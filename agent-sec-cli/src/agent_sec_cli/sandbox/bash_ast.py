"""tree-sitter based bash command analysis.

This module is intentionally conservative.  It enriches command classification
when tree-sitter-bash is available, but callers can safely fall back to the
legacy rule engine when it is not installed or parsing fails.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


@dataclass
class BashAstFinding:
    rule_id: str
    severity: str
    message: str
    evidence: str
    node_type: str


@dataclass
class BashAstAnalysis:
    available: bool
    parsed: bool
    has_error: bool = False
    error: str = ""
    commands: list[str] = field(default_factory=list)
    findings: list[BashAstFinding] = field(default_factory=list)

    def best_decision(self) -> tuple[str | None, str]:
        if not self.available or not self.parsed:
            return None, self.error
        if self.has_error:
            return "dangerous", "bash AST parse error; using conservative sandbox policy"
        for finding in self.findings:
            if finding.severity == "destructive":
                return "destructive", finding.message
        for finding in self.findings:
            if finding.severity == "dangerous":
                return "dangerous", finding.message
        return None, ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine": "tree-sitter-bash",
            "available": self.available,
            "parsed": self.parsed,
            "has_error": self.has_error,
            **({"error": self.error} if self.error else {}),
            "commands": self.commands,
            "findings": [finding.__dict__ for finding in self.findings],
        }


class BashAstAnalyzer:
    """Analyze bash command structure with tree-sitter-bash."""

    _EXEC_INTERPRETERS = {
        "bash",
        "sh",
        "zsh",
        "dash",
        "ksh",
        "python",
        "python2",
        "python3",
        "perl",
        "ruby",
        "node",
        "nodejs",
        "php",
    }
    _DOWNLOADERS = {"curl", "wget"}
    _SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
    _SENSITIVE_PATH_PREFIXES = (
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/ssh/",
        "/etc/pam.d/",
        "/etc/security/",
        "/boot/",
        "/usr/lib/systemd/",
        "/etc/systemd/system/",
    )
    _OVERWRITE_REDIRECT_TYPES = {
        "file_redirect",
        "redirected_statement",
        "redirected_declaration_command",
    }
    _DELETE_PATHS = {"/", "/etc", "/usr", "/var", "/home", "/root", "/boot"}

    def __init__(self) -> None:
        self._parser = None
        self._init_error = ""
        try:
            from tree_sitter import Language, Parser
            import tree_sitter_bash

            language_obj = tree_sitter_bash.language()
            language = (
                language_obj
                if isinstance(language_obj, Language)
                else Language(language_obj)
            )
            parser = Parser()
            if hasattr(parser, "set_language"):
                parser.set_language(language)
            else:
                parser.language = language
            self._parser = parser
        except Exception as exc:  # pragma: no cover - optional dependency path
            self._init_error = str(exc)

    def analyze(self, command: str) -> BashAstAnalysis:
        if self._parser is None:
            return BashAstAnalysis(
                available=False,
                parsed=False,
                error=f"tree-sitter-bash unavailable: {self._init_error}",
            )

        try:
            source = command.encode("utf-8")
            tree = self._parser.parse(source)
            root = tree.root_node
        except Exception as exc:  # pragma: no cover - defensive parser wrapper
            return BashAstAnalysis(available=True, parsed=False, error=str(exc))

        analysis = BashAstAnalysis(
            available=True,
            parsed=True,
            has_error=bool(getattr(root, "has_error", False)),
        )
        commands = self._collect_commands(root, source)
        analysis.commands = [cmd.name for cmd in commands if cmd.name]
        analysis.findings.extend(self._detect_pipeline_download_exec(root, source))
        analysis.findings.extend(self._detect_command_substitution_exec(root, source))
        analysis.findings.extend(self._detect_nested_command_substitution(root, source))
        analysis.findings.extend(self._detect_sudo_shell(commands))
        analysis.findings.extend(self._detect_recursive_delete(commands))
        analysis.findings.extend(self._detect_find_exec(commands))
        analysis.findings.extend(self._detect_weak_permissions(commands))
        analysis.findings.extend(self._detect_subshells(root, source))
        analysis.findings.extend(self._detect_heredoc_exec(root, source))
        analysis.findings.extend(self._detect_sensitive_redirects(root, source))
        return analysis

    def _collect_commands(self, root: Any, source: bytes) -> list["_CommandNode"]:
        result: list[_CommandNode] = []
        for node in self._walk(root):
            if node.type != "command":
                continue
            words = self._direct_word_texts(node, source)
            if words:
                result.append(_CommandNode(node=node, name=words[0], args=words[1:]))
        return result

    def _detect_pipeline_download_exec(
        self, root: Any, source: bytes
    ) -> list[BashAstFinding]:
        findings: list[BashAstFinding] = []
        for node in self._walk(root):
            if node.type != "pipeline":
                continue
            commands = self._collect_commands(node, source)
            if len(commands) < 2:
                continue
            left_names = {cmd.name for cmd in commands[:-1]}
            right_names = {cmd.name for cmd in commands[1:]}
            if left_names & self._DOWNLOADERS and right_names & self._EXEC_INTERPRETERS:
                findings.append(
                    self._finding(
                        "bash.pipeline-download-exec",
                        "dangerous",
                        "downloaded content is piped into an interpreter",
                        node,
                        source,
                    )
                )
        return findings

    def _detect_command_substitution_exec(
        self, root: Any, source: bytes
    ) -> list[BashAstFinding]:
        findings: list[BashAstFinding] = []
        for command in self._collect_commands(root, source):
            if command.name not in {"eval", "source", "."}:
                continue
            if any(
                child.type in {"command_substitution", "process_substitution"}
                or "$(" in self._text(child, source)
                or "`" in self._text(child, source)
                for child in command.node.children
            ):
                findings.append(
                    self._finding(
                        "bash.dynamic-exec",
                        "dangerous",
                        "dynamic command output is executed",
                        command.node,
                        source,
                    )
                )
        return findings

    def _detect_sudo_shell(self, commands: list["_CommandNode"]) -> list[BashAstFinding]:
        findings: list[BashAstFinding] = []
        for command in commands:
            if command.name != "sudo":
                continue
            non_flags = [arg for arg in command.args if not arg.startswith("-")]
            if non_flags and non_flags[0] in self._SHELLS:
                findings.append(
                    BashAstFinding(
                        rule_id="bash.sudo-shell",
                        severity="dangerous",
                        message="sudo starts a shell; command should run in strict sandbox",
                        evidence=self._command_text(command),
                        node_type=command.node.type,
                    )
                )
        return findings

    def _detect_find_exec(self, commands: list["_CommandNode"]) -> list[BashAstFinding]:
        findings: list[BashAstFinding] = []
        for command in commands:
            if command.name != "find":
                continue
            text = self._command_text(command)
            if "-exec" not in command.args and "-exec" not in text:
                continue
            severity = (
                "destructive"
                if any(token in text for token in (" rm ", " rm;", " rm\\;", " shred "))
                else "dangerous"
            )
            findings.append(
                BashAstFinding(
                    rule_id="bash.find-exec",
                    severity=severity,
                    message="find uses -exec to invoke another command",
                    evidence=text,
                    node_type=command.node.type,
                )
            )
        return findings

    def _detect_recursive_delete(
        self, commands: list["_CommandNode"]
    ) -> list[BashAstFinding]:
        findings: list[BashAstFinding] = []
        for command in commands:
            if command.name != "rm":
                continue
            args = command.args
            recursive = any(
                arg in {"-r", "-R", "--recursive"} or "r" in arg[1:]
                for arg in args
                if arg.startswith("-")
            )
            force = any(
                arg == "-f" or "f" in arg[1:] for arg in args if arg.startswith("-")
            )
            targets = [arg for arg in args if not arg.startswith("-")]
            destructive_target = any(target in self._DELETE_PATHS for target in targets)
            severity = "destructive" if destructive_target else "dangerous"
            if recursive and force:
                findings.append(
                    BashAstFinding(
                        rule_id="bash.recursive-force-delete",
                        severity=severity,
                        message="recursive forced deletion detected",
                        evidence=self._command_text(command),
                        node_type=command.node.type,
                    )
                )
        return findings

    def _detect_weak_permissions(
        self, commands: list["_CommandNode"]
    ) -> list[BashAstFinding]:
        findings: list[BashAstFinding] = []
        for command in commands:
            if command.name != "chmod":
                continue
            if any(arg in {"777", "0777", "a+rwx", "ugo+rwx"} for arg in command.args):
                findings.append(
                    BashAstFinding(
                        rule_id="bash.weak-permissions",
                        severity="dangerous",
                        message="world-writable executable permissions detected",
                        evidence=self._command_text(command),
                        node_type=command.node.type,
                    )
                )
        return findings

    def _detect_subshells(self, root: Any, source: bytes) -> list[BashAstFinding]:
        findings: list[BashAstFinding] = []
        for node in self._walk(root):
            if node.type not in {"subshell", "compound_statement"}:
                continue
            text = self._text(node, source)
            if any(op in text for op in self._COMPOUND_RISK_TOKENS()):
                findings.append(
                    self._finding(
                        "bash.subshell-risk",
                        "dangerous",
                        "subshell or compound statement contains risky shell behavior",
                        node,
                        source,
                    )
                )
        return findings

    def _detect_heredoc_exec(self, root: Any, source: bytes) -> list[BashAstFinding]:
        findings: list[BashAstFinding] = []
        for node in self._walk(root):
            if node.type != "redirected_statement":
                continue
            command_node = next((child for child in node.children if child.type == "command"), None)
            heredoc_node = next(
                (child for child in node.children if child.type == "heredoc_redirect"),
                None,
            )
            if command_node is None or heredoc_node is None:
                continue
            command_words = self._direct_word_texts(command_node, source)
            if not command_words or command_words[0] not in self._EXEC_INTERPRETERS:
                continue
            findings.append(
                BashAstFinding(
                    rule_id="bash.heredoc-exec",
                    severity="dangerous",
                    message="interpreter is fed from a heredoc body",
                    evidence=self._text(node, source).strip(),
                    node_type=node.type,
                )
            )
        return findings

    def _detect_nested_command_substitution(
        self, root: Any, source: bytes
    ) -> list[BashAstFinding]:
        findings: list[BashAstFinding] = []
        for node in self._walk(root):
            if node.type != "command_substitution":
                continue
            nested = sum(1 for child in self._walk(node) if child.type == "command_substitution")
            if nested > 1:
                findings.append(
                    self._finding(
                        "bash.nested-command-substitution",
                        "dangerous",
                        "nested command substitution detected",
                        node,
                        source,
                    )
                )
        return findings

    def _detect_sensitive_redirects(
        self, root: Any, source: bytes
    ) -> list[BashAstFinding]:
        findings: list[BashAstFinding] = []
        for node in self._walk(root):
            if "redirect" not in node.type:
                continue
            text = self._text(node, source)
            if any(path in text for path in self._SENSITIVE_PATH_PREFIXES):
                severity = (
                    "destructive"
                    if node.type in self._OVERWRITE_REDIRECT_TYPES and any(op in text for op in (">", ">|"))
                    else "dangerous"
                )
                findings.append(
                    BashAstFinding(
                        "bash.sensitive-redirect",
                        severity,
                        "redirect targets a sensitive system path",
                        text.strip(),
                        node.type,
                    )
                )
        return findings

    @staticmethod
    def _walk(root: Any) -> Iterable[Any]:
        stack = [root]
        while stack:
            node = stack.pop()
            yield node
            stack.extend(reversed(getattr(node, "children", [])))

    @staticmethod
    def _COMPOUND_RISK_TOKENS() -> tuple[str, ...]:
        return ("$(", "`", "curl ", "wget ", "sudo ", "rm -", "chmod 777", "find ")

    def _direct_word_texts(self, node: Any, source: bytes) -> list[str]:
        words: list[str] = []
        for child in node.children:
            if child.type in {
                "command_name",
                "word",
                "string",
                "raw_string",
                "concatenation",
            }:
                text = self._clean_word(self._text(child, source))
                if text:
                    words.append(text)
        return words

    @staticmethod
    def _clean_word(text: str) -> str:
        return text.strip().strip("'\"")

    @staticmethod
    def _text(node: Any, source: bytes) -> str:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

    def _finding(
        self, rule_id: str, severity: str, message: str, node: Any, source: bytes
    ) -> BashAstFinding:
        return BashAstFinding(
            rule_id=rule_id,
            severity=severity,
            message=message,
            evidence=self._text(node, source).strip(),
            node_type=node.type,
        )

    def _command_text(self, command: "_CommandNode") -> str:
        return " ".join([command.name, *command.args]).strip()


@dataclass
class _CommandNode:
    node: Any
    name: str
    args: list[str]
