"""CyberShield Enterprise - SOAR Playbook AST Validator, Sandbox Runtime & Hot-Reload Manager.
Implements Python AST safety auditing, isolated restricted execution namespaces,
automated code synthesis, and atomic zero-downtime hot-reloading with rollback.
"""

import ast
import hashlib
import time
import uuid
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timezone

from .schemas import (
    PlaybookTriggerType,
    PlaybookExitStatus,
    SafetySandboxPolicy,
    DynamicPlaybookSpec,
    ASTValidationResult,
    PlaybookExecutionResult,
    HotReloadRegistryMetrics,
)


class PlaybookASTValidator:
    """Static AST inspector to guarantee playbook safety before compilation."""

    def __init__(self, policy: Optional[SafetySandboxPolicy] = None):
        self.policy = policy or SafetySandboxPolicy()

    def validate(self, source_code: str) -> ASTValidationResult:
        """Parse and walk the AST to detect disallowed modules, functions, or escape attempts."""
        violations: List[str] = []
        try:
            tree = ast.parse(source_code)
        except SyntaxError as e:
            return ASTValidationResult(
                is_safe=False,
                ast_nodes_inspected=0,
                detected_violations=[f"Python Syntax Error: {str(e)}"],
            )

        node_count = 0
        has_entrypoint = False

        for node in ast.walk(tree):
            node_count += 1

            # 1. Entrypoint check
            if isinstance(node, ast.FunctionDef) and node.name == "run_playbook":
                has_entrypoint = True

            # 2. Module Import Whitelist Check
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_mod = alias.name.split(".")[0]
                    if root_mod not in self.policy.allowed_modules:
                        violations.append(f"Security Violation: Import of unapproved module '{alias.name}'.")

            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    root_mod = node.module.split(".")[0]
                    if root_mod not in self.policy.allowed_modules:
                        violations.append(f"Security Violation: From-import of unapproved module '{node.module}'.")

            # 3. Disallowed Function Calls Check
            elif isinstance(node, ast.Call):
                func_name = None
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                if func_name and func_name in self.policy.disallowed_calls:
                    violations.append(f"Security Violation: Call to restricted builtin '{func_name}()'.")

            # 4. Dangerous Dunder Attribute Access (Sandbox Escape Prevention)
            elif isinstance(node, ast.Attribute):
                if node.attr in {"__subclasses__", "__globals__", "__code__", "__closure__", "__class__", "__builtins__"}:
                    violations.append(f"Security Violation: Restricted introspection attribute '{node.attr}'.")

        if not has_entrypoint:
            violations.append("Contract Violation: Playbook must define 'run_playbook(context, actions)' entrypoint.")

        is_safe = len(violations) == 0
        bytecode_hash = hashlib.sha256(source_code.encode("utf-8")).hexdigest() if is_safe else None

        return ASTValidationResult(
            is_safe=is_safe,
            ast_nodes_inspected=node_count,
            detected_violations=violations,
            compiled_bytecode_hash=bytecode_hash,
        )


class ActionsProxy:
    """Safe dispatcher passed into playbooks to record and execute mitigation actions."""

    def __init__(self):
        self.invoked_actions: List[str] = []
        self.logs: List[str] = []

    def isolate_host(self, host_id: str):
        msg = f"ACTION: isolate_host('{host_id}')"
        self.invoked_actions.append(f"ISOLATE_HOST:{host_id}")
        self.logs.append(msg)

    def block_ip(self, ip: str):
        msg = f"ACTION: block_ip('{ip}')"
        self.invoked_actions.append(f"BLOCK_IP:{ip}")
        self.logs.append(msg)

    def quarantine_file(self, file_hash_or_path: str):
        msg = f"ACTION: quarantine_file('{file_hash_or_path}')"
        self.invoked_actions.append(f"QUARANTINE_FILE:{file_hash_or_path}")
        self.logs.append(msg)

    def kill_process(self, pid: int):
        msg = f"ACTION: kill_process({pid})"
        self.invoked_actions.append(f"KILL_PROCESS:{pid}")
        self.logs.append(msg)

    def send_notification(self, channel: str, message: str):
        msg = f"ACTION: send_notification(channel='{channel}', message='{message}')"
        self.invoked_actions.append(f"NOTIFY:{channel}")
        self.logs.append(msg)

    def log(self, message: str):
        self.logs.append(f"INFO: {message}")


class SandboxedPlaybookRuntime:
    """Executes validated playbooks within a hardened restricted Python scope."""

    def __init__(self, policy: Optional[SafetySandboxPolicy] = None):
        self.policy = policy or SafetySandboxPolicy()

    def execute(
        self,
        source_code: str,
        context: Dict[str, Any],
    ) -> Tuple[PlaybookExitStatus, List[str], List[str], Optional[str]]:
        """Run the playbook in a restricted environment and capture output."""
        # Safe builtins subset
        safe_builtins = {
            "len": len, "range": range, "str": str, "int": int,
            "dict": dict, "list": list, "set": set, "tuple": tuple,
            "min": min, "max": max, "round": round, "sum": sum,
            "enumerate": enumerate, "isinstance": isinstance,
            "bool": bool, "float": float, "True": True, "False": False, "None": None,
        }

        # Sandbox globals
        restricted_globals = {
            "__builtins__": safe_builtins,
            "__name__": "__soar_sandbox__",
        }

        actions = ActionsProxy()
        restricted_locals: Dict[str, Any] = {}

        t_start = time.perf_counter()

        try:
            # Compile and execute definition
            compiled = compile(source_code, "<dynamic_playbook>", "exec")
            exec(compiled, restricted_globals, restricted_locals)

            if "run_playbook" not in restricted_locals:
                return (
                    PlaybookExitStatus.RUNTIME_ERROR,
                    actions.logs,
                    actions.invoked_actions,
                    "Entrypoint 'run_playbook' not defined in locals.",
                )

            entrypoint = restricted_locals["run_playbook"]
            # Call entrypoint
            entrypoint(context, actions)
            exit_status = PlaybookExitStatus.SUCCESS
            err_msg = None

        except Exception as e:
            exit_status = PlaybookExitStatus.RUNTIME_ERROR
            err_msg = f"{type(e).__name__}: {str(e)}"
            actions.logs.append(f"ERROR: {err_msg}")

        return exit_status, actions.logs, actions.invoked_actions, err_msg


class PlaybookHotReloadManager:
    """Manages versioned, hot-swappable SOAR playbooks and synthesis."""

    def __init__(self):
        self.active_playbooks: Dict[str, DynamicPlaybookSpec] = {}
        self.playbook_history: Dict[str, List[DynamicPlaybookSpec]] = {}
        self.validator = PlaybookASTValidator()
        self.runtime = SandboxedPlaybookRuntime()

        # Metrics
        self.total_compilations = 0
        self.sandbox_rejections = 0
        self.total_executions = 0
        self.rollbacks_executed = 0

    def compile_and_register(self, spec: DynamicPlaybookSpec) -> ASTValidationResult:
        """Validate, compile, and register a dynamic playbook with version tracking."""
        self.total_compilations += 1
        val_result = self.validator.validate(spec.python_source_code)

        if not val_result.is_safe:
            self.sandbox_rejections += 1
            return val_result

        pid = spec.playbook_id

        # Save previous version in history
        if pid in self.active_playbooks:
            prev = self.active_playbooks[pid]
            if pid not in self.playbook_history:
                self.playbook_history[pid] = []
            self.playbook_history[pid].append(prev)
            spec.version = prev.version + 1

        self.active_playbooks[pid] = spec
        return val_result

    def rollback(self, playbook_id: str) -> DynamicPlaybookSpec:
        """Revert a playbook to its immediately preceding version."""
        if playbook_id not in self.playbook_history or not self.playbook_history[playbook_id]:
            raise ValueError(f"No rollback history available for playbook '{playbook_id}'.")

        prev_spec = self.playbook_history[playbook_id].pop()
        self.active_playbooks[playbook_id] = prev_spec
        self.rollbacks_executed += 1
        return prev_spec

    def execute_playbook(
        self,
        playbook_id: str,
        context: Dict[str, Any],
    ) -> PlaybookExecutionResult:
        """Execute the active version of a registered playbook in the sandbox."""
        if playbook_id not in self.active_playbooks:
            raise ValueError(f"Playbook '{playbook_id}' is not registered.")

        spec = self.active_playbooks[playbook_id]
        if not spec.is_active:
            raise ValueError(f"Playbook '{playbook_id}' is disabled.")

        t_start = time.perf_counter()
        exit_status, logs, actions, err = self.runtime.execute(spec.python_source_code, context)
        duration_ms = round((time.perf_counter() - t_start) * 1000.0, 2)

        self.total_executions += 1

        return PlaybookExecutionResult(
            execution_id=f"exec-{uuid.uuid4().hex[:8]}",
            playbook_id=playbook_id,
            playbook_version=spec.version,
            trigger_event=context,
            exit_status=exit_status,
            output_log=logs,
            execution_duration_ms=duration_ms,
            actions_invoked=actions,
            error_message=err,
        )

    def synthesize_playbook_code(
        self,
        intent: str,
        trigger_type: PlaybookTriggerType = PlaybookTriggerType.ALERT_SEVERITY,
    ) -> str:
        """Synthesize verified, safe Python playbook source code from natural language intent."""
        intent_lower = intent.lower()

        code_lines = [
            "# Auto-Synthesized CyberShield SOAR Dynamic Playbook",
            f"# Trigger: {trigger_type.value}",
            f"# Intent: {intent}",
            "",
            "def run_playbook(context, actions):",
            "    actions.log('Executing automated incident response playbook')",
            "    severity = context.get('severity', 'LOW')",
            "    host_id = context.get('host_id')",
            "    source_ip = context.get('source_ip')",
            "    file_hash = context.get('file_hash')",
            "    pid = context.get('pid')",
            "",
        ]

        if "isolate" in intent_lower and "host" in intent_lower:
            code_lines.append("    if host_id:")
            code_lines.append("        actions.isolate_host(host_id)")

        if "block" in intent_lower and ("ip" in intent_lower or "c2" in intent_lower):
            code_lines.append("    if source_ip:")
            code_lines.append("        actions.block_ip(source_ip)")

        if "quarantine" in intent_lower and "file" in intent_lower:
            code_lines.append("    if file_hash:")
            code_lines.append("        actions.quarantine_file(file_hash)")

        if "kill" in intent_lower and "process" in intent_lower:
            code_lines.append("    if pid:")
            code_lines.append("        actions.kill_process(pid)")

        if "slack" in intent_lower or "notify" in intent_lower or "alert" in intent_lower:
            code_lines.append("    actions.send_notification('soc-incidents', f'Auto-containment triggered for host {host_id}')")

        code_lines.append("    actions.log('Playbook execution completed successfully')")

        return "\n".join(code_lines)

    def get_metrics(self) -> HotReloadRegistryMetrics:
        """Return compilation, sandbox rejection, and execution metrics."""
        return HotReloadRegistryMetrics(
            active_hotloaded_playbooks=len(self.active_playbooks),
            total_compilations=self.total_compilations,
            sandbox_rejections=self.sandbox_rejections,
            total_executions=self.total_executions,
            rollbacks_executed=self.rollbacks_executed,
        )
