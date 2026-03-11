from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from memory.syntactic.function import Function
from memory.syntactic.value import Value, ValueLabel
from tstool.analyzer.TS_analyzer import TSAnalyzer


class SootPrefilterVerdict(str, Enum):
    PASS = "pass"
    BLOCK = "block"
    UNKNOWN = "unknown"
    DISABLED = "disabled"


@dataclass
class SootPrefilterConfig:
    enabled: bool = False
    shadow_mode: bool = True
    facts_path: str = ""
    timeout_ms: int = 200


@dataclass
class SootPrefilterResult:
    verdict: SootPrefilterVerdict
    reason: str
    elapsed_ms: float = 0.0
    matched_methods: int = 0
    evidence: List[str] = field(default_factory=list)

    @property
    def should_skip_llm(self) -> bool:
        return self.verdict == SootPrefilterVerdict.BLOCK


@dataclass
class SootPrefilterStats:
    total: int = 0
    passed: int = 0
    blocked: int = 0
    unknown: int = 0
    disabled: int = 0
    skipped_by_soot: int = 0

    # Detailed reasons for observability.
    unreachable: int = 0
    safe_must_close: int = 0
    safe_method_all_sources_hard: int = 0
    facts_unavailable: int = 0
    method_unmapped: int = 0
    no_candidate_line: int = 0
    malformed_facts: int = 0

    def update(self, result: SootPrefilterResult, shadow_mode: bool) -> None:
        self.total += 1
        if result.verdict == SootPrefilterVerdict.PASS:
            self.passed += 1
        elif result.verdict == SootPrefilterVerdict.BLOCK:
            self.blocked += 1
            if not shadow_mode:
                self.skipped_by_soot += 1
        elif result.verdict == SootPrefilterVerdict.UNKNOWN:
            self.unknown += 1
        else:
            self.disabled += 1

        if result.reason == "unreachable":
            self.unreachable += 1
        elif result.reason == "safe_must_close":
            self.safe_must_close += 1
        elif result.reason == "safe_method_all_sources_hard":
            self.safe_method_all_sources_hard += 1
        elif result.reason == "facts_unavailable":
            self.facts_unavailable += 1
        elif result.reason == "method_unmapped":
            self.method_unmapped += 1
        elif result.reason == "no_candidate_line":
            self.no_candidate_line += 1
        elif result.reason == "malformed_facts":
            self.malformed_facts += 1

    def to_dict(self) -> Dict[str, int]:
        return {
            "total": self.total,
            "passed": self.passed,
            "blocked": self.blocked,
            "unknown": self.unknown,
            "disabled": self.disabled,
            "skipped_by_soot": self.skipped_by_soot,
            "unreachable": self.unreachable,
            "safe_must_close": self.safe_must_close,
            "safe_method_all_sources_hard": self.safe_method_all_sources_hard,
            "facts_unavailable": self.facts_unavailable,
            "method_unmapped": self.method_unmapped,
            "no_candidate_line": self.no_candidate_line,
            "malformed_facts": self.malformed_facts,
        }


class JavaSootPrefilter:
    """
    Deterministic Java MLK prefilter backed by Soot facts.
    The prefilter is intentionally conservative: if facts are missing or ambiguous,
    it returns UNKNOWN and lets downstream validators decide.
    """

    def __init__(self, ts_analyzer: TSAnalyzer, config: SootPrefilterConfig):
        self.ts_analyzer = ts_analyzer
        self.config = config
        self._facts_by_uid: Dict[str, Dict[str, Any]] = {}
        self._facts_by_file_and_name: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._facts_load_error: str = ""

        if self.config.enabled:
            self._load_facts()

    def evaluate(
        self,
        buggy_path: List[Value],
        values_to_functions: Dict[Value, Optional[Function]],
    ) -> SootPrefilterResult:
        start = time.time()

        if not self.config.enabled:
            return SootPrefilterResult(
                verdict=SootPrefilterVerdict.DISABLED,
                reason="soot prefilter disabled",
            )

        if self._facts_load_error != "":
            return SootPrefilterResult(
                verdict=SootPrefilterVerdict.UNKNOWN,
                reason="facts_unavailable",
                elapsed_ms=(time.time() - start) * 1000.0,
                evidence=[self._facts_load_error],
            )

        method_lines, source_lines, method_map = self._collect_candidate_lines(
            buggy_path, values_to_functions
        )
        if len(method_lines) == 0:
            return SootPrefilterResult(
                verdict=SootPrefilterVerdict.UNKNOWN,
                reason="no_candidate_line",
                elapsed_ms=(time.time() - start) * 1000.0,
            )

        matched_methods = 0
        method_unmapped = 0
        fallback_evidence: List[str] = []

        for function_id, candidate_lines in method_lines.items():
            function = method_map.get(function_id)
            if function is None:
                continue
            method_facts = self._resolve_method_facts(function)
            if method_facts is None:
                method_unmapped += 1
                continue
            matched_methods += 1

            unreachable_evidence = self._check_unreachable_branch(
                candidate_lines, method_facts
            )
            if unreachable_evidence is not None:
                return SootPrefilterResult(
                    verdict=SootPrefilterVerdict.BLOCK,
                    reason="unreachable",
                    elapsed_ms=(time.time() - start) * 1000.0,
                    matched_methods=matched_methods,
                    evidence=[unreachable_evidence],
                )

            must_close_evidence = self._check_must_close_source(
                source_lines.get(function_id, set()), method_facts
            )
            if must_close_evidence is not None:
                return SootPrefilterResult(
                    verdict=SootPrefilterVerdict.BLOCK,
                    reason="safe_must_close",
                    elapsed_ms=(time.time() - start) * 1000.0,
                    matched_methods=matched_methods,
                    evidence=[must_close_evidence],
                )

            method_hard_safe_evidence = self._check_method_all_sources_hard(method_facts)
            if method_hard_safe_evidence is not None:
                return SootPrefilterResult(
                    verdict=SootPrefilterVerdict.BLOCK,
                    reason="safe_method_all_sources_hard",
                    elapsed_ms=(time.time() - start) * 1000.0,
                    matched_methods=matched_methods,
                    evidence=[method_hard_safe_evidence],
                )

            fallback_evidence.append(
                f"{function.function_uid or function.function_name}: no blocking evidence"
            )

        elapsed_ms = (time.time() - start) * 1000.0
        if matched_methods == 0:
            reason = "method_unmapped" if method_unmapped > 0 else "no_candidate_line"
            return SootPrefilterResult(
                verdict=SootPrefilterVerdict.UNKNOWN,
                reason=reason,
                elapsed_ms=elapsed_ms,
                matched_methods=0,
            )

        return SootPrefilterResult(
            verdict=SootPrefilterVerdict.PASS,
            reason="no_blocking_evidence",
            elapsed_ms=elapsed_ms,
            matched_methods=matched_methods,
            evidence=fallback_evidence[:1],
        )

    def evaluate_source_hard_safety(
        self, src_value: Value, src_function: Function
    ) -> Tuple[bool, str]:
        if not self.config.enabled:
            return False, "soot_prefilter_disabled"
        if self._facts_load_error != "":
            return False, "facts_unavailable"

        method_facts = self._resolve_method_facts(src_function)
        if method_facts is None:
            return False, "method_unmapped"

        if self._safe_bool(method_facts.get("all_sources_hard_closed")):
            proof_kind = str(method_facts.get("method_proof_kind", "")).strip().lower()
            if proof_kind in {"", "hard"}:
                return True, "method_all_sources_hard_closed"
            return False, "method_proof_not_hard"

        source_line_candidates: Set[int] = {src_value.line_number}
        relative_line = src_function.file_line2function_line(src_value.line_number)
        if relative_line > 0:
            source_line_candidates.add(relative_line)

        source_guarantee_obj = method_facts.get("source_close_guarantee", {})
        reason_obj = method_facts.get("must_close_reason", {})
        proof_obj = method_facts.get("source_proof_kind", {})
        if not isinstance(source_guarantee_obj, dict):
            return False, "source_close_guarantee_missing"

        for src_line in source_line_candidates:
            guaranteed = self._safe_bool(
                source_guarantee_obj.get(str(src_line), source_guarantee_obj.get(src_line))
            )
            if not guaranteed:
                continue
            line_reason = ""
            if isinstance(reason_obj, dict):
                line_reason = str(
                    reason_obj.get(str(src_line), reason_obj.get(src_line, ""))
                ).strip()
            line_proof = ""
            if isinstance(proof_obj, dict):
                line_proof = str(
                    proof_obj.get(str(src_line), proof_obj.get(src_line, ""))
                ).strip()
            is_hard = line_proof.lower() == "hard" and line_reason == "all_exit_paths_closed_for_alias"
            if is_hard:
                return True, f"line_{src_line}_all_exit_paths_closed_for_alias"
            return False, f"line_{src_line}_not_strict_hard"

        return False, "source_line_not_hard_safe"

    def _load_facts(self) -> None:
        facts_path = self.config.facts_path.strip()
        if facts_path == "":
            self._facts_load_error = "soot facts path is empty"
            return
        if not os.path.exists(facts_path):
            self._facts_load_error = f"soot facts file does not exist: {facts_path}"
            return

        try:
            with open(facts_path, "r", encoding="utf-8") as facts_file:
                payload = json.load(facts_file)
        except Exception as err:
            self._facts_load_error = f"failed to load soot facts: {err}"
            return

        methods_obj = payload.get("methods")
        if methods_obj is None:
            self._facts_load_error = "soot facts missing 'methods'"
            return

        method_items: List[Tuple[str, Dict[str, Any]]] = []
        if isinstance(methods_obj, dict):
            for key, method_payload in methods_obj.items():
                if isinstance(method_payload, dict):
                    method_items.append((str(key), method_payload))
        elif isinstance(methods_obj, list):
            for method_payload in methods_obj:
                if not isinstance(method_payload, dict):
                    continue
                key = str(method_payload.get("function_uid", ""))
                method_items.append((key, method_payload))
        else:
            self._facts_load_error = "soot facts 'methods' must be dict or list"
            return

        if len(method_items) == 0:
            self._facts_load_error = "soot facts contain no method entries"
            return

        for key, method_payload in method_items:
            function_uid = str(method_payload.get("function_uid", key)).strip()
            if function_uid != "":
                self._facts_by_uid[function_uid] = method_payload

            file_path = str(method_payload.get("file", "")).strip()
            method_name = str(
                method_payload.get(
                    "method_name", method_payload.get("function_name", "")
                )
            ).strip()
            if file_path != "" and method_name != "":
                lookup_key = (self._normalize_path(file_path), method_name)
                self._facts_by_file_and_name[lookup_key] = method_payload

    def _collect_candidate_lines(
        self,
        buggy_path: List[Value],
        values_to_functions: Dict[Value, Optional[Function]],
    ) -> Tuple[Dict[int, Set[int]], Dict[int, Set[int]], Dict[int, Function]]:
        method_lines: Dict[int, Set[int]] = {}
        source_lines: Dict[int, Set[int]] = {}
        method_map: Dict[int, Function] = {}

        for value in buggy_path:
            function = values_to_functions.get(value)
            if function is None:
                continue
            relative_line = function.file_line2function_line(value.line_number)
            if relative_line <= 0:
                continue
            method_map[function.function_id] = function
            method_lines.setdefault(function.function_id, set()).add(relative_line)
            # Keep absolute line as extra hint so soot_facts can use either mode.
            method_lines[function.function_id].add(value.line_number)
            if value.label == ValueLabel.SRC:
                source_lines.setdefault(function.function_id, set()).add(relative_line)
                source_lines[function.function_id].add(value.line_number)
        return method_lines, source_lines, method_map

    def _resolve_method_facts(self, function: Function) -> Optional[Dict[str, Any]]:
        if function.function_uid != "" and function.function_uid in self._facts_by_uid:
            return self._facts_by_uid[function.function_uid]

        fallback_key = (
            self._normalize_path(function.file_path),
            function.function_name,
        )
        return self._facts_by_file_and_name.get(fallback_key)

    def _check_unreachable_branch(
        self, candidate_lines: Set[int], method_facts: Dict[str, Any]
    ) -> Optional[str]:
        if_nodes = method_facts.get("if_nodes", [])
        if not isinstance(if_nodes, list):
            return None

        for if_node in if_nodes:
            if not isinstance(if_node, dict):
                continue

            hit_true = self._branch_hit(candidate_lines, if_node, True)
            hit_false = self._branch_hit(candidate_lines, if_node, False)
            if hit_true and hit_false:
                continue
            if not hit_true and not hit_false:
                continue

            if hit_true and self._branch_unreachable(if_node, True):
                if_line = self._safe_int(if_node.get("line"), -1)
                reason = str(
                    if_node.get(
                        "true_unreachable_reason",
                        if_node.get("unreachable_reason", ""),
                    )
                ).strip()
                proof_kind = str(if_node.get("proof_kind", "")).strip()
                reason_suffix = ""
                if reason != "":
                    reason_suffix += f"; reason={reason}"
                if proof_kind != "":
                    reason_suffix += f"; proof_kind={proof_kind}"
                return (
                    f"true branch is unreachable by Soot facts at if line {if_line}{reason_suffix}"
                )

            if hit_false and self._branch_unreachable(if_node, False):
                if_line = self._safe_int(if_node.get("line"), -1)
                reason = str(
                    if_node.get(
                        "false_unreachable_reason",
                        if_node.get("unreachable_reason", ""),
                    )
                ).strip()
                proof_kind = str(if_node.get("proof_kind", "")).strip()
                reason_suffix = ""
                if reason != "":
                    reason_suffix += f"; reason={reason}"
                if proof_kind != "":
                    reason_suffix += f"; proof_kind={proof_kind}"
                return (
                    f"false branch is unreachable by Soot facts at if line {if_line}{reason_suffix}"
                )

        return None

    def _check_must_close_source(
        self, source_lines: Set[int], method_facts: Dict[str, Any]
    ) -> Optional[str]:
        if len(source_lines) == 0:
            return None

        if bool(method_facts.get("must_close_all_sources", False)):
            return "all source allocations are guaranteed to close by Soot facts"

        guaranteed_lines: Set[int] = set()
        reason_by_line: Dict[int, str] = {}
        proof_by_line: Dict[int, str] = {}
        for key in [
            "must_close_sources",
            "must_close_source_lines",
            "guaranteed_close_sources",
        ]:
            guaranteed_lines.update(self._to_int_set(method_facts.get(key)))

        raw_reason_map = method_facts.get("must_close_reason", {})
        if isinstance(raw_reason_map, dict):
            for line_key, reason in raw_reason_map.items():
                line_no = self._safe_int(line_key, -1)
                if line_no > 0:
                    reason_by_line[line_no] = str(reason).strip()

        raw_proof_map = method_facts.get("source_proof_kind", {})
        if isinstance(raw_proof_map, dict):
            for line_key, proof_kind in raw_proof_map.items():
                line_no = self._safe_int(line_key, -1)
                if line_no > 0:
                    proof_by_line[line_no] = str(proof_kind).strip()

        line_guarantee_obj = method_facts.get("source_close_guarantee", {})
        if isinstance(line_guarantee_obj, dict):
            for line_key, guaranteed in line_guarantee_obj.items():
                if bool(guaranteed):
                    guaranteed_lines.add(self._safe_int(line_key, -1))

        guaranteed_lines = set(line for line in guaranteed_lines if line > 0)
        for src_line in source_lines:
            if src_line in guaranteed_lines:
                line_reason = reason_by_line.get(src_line, "")
                line_proof = proof_by_line.get(src_line, "")
                is_hard = (
                    line_proof.lower() == "hard"
                    and line_reason == "all_exit_paths_closed_for_alias"
                )
                if not is_hard:
                    continue
                details = []
                if line_reason != "":
                    details.append(f"reason={line_reason}")
                if line_proof != "":
                    details.append(f"proof_kind={line_proof}")
                suffix = ""
                if len(details) > 0:
                    suffix = "; " + ", ".join(details)
                return (
                    f"source line {src_line} is guaranteed to close by Soot facts{suffix}"
                )
        return None

    def _check_method_all_sources_hard(
        self, method_facts: Dict[str, Any]
    ) -> Optional[str]:
        if self._safe_bool(method_facts.get("all_sources_hard_closed")):
            method_proof_kind = str(method_facts.get("method_proof_kind", "")).strip().lower()
            if method_proof_kind in {"", "hard"}:
                return (
                    "all sources in this method are hard-guaranteed to close by Soot facts"
                )
            return None

        source_lines = self._to_int_set(method_facts.get("source_lines"))
        source_lines = set(line for line in source_lines if line > 0)
        if len(source_lines) == 0:
            return None

        raw_guarantee = method_facts.get("source_close_guarantee", {})
        raw_proof = method_facts.get("source_proof_kind", {})
        if not isinstance(raw_guarantee, dict) or not isinstance(raw_proof, dict):
            return None

        for src_line in source_lines:
            guaranteed = self._safe_bool(
                raw_guarantee.get(str(src_line), raw_guarantee.get(src_line))
            )
            proof_kind = str(
                raw_proof.get(str(src_line), raw_proof.get(src_line, ""))
            ).strip()
            if not guaranteed:
                return None
            if proof_kind.lower() != "hard":
                return None

        return "method-level hard guarantee: all source allocations are closed on all paths"

    def _branch_hit(
        self, candidate_lines: Set[int], if_node: Dict[str, Any], is_true_branch: bool
    ) -> bool:
        line_list_keys = (
            ["true_lines", "then_lines", "true_branch_lines"]
            if is_true_branch
            else ["false_lines", "else_lines", "false_branch_lines"]
        )
        range_keys = (
            ["true_scope", "true_range", "then_scope"]
            if is_true_branch
            else ["false_scope", "false_range", "else_scope"]
        )

        line_pool: Set[int] = set()
        for key in line_list_keys:
            line_pool.update(self._to_int_set(if_node.get(key)))
        if any(line in line_pool for line in candidate_lines):
            return True

        for key in range_keys:
            if self._line_hit_range(candidate_lines, if_node.get(key)):
                return True
        return False

    def _branch_unreachable(self, if_node: Dict[str, Any], is_true_branch: bool) -> bool:
        direct_key = "true_unreachable" if is_true_branch else "false_unreachable"
        if bool(if_node.get(direct_key, False)):
            return True

        tags = if_node.get("unreachable_branches", [])
        if isinstance(tags, list):
            target = "true" if is_true_branch else "false"
            return target in [str(tag).strip().lower() for tag in tags]
        return False

    def _line_hit_range(self, lines: Set[int], raw_scope: Any) -> bool:
        if isinstance(raw_scope, list) and len(raw_scope) == 2:
            lower = self._safe_int(raw_scope[0], -1)
            upper = self._safe_int(raw_scope[1], -1)
            if lower > 0 and upper > 0:
                return any(lower <= line <= upper for line in lines)
        if isinstance(raw_scope, dict):
            lower = self._safe_int(raw_scope.get("start"), -1)
            upper = self._safe_int(raw_scope.get("end"), -1)
            if lower > 0 and upper > 0:
                return any(lower <= line <= upper for line in lines)
        return False

    def _to_int_set(self, value: Any) -> Set[int]:
        if value is None:
            return set()
        if isinstance(value, list):
            return set(self._safe_int(item, -1) for item in value)
        return {self._safe_int(value, -1)}

    def _safe_int(self, value: Any, default: int) -> int:
        try:
            return int(value)
        except Exception:
            return default

    def _safe_bool(self, value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            return normalized in {"1", "true", "yes"}
        if isinstance(value, int):
            return value != 0
        return bool(value)

    def _normalize_path(self, file_path: str) -> str:
        return file_path.replace("\\", "/").strip().lower()
