from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from memory.syntactic.function import Function
from memory.syntactic.value import Value
from tstool.analyzer.TS_analyzer import TSAnalyzer

try:
    from z3 import (
        And,
        Bool,
        BoolVal,
        Int,
        IntVal,
        Not,
        Or,
        Solver,
        sat,
        unsat,
    )

    Z3_AVAILABLE = True
except Exception:
    Z3_AVAILABLE = False


class Z3PrefilterVerdict(str, Enum):
    SAT = "sat"
    UNSAT = "unsat"
    UNKNOWN = "unknown"
    DISABLED = "disabled"


@dataclass
class Z3PrefilterConfig:
    enabled: bool = False
    timeout_ms: int = 200
    shadow_mode: bool = True
    max_constraints: int = 64


@dataclass
class Z3PrefilterResult:
    verdict: Z3PrefilterVerdict
    reason: str
    elapsed_ms: float = 0.0
    total_constraints: int = 0
    parsed_constraints: int = 0
    unsat_core: List[str] = field(default_factory=list)

    @property
    def should_skip_llm(self) -> bool:
        return self.verdict == Z3PrefilterVerdict.UNSAT


@dataclass
class Z3PrefilterStats:
    total: int = 0
    sat: int = 0
    unsat: int = 0
    unknown: int = 0
    disabled: int = 0
    skipped_by_unsat: int = 0

    # Unknown sub-categories for observability.
    no_constraint: int = 0
    parse_fail: int = 0
    timeout: int = 0
    unsupported_expr: int = 0
    has_if_but_unmapped: int = 0

    def update(self, result: Z3PrefilterResult, shadow_mode: bool) -> None:
        self.total += 1
        if result.verdict == Z3PrefilterVerdict.SAT:
            self.sat += 1
        elif result.verdict == Z3PrefilterVerdict.UNSAT:
            self.unsat += 1
            if not shadow_mode:
                self.skipped_by_unsat += 1
        elif result.verdict == Z3PrefilterVerdict.UNKNOWN:
            self.unknown += 1
        else:
            self.disabled += 1

        if result.reason == "no_constraint":
            self.no_constraint += 1
        elif result.reason == "parse_fail":
            self.parse_fail += 1
        elif result.reason == "timeout":
            self.timeout += 1
        elif result.reason == "unsupported_expr":
            self.unsupported_expr += 1
        elif result.reason == "has_if_but_unmapped":
            self.has_if_but_unmapped += 1

    def to_dict(self) -> Dict[str, int]:
        return {
            "total": self.total,
            "sat": self.sat,
            "unsat": self.unsat,
            "unknown": self.unknown,
            "disabled": self.disabled,
            "skipped_by_unsat": self.skipped_by_unsat,
            "no_constraint": self.no_constraint,
            "parse_fail": self.parse_fail,
            "timeout": self.timeout,
            "unsupported_expr": self.unsupported_expr,
            "has_if_but_unmapped": self.has_if_but_unmapped,
        }


class JavaZ3PathPrefilter:
    """
    Deterministic pre-filter for Java MLK paths.
    It uses path line hints to infer branch choices and checks satisfiability.
    """

    IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.$\[\]]*$")

    def __init__(self, ts_analyzer: TSAnalyzer, config: Z3PrefilterConfig):
        self.ts_analyzer = ts_analyzer
        self.config = config

    def evaluate(
        self,
        buggy_path: List[Value],
        values_to_functions: Dict[Value, Optional[Function]],
        line_numbers_by_function: Optional[Dict[int, List[int]]] = None,
    ) -> Z3PrefilterResult:
        start = time.time()

        if not self.config.enabled:
            return Z3PrefilterResult(
                Z3PrefilterVerdict.DISABLED, "z3 prefilter disabled"
            )
        if not Z3_AVAILABLE:
            return Z3PrefilterResult(
                Z3PrefilterVerdict.DISABLED, "z3-solver is not available"
            )

        inferred_lines = self._build_line_hints_from_values(
            buggy_path, values_to_functions
        )
        if line_numbers_by_function is not None:
            for function_id, line_numbers in line_numbers_by_function.items():
                if function_id not in inferred_lines:
                    inferred_lines[function_id] = []
                inferred_lines[function_id].extend(line_numbers)
        for function_id in inferred_lines:
            inferred_lines[function_id] = sorted(
                set(ln for ln in inferred_lines[function_id] if ln > 0)
            )

        branch_constraints: Dict[Tuple[int, int, int], Tuple[str, bool, str]] = {}
        has_if_but_unmapped = 0

        functions = {
            function.function_id: function
            for function in values_to_functions.values()
            if function is not None
        }

        for function_id, function in functions.items():
            if len(function.if_statements) == 0:
                continue

            candidate_lines = inferred_lines.get(function_id, [])
            if len(candidate_lines) == 0:
                has_if_but_unmapped += 1
                continue

            mapped_for_function = False
            for (if_start, if_end), if_info in function.if_statements.items():
                (_, _, condition_str, true_scope, else_scope) = if_info

                hit_true = any(
                    self._line_in_scope(line_number, true_scope)
                    for line_number in candidate_lines
                )
                hit_false = any(
                    self._line_in_scope(line_number, else_scope)
                    for line_number in candidate_lines
                )

                # Ambiguous branch evidence is skipped conservatively.
                if hit_true and hit_false:
                    continue
                if not hit_true and not hit_false:
                    continue

                mapped_for_function = True
                taken = hit_true and not hit_false
                key = (function_id, if_start, if_end)
                if key in branch_constraints:
                    _, existing_taken, _ = branch_constraints[key]
                    if existing_taken != taken:
                        return Z3PrefilterResult(
                            verdict=Z3PrefilterVerdict.UNSAT,
                            reason="unsat",
                            elapsed_ms=(time.time() - start) * 1000.0,
                        )
                else:
                    track_name = f"if_{function_id}_{if_start}_{if_end}"
                    branch_constraints[key] = (condition_str, taken, track_name)

                if len(branch_constraints) >= self.config.max_constraints:
                    break

            if not mapped_for_function:
                has_if_but_unmapped += 1

        constraints = list(branch_constraints.values())
        if len(constraints) == 0:
            reason = "has_if_but_unmapped" if has_if_but_unmapped > 0 else "no_constraint"
            return Z3PrefilterResult(
                verdict=Z3PrefilterVerdict.UNKNOWN,
                reason=reason,
                elapsed_ms=(time.time() - start) * 1000.0,
            )

        solver = Solver()
        solver.set("timeout", self.config.timeout_ms)

        bool_vars: Dict[str, Any] = {}
        int_vars: Dict[str, Any] = {}
        parsed_constraints = 0
        parse_fail_count = 0
        unsupported_only_count = 0

        for condition_str, taken_true, track_name in constraints:
            parsed_expr, parse_reason = self._parse_expr(
                condition_str, bool_vars, int_vars
            )
            if parsed_expr is None:
                if parse_reason == "unsupported_expr":
                    unsupported_only_count += 1
                else:
                    parse_fail_count += 1
                continue

            parsed_constraints += 1
            solver.assert_and_track(
                parsed_expr if taken_true else Not(parsed_expr), Bool(track_name)
            )

        if parsed_constraints == 0:
            reason = "unsupported_expr" if unsupported_only_count > 0 else "parse_fail"
            return Z3PrefilterResult(
                verdict=Z3PrefilterVerdict.UNKNOWN,
                reason=reason,
                elapsed_ms=(time.time() - start) * 1000.0,
                total_constraints=len(constraints),
                parsed_constraints=0,
            )

        check_result = solver.check()
        elapsed_ms = (time.time() - start) * 1000.0

        if check_result == unsat:
            return Z3PrefilterResult(
                verdict=Z3PrefilterVerdict.UNSAT,
                reason="unsat",
                elapsed_ms=elapsed_ms,
                total_constraints=len(constraints),
                parsed_constraints=parsed_constraints,
                unsat_core=[str(item) for item in solver.unsat_core()],
            )

        if check_result == sat:
            return Z3PrefilterResult(
                verdict=Z3PrefilterVerdict.SAT,
                reason="sat",
                elapsed_ms=elapsed_ms,
                total_constraints=len(constraints),
                parsed_constraints=parsed_constraints,
            )

        reason_unknown = solver.reason_unknown().lower()
        reason = "timeout" if "timeout" in reason_unknown else "unknown"
        return Z3PrefilterResult(
            verdict=Z3PrefilterVerdict.UNKNOWN,
            reason=reason,
            elapsed_ms=elapsed_ms,
            total_constraints=len(constraints),
            parsed_constraints=parsed_constraints,
        )

    def _build_line_hints_from_values(
        self,
        buggy_path: List[Value],
        values_to_functions: Dict[Value, Optional[Function]],
    ) -> Dict[int, List[int]]:
        hints: Dict[int, List[int]] = {}
        for value in buggy_path:
            function = values_to_functions.get(value)
            if function is None:
                continue
            relative_line = function.file_line2function_line(value.line_number)
            if relative_line <= 0:
                continue
            hints.setdefault(function.function_id, []).append(relative_line)
        return hints

    def _line_in_scope(self, line_number: int, scope: Tuple[int, int]) -> bool:
        if len(scope) != 2:
            return False
        lower, upper = scope
        if lower <= 0 or upper <= 0:
            return False
        return lower <= line_number <= upper

    def _strip_outer_parentheses(self, text: str) -> str:
        normalized = text.strip()
        while normalized.startswith("(") and normalized.endswith(")"):
            depth = 0
            wrapped = True
            for i, ch in enumerate(normalized):
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0 and i != len(normalized) - 1:
                        wrapped = False
                        break
            if not wrapped:
                break
            normalized = normalized[1:-1].strip()
        return normalized

    def _split_top_level(self, text: str, op: str) -> List[str]:
        parts: List[str] = []
        depth = 0
        start = 0
        i = 0
        while i < len(text):
            ch = text[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif depth == 0 and text[i : i + len(op)] == op:
                parts.append(text[start:i].strip())
                start = i + len(op)
                i += len(op)
                continue
            i += 1
        parts.append(text[start:].strip())
        return [item for item in parts if item]

    def _find_comparison_op(self, text: str) -> Optional[Tuple[str, str, str]]:
        operators = ["==", "!=", "<=", ">=", "<", ">"]
        depth = 0
        i = 0
        while i < len(text):
            ch = text[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif depth == 0:
                for op in operators:
                    if text[i : i + len(op)] == op:
                        left = text[:i].strip()
                        right = text[i + len(op) :].strip()
                        if left == "" or right == "":
                            return None
                        return left, op, right
            i += 1
        return None

    def _parse_expr(
        self,
        text: str,
        bool_vars: Dict[str, Any],
        int_vars: Dict[str, Any],
    ) -> Tuple[Optional[Any], str]:
        normalized = self._strip_outer_parentheses(text)

        or_parts = self._split_top_level(normalized, "||")
        if len(or_parts) > 1:
            sub_exprs: List[Any] = []
            reason = "parse_fail"
            for item in or_parts:
                parsed, sub_reason = self._parse_expr(item, bool_vars, int_vars)
                if parsed is None:
                    if sub_reason == "unsupported_expr":
                        reason = "unsupported_expr"
                    return None, reason
                if sub_reason == "unsupported_expr":
                    reason = "unsupported_expr"
                sub_exprs.append(parsed)
            return Or(*sub_exprs), reason

        and_parts = self._split_top_level(normalized, "&&")
        if len(and_parts) > 1:
            sub_exprs = []
            reason = "parse_fail"
            for item in and_parts:
                parsed, sub_reason = self._parse_expr(item, bool_vars, int_vars)
                if parsed is None:
                    if sub_reason == "unsupported_expr":
                        reason = "unsupported_expr"
                    return None, reason
                if sub_reason == "unsupported_expr":
                    reason = "unsupported_expr"
                sub_exprs.append(parsed)
            return And(*sub_exprs), reason

        if normalized.startswith("!"):
            sub_expr, sub_reason = self._parse_expr(
                normalized[1:].strip(), bool_vars, int_vars
            )
            if sub_expr is None:
                return None, sub_reason
            return Not(sub_expr), sub_reason

        if normalized == "true":
            return BoolVal(True), "parse_fail"
        if normalized == "false":
            return BoolVal(False), "parse_fail"

        cmp_info = self._find_comparison_op(normalized)
        if cmp_info is not None:
            left_raw, op, right_raw = cmp_info
            left_term, left_sort, left_reason = self._parse_comparison_term(
                left_raw, right_raw, bool_vars, int_vars
            )
            right_term, right_sort, right_reason = self._parse_comparison_term(
                right_raw, left_raw, bool_vars, int_vars
            )
            if left_term is None or right_term is None:
                if "unsupported_expr" in {left_reason, right_reason}:
                    return None, "unsupported_expr"
                return None, "parse_fail"

            if op in {"<", "<=", ">", ">="}:
                if left_sort != "int" or right_sort != "int":
                    return None, "parse_fail"
            elif left_sort != right_sort:
                return None, "parse_fail"

            reason = (
                "unsupported_expr"
                if "unsupported_expr" in {left_reason, right_reason}
                else "parse_fail"
            )
            if op == "==":
                return left_term == right_term, reason
            if op == "!=":
                return left_term != right_term, reason
            if op == "<":
                return left_term < right_term, reason
            if op == "<=":
                return left_term <= right_term, reason
            if op == ">":
                return left_term > right_term, reason
            if op == ">=":
                return left_term >= right_term, reason
            return None, "parse_fail"

        if self.IDENT_RE.match(normalized):
            key = self._symbol_key(normalized, "b")
            if key not in bool_vars:
                bool_vars[key] = Bool(key)
            return bool_vars[key], "parse_fail"

        if "(" in normalized and ")" in normalized:
            key = self._symbol_key(normalized, "ub")
            if key not in bool_vars:
                bool_vars[key] = Bool(key)
            return bool_vars[key], "unsupported_expr"

        return None, "parse_fail"

    def _parse_comparison_term(
        self,
        token: str,
        peer: str,
        bool_vars: Dict[str, Any],
        int_vars: Dict[str, Any],
    ) -> Tuple[Optional[Any], str, str]:
        normalized = self._strip_outer_parentheses(token)
        peer_normalized = self._strip_outer_parentheses(peer)

        if normalized == "true":
            return BoolVal(True), "bool", "parse_fail"
        if normalized == "false":
            return BoolVal(False), "bool", "parse_fail"
        if normalized == "null":
            return IntVal(0), "int", "parse_fail"
        if re.match(r"^-?\d+$", normalized):
            return IntVal(int(normalized)), "int", "parse_fail"

        hint_is_bool = peer_normalized in {"true", "false"}
        hint_is_int = peer_normalized == "null" or bool(
            re.match(r"^-?\d+$", peer_normalized)
        )

        if self.IDENT_RE.match(normalized):
            if hint_is_bool:
                key = self._symbol_key(normalized, "b")
                if key not in bool_vars:
                    bool_vars[key] = Bool(key)
                return bool_vars[key], "bool", "parse_fail"
            key = self._symbol_key(normalized, "i")
            if key not in int_vars:
                int_vars[key] = Int(key)
            return int_vars[key], "int", "parse_fail"

        if "(" in normalized and ")" in normalized:
            if hint_is_bool:
                key = self._symbol_key(normalized, "ub")
                if key not in bool_vars:
                    bool_vars[key] = Bool(key)
                return bool_vars[key], "bool", "unsupported_expr"
            if hint_is_int or not hint_is_bool:
                key = self._symbol_key(normalized, "ui")
                if key not in int_vars:
                    int_vars[key] = Int(key)
                return int_vars[key], "int", "unsupported_expr"

        return None, "unknown", "parse_fail"

    def _symbol_key(self, token: str, prefix: str) -> str:
        normalized = re.sub(r"[^A-Za-z0-9_]", "_", token)
        if normalized == "":
            normalized = "expr"
        if len(normalized) > 40:
            normalized = normalized[:40]
        return f"{prefix}_{normalized}_{abs(hash(token)) % 100000}"
