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

    def to_dict(self) -> Dict[str, int]:
        return {
            "total": self.total,
            "sat": self.sat,
            "unsat": self.unsat,
            "unknown": self.unknown,
            "disabled": self.disabled,
            "skipped_by_unsat": self.skipped_by_unsat,
        }


class JavaZ3PathPrefilter:
    """
    Deterministic pre-filter for Java MLK paths.
    It infers branch choices from path line numbers and checks their satisfiability.
    """

    CMP_RE = re.compile(
        r"^\s*([A-Za-z_]\w*|-?\d+|true|false)\s*"
        r"(==|!=|<=|>=|<|>)\s*"
        r"([A-Za-z_]\w*|-?\d+|true|false)\s*$"
    )

    def __init__(self, ts_analyzer: TSAnalyzer, config: Z3PrefilterConfig):
        self.ts_analyzer = ts_analyzer
        self.config = config

    def evaluate(
        self,
        buggy_path: List[Value],
        values_to_functions: Dict[Value, Optional[Function]],
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

        branch_constraints: Dict[
            Tuple[int, int, int], Tuple[str, bool, str]
        ] = {}

        for value in buggy_path:
            function = values_to_functions.get(value)
            if function is None:
                continue

            for (if_start, if_end), if_info in function.if_statements.items():
                (_, _, cond_str, true_scope, else_scope) = if_info

                taken: Optional[bool] = None
                if self._line_in_scope(value.line_number, true_scope):
                    taken = True
                elif self._line_in_scope(value.line_number, else_scope):
                    taken = False

                if taken is None:
                    continue

                key = (function.function_id, if_start, if_end)
                if key in branch_constraints:
                    _, existing_taken, _ = branch_constraints[key]
                    if existing_taken != taken:
                        return Z3PrefilterResult(
                            verdict=Z3PrefilterVerdict.UNSAT,
                            reason=f"direct branch conflict at if({if_start},{if_end})",
                            elapsed_ms=(time.time() - start) * 1000.0,
                        )
                else:
                    track_name = f"if_{function.function_id}_{if_start}_{if_end}"
                    branch_constraints[key] = (cond_str, taken, track_name)

                if len(branch_constraints) >= self.config.max_constraints:
                    break

        constraints = list(branch_constraints.values())
        if len(constraints) == 0:
            return Z3PrefilterResult(
                verdict=Z3PrefilterVerdict.UNKNOWN,
                reason="no usable branch constraints",
                elapsed_ms=(time.time() - start) * 1000.0,
            )

        solver = Solver()
        solver.set("timeout", self.config.timeout_ms)

        bool_vars: Dict[str, Any] = {}
        int_vars: Dict[str, Any] = {}

        parsed_constraints = 0
        for cond_str, taken_true, track_name in constraints:
            parsed = self._parse_expr(cond_str, bool_vars, int_vars)
            if parsed is None:
                continue

            parsed_constraints += 1
            solver.assert_and_track(parsed if taken_true else Not(parsed), Bool(track_name))

        if parsed_constraints == 0:
            return Z3PrefilterResult(
                verdict=Z3PrefilterVerdict.UNKNOWN,
                reason="constraints found but none parsable",
                elapsed_ms=(time.time() - start) * 1000.0,
                total_constraints=len(constraints),
                parsed_constraints=0,
            )

        check_result = solver.check()
        elapsed_ms = (time.time() - start) * 1000.0

        if check_result == unsat:
            return Z3PrefilterResult(
                verdict=Z3PrefilterVerdict.UNSAT,
                reason="unsat by z3",
                elapsed_ms=elapsed_ms,
                total_constraints=len(constraints),
                parsed_constraints=parsed_constraints,
                unsat_core=[str(item) for item in solver.unsat_core()],
            )

        if check_result == sat:
            return Z3PrefilterResult(
                verdict=Z3PrefilterVerdict.SAT,
                reason="sat by z3",
                elapsed_ms=elapsed_ms,
                total_constraints=len(constraints),
                parsed_constraints=parsed_constraints,
            )

        return Z3PrefilterResult(
            verdict=Z3PrefilterVerdict.UNKNOWN,
            reason="z3 returned unknown",
            elapsed_ms=elapsed_ms,
            total_constraints=len(constraints),
            parsed_constraints=parsed_constraints,
        )

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

    def _parse_expr(
        self,
        text: str,
        bool_vars: Dict[str, Any],
        int_vars: Dict[str, Any],
    ) -> Optional[Any]:
        normalized = self._strip_outer_parentheses(text)

        or_parts = self._split_top_level(normalized, "||")
        if len(or_parts) > 1:
            sub_exprs = [self._parse_expr(item, bool_vars, int_vars) for item in or_parts]
            if any(item is None for item in sub_exprs):
                return None
            return Or(*sub_exprs)

        and_parts = self._split_top_level(normalized, "&&")
        if len(and_parts) > 1:
            sub_exprs = [self._parse_expr(item, bool_vars, int_vars) for item in and_parts]
            if any(item is None for item in sub_exprs):
                return None
            return And(*sub_exprs)

        if normalized.startswith("!"):
            sub_expr = self._parse_expr(normalized[1:].strip(), bool_vars, int_vars)
            if sub_expr is None:
                return None
            return Not(sub_expr)

        if normalized == "true":
            return BoolVal(True)
        if normalized == "false":
            return BoolVal(False)

        cmp_match = self.CMP_RE.match(normalized)
        if cmp_match is not None:
            left_raw, op, right_raw = cmp_match.groups()
            left_term = self._parse_comparison_term(
                left_raw, right_raw, bool_vars, int_vars
            )
            right_term = self._parse_comparison_term(
                right_raw, left_raw, bool_vars, int_vars
            )
            if left_term is None or right_term is None:
                return None
            if op == "==":
                return left_term == right_term
            if op == "!=":
                return left_term != right_term
            if op == "<":
                return left_term < right_term
            if op == "<=":
                return left_term <= right_term
            if op == ">":
                return left_term > right_term
            if op == ">=":
                return left_term >= right_term
            return None

        if re.match(r"^[A-Za-z_]\w*$", normalized):
            if normalized not in bool_vars:
                bool_vars[normalized] = Bool(normalized)
            return bool_vars[normalized]

        return None

    def _parse_comparison_term(
        self,
        token: str,
        peer: str,
        bool_vars: Dict[str, Any],
        int_vars: Dict[str, Any],
    ) -> Optional[Any]:
        normalized = token.strip()
        if normalized == "true":
            return BoolVal(True)
        if normalized == "false":
            return BoolVal(False)
        if re.match(r"^-?\d+$", normalized):
            return IntVal(int(normalized))
        if re.match(r"^[A-Za-z_]\w*$", normalized):
            peer_is_bool_literal = peer in {"true", "false"}
            if peer_is_bool_literal:
                if normalized not in bool_vars:
                    bool_vars[normalized] = Bool(normalized)
                return bool_vars[normalized]
            if normalized not in int_vars:
                int_vars[normalized] = Int(normalized)
            return int_vars[normalized]
        return None
