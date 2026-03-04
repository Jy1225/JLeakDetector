import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

from memory.syntactic.function import Function
from memory.syntactic.value import Value, ValueLabel
from tstool.analyzer.TS_analyzer import TSAnalyzer


class ObjState(Enum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    ESCAPED = "ESCAPED"


@dataclass(frozen=True)
class ObjID:
    context_hash: str
    file_path: str
    alloc_line: int
    alloc_seq: int

    def __str__(self) -> str:
        return f"{self.context_hash}:{self.file_path}:{self.alloc_line}:{self.alloc_seq}"


class JavaResourceOwnershipValidator:
    """
    Best-effort ownership validator to reduce Java MLK false positives.
    It tracks object instances with ObjID and propagates ownership by identifiers.
    """

    IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
    KEYWORDS = {
        "new",
        "return",
        "this",
        "super",
        "null",
        "true",
        "false",
        "if",
        "else",
        "while",
        "for",
        "switch",
        "case",
    }

    def __init__(self, ts_analyzer: TSAnalyzer) -> None:
        self.ts_analyzer = ts_analyzer

    def validate_candidate(
        self,
        src_value: Value,
        buggy_path: List[Value],
        values_to_functions: Dict[Value, Optional[Function]],
    ) -> Tuple[bool, str]:
        """
        Returns (True, reason) if candidate should be reported as leak.
        """
        points_to: Dict[str, Set[ObjID]] = {}
        obj_state: Dict[ObjID, ObjState] = {}
        alloc_counter: Dict[Tuple[str, str, int], int] = {}

        src_objids: Set[ObjID] = set()
        ordered_values = list(buggy_path)
        ordered_values.sort(key=lambda v: (v.file, v.line_number, v.index))

        for value in ordered_values:
            function = values_to_functions.get(value)
            context_hash = self._build_context_hash(function)

            if value.label == ValueLabel.SRC:
                objid = self._new_objid(value, context_hash, alloc_counter)
                obj_state[objid] = ObjState.OPEN
                src_objids.add(objid)
                for token in self._extract_identifier_tokens(value.name):
                    points_to.setdefault(token, set()).add(objid)
                continue

            self._apply_event(value, points_to, obj_state)

        if len(src_objids) == 0:
            return False, "no source object id built"

        for src_objid in src_objids:
            if src_objid not in obj_state:
                continue
            if obj_state[src_objid] == ObjState.OPEN:
                return True, "source object remains OPEN"
        return False, "source object is CLOSED or ESCAPED"

    def _new_objid(
        self,
        alloc_site: Value,
        context_hash: str,
        alloc_counter: Dict[Tuple[str, str, int], int],
    ) -> ObjID:
        counter_key = (context_hash, alloc_site.file, alloc_site.line_number)
        seq = alloc_counter.get(counter_key, 0) + 1
        alloc_counter[counter_key] = seq
        return ObjID(context_hash, alloc_site.file, alloc_site.line_number, seq)

    def _apply_event(
        self,
        value: Value,
        points_to: Dict[str, Set[ObjID]],
        obj_state: Dict[ObjID, ObjState],
    ) -> None:
        if self._is_assignment_expr(value.name):
            self._apply_assignment(value.name, points_to)

        tokens = self._extract_identifier_tokens(value.name)
        related_objids: Set[ObjID] = set()
        for token in tokens:
            related_objids.update(points_to.get(token, set()))

        if value.label == ValueLabel.SINK:
            for objid in related_objids:
                if obj_state.get(objid) == ObjState.OPEN:
                    obj_state[objid] = ObjState.CLOSED
            return

        if value.label in {ValueLabel.RET, ValueLabel.ARG, ValueLabel.PARA, ValueLabel.OUT}:
            for objid in related_objids:
                if obj_state.get(objid) == ObjState.OPEN:
                    obj_state[objid] = ObjState.ESCAPED

    def _is_assignment_expr(self, expr: str) -> bool:
        cleaned = expr.replace("==", "").replace(">=", "").replace("<=", "").replace("!=", "")
        return "=" in cleaned and "return " not in cleaned

    def _apply_assignment(self, expr: str, points_to: Dict[str, Set[ObjID]]) -> None:
        if "=" not in expr:
            return
        left, right = expr.split("=", 1)
        left_tokens = self._extract_identifier_tokens(left)
        right_tokens = self._extract_identifier_tokens(right)
        if len(left_tokens) == 0 or len(right_tokens) == 0:
            return
        right_pts: Set[ObjID] = set()
        for token in right_tokens:
            right_pts.update(points_to.get(token, set()))
        if len(right_pts) == 0:
            return
        for left_token in left_tokens:
            points_to[left_token] = set(right_pts)

    def _extract_identifier_tokens(self, expr: str) -> List[str]:
        tokens = self.IDENTIFIER_RE.findall(expr)
        return [token for token in tokens if token not in self.KEYWORDS]

    def _build_context_hash(self, function: Optional[Function]) -> str:
        if function is None:
            return "GLOBAL"
        if function.function_uid != "":
            return function.function_uid
        return f"{function.file_path}:{function.function_name}:{function.start_line_number}"
