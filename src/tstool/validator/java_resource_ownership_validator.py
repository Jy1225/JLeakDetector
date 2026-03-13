import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

from memory.syntactic.function import Function
from memory.syntactic.value import Value, ValueLabel
from tstool.analyzer.TS_analyzer import TSAnalyzer
from tstool.validator.java_resource_semantics import (
    GUARANTEE_NONE,
    decode_guarantee_level_marker,
    is_all_exit_guaranteed,
)


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
    NON_OWNERSHIP_METHODS = {
        "println",
        "print",
        "printf",
        "format",
        "size",
        "first",
        "next",
        "hasnext",
        "readline",
        "tostring",
        "hashcode",
        "equals",
        "requirenonnull",
        "debug",
        "info",
        "warn",
        "error",
        "trace",
        "submit",
        "execute",
        "schedule",
        "scheduleatfixedrate",
        "schedulewithfixeddelay",
        "invokeall",
        "invokeany",
        "awaittermination",
        "trylock",
    }
    OWNERSHIP_TRANSFER_METHODS = {
        "put",
        "add",
        "offer",
        "push",
        "enqueue",
        "register",
        "retain",
        "cache",
        "store",
        "save",
        "setresource",
        "setstream",
        "setlock",
        "setexecutor",
        "setsemaphore",
        "attach",
        "bind",
    }
    RESOURCE_LIKE_SUFFIXES = (
        "Stream",
        "Reader",
        "Writer",
        "Channel",
        "Socket",
        "Connection",
        "Statement",
        "ResultSet",
        "Scanner",
        "FileSystem",
        "Lock",
        "Semaphore",
        "Selector",
        "Executor",
        "ThreadPool",
    )

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
        candidate_guarantee_level = self._extract_guarantee_level_from_path(buggy_path)
        allow_sink_close = is_all_exit_guaranteed(candidate_guarantee_level)

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

            self._apply_event(
                value,
                function,
                points_to,
                obj_state,
                allow_sink_close=allow_sink_close,
            )

        if len(src_objids) == 0:
            return False, "no source object id built"

        for src_objid in src_objids:
            if src_objid not in obj_state:
                continue
            if obj_state[src_objid] == ObjState.OPEN:
                return True, "source object remains OPEN"
        return False, "source object is not OPEN (closed or transferred)"

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
        function: Optional[Function],
        points_to: Dict[str, Set[ObjID]],
        obj_state: Dict[ObjID, ObjState],
        allow_sink_close: bool,
    ) -> None:
        if self._is_assignment_expr(value.name):
            self._apply_assignment(value.name, points_to)

        tokens = self._extract_identifier_tokens(value.name)
        related_objids: Set[ObjID] = set()
        for token in tokens:
            related_objids.update(points_to.get(token, set()))

        if value.label == ValueLabel.SINK:
            if not allow_sink_close:
                return
            for objid in related_objids:
                if obj_state.get(objid) == ObjState.OPEN:
                    obj_state[objid] = ObjState.CLOSED
            return

        if value.label in {ValueLabel.RET, ValueLabel.PARA, ValueLabel.OUT}:
            # Do not directly mark ESCAPED here. Responsibility transfer is decided
            # by agent-level chain classification (case2/case3), not by local event.
            return

        if value.label == ValueLabel.ARG:
            # Keep OPEN in validator; whether ARG transfers ownership is handled by
            # agent-level termination classification to avoid premature false negatives.
            _ = self.is_non_ownership_argument(value, function)
            return

    def _extract_guarantee_level_from_path(self, buggy_path: List[Value]) -> str:
        fallback = GUARANTEE_NONE
        for value in buggy_path:
            if value.label != ValueLabel.LOCAL:
                continue
            decoded = decode_guarantee_level_marker(value.name)
            if decoded == "":
                continue
            if is_all_exit_guaranteed(decoded):
                return decoded
            fallback = decoded
        return fallback

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

    def is_non_ownership_argument(
        self, value: Value, function: Optional[Function]
    ) -> bool:
        """
        Best-effort classification for ARG values that do not transfer resource ownership.
        """
        if value.label != ValueLabel.ARG:
            return False
        if value.name.strip() in {"this", "super"}:
            # Receiver-style pseudo argument does not mean ownership transfer.
            return True
        if function is None:
            return False

        line_text = self.ts_analyzer.get_content_by_line_number(
            value.line_number, value.file
        )
        if self._is_non_transfer_receiver_call(value, line_text):
            return True
        if self._is_resource_wrapping_constructor_argument(value, line_text):
            return True
        method_name = self._extract_invoked_method_name(line_text)
        normalized_name = method_name.lower()

        if "System.out." in line_text or "System.err." in line_text:
            return True
        if normalized_name in self.NON_OWNERSHIP_METHODS:
            return True
        if normalized_name in self.OWNERSHIP_TRANSFER_METHODS:
            return False
        if "logger." in line_text.lower() or ".log(" in line_text.lower():
            return True
        return False

    def _is_non_transfer_receiver_call(self, value: Value, line_text: str) -> bool:
        """
        Conservative rule for receiver-style usage:
        when the tracked resource variable is the method receiver (e.g.,
        conn.prepareStatement(...)), treat it as non-ownership transfer unless the
        method name is explicitly in transfer APIs.
        """
        receiver_method_name = self._extract_receiver_method_name(value.name, line_text)
        if receiver_method_name == "":
            return False

        normalized_name = receiver_method_name.lower()
        if normalized_name in self.OWNERSHIP_TRANSFER_METHODS:
            return False
        return True

    def _extract_receiver_method_name(self, receiver_name: str, line_text: str) -> str:
        receiver_candidates = [receiver_name.strip()]
        receiver_candidates.extend(self._extract_identifier_tokens(receiver_name))

        seen = set()
        for candidate in receiver_candidates:
            if candidate == "" or candidate in seen:
                continue
            seen.add(candidate)
            matches = re.findall(
                rf"\b{re.escape(candidate)}\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(",
                line_text,
            )
            if len(matches) > 0:
                return matches[-1]
        return ""

    def _is_resource_wrapping_constructor_argument(
        self, value: Value, line_text: str
    ) -> bool:
        """
        Treat constructor wrapping calls as non-ownership transfer, e.g.:
          readerBuffered = new BufferedReader(readerInputStream);
        """
        constructor_match = re.search(
            r"new\s+([A-Za-z_][A-Za-z0-9_$.<>]*)\s*\((.*)\)",
            line_text,
        )
        if constructor_match is None:
            return False

        created_type = self._normalize_type_name(constructor_match.group(1))
        if not self._looks_resource_like_type(created_type):
            return False

        constructor_args = self._split_top_level_args(constructor_match.group(2))
        arg_expr = ""
        if 0 <= value.index < len(constructor_args):
            arg_expr = constructor_args[value.index].strip()
        elif value.name.strip() != "":
            arg_expr = value.name.strip()

        if arg_expr == "":
            return False
        if self._looks_literal_or_new_object(arg_expr):
            return False
        return True

    def _normalize_type_name(self, raw_type: str) -> str:
        normalized = raw_type.strip()
        if "<" in normalized:
            normalized = normalized.split("<", 1)[0]
        if "." in normalized:
            normalized = normalized.split(".")[-1]
        return normalized.strip()

    def _looks_resource_like_type(self, type_name: str) -> bool:
        if type_name == "":
            return False
        for suffix in self.RESOURCE_LIKE_SUFFIXES:
            if type_name.endswith(suffix):
                return True
        return False

    def _split_top_level_args(self, args_text: str) -> List[str]:
        args: List[str] = []
        depth = 0
        start = 0
        in_single_quote = False
        in_double_quote = False
        escaped = False

        for i, ch in enumerate(args_text):
            if escaped:
                escaped = False
                continue
            if ch == "\\":
                escaped = True
                continue
            if ch == "'" and not in_double_quote:
                in_single_quote = not in_single_quote
                continue
            if ch == '"' and not in_single_quote:
                in_double_quote = not in_double_quote
                continue
            if in_single_quote or in_double_quote:
                continue

            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth = max(0, depth - 1)
            elif ch == "," and depth == 0:
                args.append(args_text[start:i].strip())
                start = i + 1

        last = args_text[start:].strip()
        if last != "":
            args.append(last)
        return args

    def _looks_literal_or_new_object(self, expr: str) -> bool:
        text = expr.strip()
        if text == "":
            return True
        if text.startswith(("\"", "'")):
            return True
        if re.fullmatch(r"[0-9]+", text):
            return True
        if text in {"true", "false", "null"}:
            return True
        if text.startswith("new "):
            return True
        return False

    def _extract_invoked_method_name(self, line_text: str) -> str:
        # Prefer qualified invocations such as obj.foo(...)
        qualified = re.findall(r"\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(", line_text)
        if len(qualified) > 0:
            return qualified[-1]
        plain = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", line_text)
        if len(plain) > 0:
            return plain[-1]
        return ""

    def _build_context_hash(self, function: Optional[Function]) -> str:
        if function is None:
            return "GLOBAL"
        if function.function_uid != "":
            return function.function_uid
        return f"{function.file_path}:{function.function_name}:{function.start_line_number}"
