from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

from memory.syntactic.value import Value


@dataclass(frozen=True)
class SourceInstance:
    src_key: str
    src_value: Value
    source_file: str
    source_method_uid: str
    obligation_component_key: str
    resource_kind: str
    guarantee_class: str
    source_symbol: str
    source_line: int


@dataclass(frozen=True)
class TransferEdge:
    src_key_a: str
    src_key_b: str
    edge_type: str
    confidence: str


@dataclass
class IssueComponent:
    component_id: int
    signature: Tuple[str, str, str, str]
    member_source_keys: List[str] = field(default_factory=list)
    edge_count: int = 0


class IssueGraphBuilder:
    """
    Lightweight issue-first pre-LLM graph for Java MLK.
    Nodes are source instances and edges connect likely same-leak obligations.
    """

    def __init__(
        self,
        source_instances: List[SourceInstance],
        method_id_by_uid: Dict[str, int] | None = None,
        call_out: Dict[int, Set[int]] | None = None,
        call_in: Dict[int, Set[int]] | None = None,
        max_method_hops: int = 2,
    ) -> None:
        self.source_instances = source_instances
        self.method_id_by_uid = method_id_by_uid if method_id_by_uid is not None else {}
        self.call_out = call_out if call_out is not None else {}
        self.call_in = call_in if call_in is not None else {}
        self.max_method_hops = max(1, max_method_hops)
        self._source_by_key: Dict[str, SourceInstance] = {
            inst.src_key: inst for inst in source_instances
        }
        self._method_hop_cache: Dict[Tuple[str, str], bool] = {}

    @staticmethod
    def _family_anchor(component_key: str) -> str:
        text = component_key.strip().lower()
        if ":component:" in text:
            text = text.split(":component:", 1)[1]
        elif ":family:" in text:
            text = text.split(":family:", 1)[1]
        parts = [p for p in text.split(":") if p != ""]
        if len(parts) >= 2:
            return f"{parts[0]}:{parts[1]}"
        if len(parts) == 1:
            return parts[0]
        return text

    @staticmethod
    def _line_close(a: int, b: int, threshold: int) -> bool:
        if a < 0 or b < 0:
            return False
        return abs(a - b) <= threshold

    def _method_related(self, uid_a: str, uid_b: str) -> bool:
        if uid_a == "" or uid_b == "":
            return False
        if uid_a == uid_b:
            return True
        pair = (uid_a, uid_b) if uid_a <= uid_b else (uid_b, uid_a)
        if pair in self._method_hop_cache:
            return self._method_hop_cache[pair]
        fid_a = self.method_id_by_uid.get(uid_a)
        fid_b = self.method_id_by_uid.get(uid_b)
        if fid_a is None or fid_b is None:
            self._method_hop_cache[pair] = False
            return False
        if fid_a == fid_b:
            self._method_hop_cache[pair] = True
            return True
        frontier: List[Tuple[int, int]] = [(fid_a, 0)]
        visited: Set[int] = {fid_a}
        related = False
        while len(frontier) > 0:
            current, hops = frontier.pop(0)
            if hops >= self.max_method_hops:
                continue
            neighbors = set(self.call_out.get(current, set()))
            neighbors.update(self.call_in.get(current, set()))
            for nxt in neighbors:
                if nxt == fid_b:
                    related = True
                    frontier = []
                    break
                if nxt in visited:
                    continue
                visited.add(nxt)
                frontier.append((nxt, hops + 1))
        self._method_hop_cache[pair] = related
        return related

    def build_edges(self) -> List[TransferEdge]:
        bucket: Dict[Tuple[str, str, str], List[SourceInstance]] = {}
        for inst in self.source_instances:
            key = (
                inst.source_file,
                inst.resource_kind,
                inst.guarantee_class,
            )
            bucket.setdefault(key, []).append(inst)

        edges: List[TransferEdge] = []
        for instances in bucket.values():
            if len(instances) <= 1:
                continue
            for i in range(len(instances)):
                for j in range(i + 1, len(instances)):
                    a = instances[i]
                    b = instances[j]
                    if a.src_key == b.src_key:
                        continue
                    same_component = (
                        a.obligation_component_key == b.obligation_component_key
                    )
                    same_method_symbol = (
                        a.source_method_uid != ""
                        and a.source_method_uid == b.source_method_uid
                        and a.source_symbol == b.source_symbol
                    )
                    anchor_a = self._family_anchor(a.obligation_component_key)
                    anchor_b = self._family_anchor(b.obligation_component_key)
                    same_anchor = anchor_a != "" and anchor_a == anchor_b
                    same_symbol = (
                        a.source_symbol != ""
                        and b.source_symbol != ""
                        and a.source_symbol == b.source_symbol
                    )
                    method_related = self._method_related(
                        a.source_method_uid, b.source_method_uid
                    )
                    line_close_small = self._line_close(a.source_line, b.source_line, 6)
                    line_close_tight = self._line_close(a.source_line, b.source_line, 3)

                    edge_type = ""
                    confidence = "low"
                    if same_component:
                        edge_type = "same_component_key"
                        confidence = "high"
                    elif same_method_symbol:
                        edge_type = "same_method_symbol"
                        confidence = "high"
                    elif same_anchor and same_symbol and method_related:
                        edge_type = "same_family_anchor_related_method"
                        confidence = "medium"
                    elif same_symbol and method_related and line_close_small:
                        edge_type = "related_method_line_close"
                        confidence = "medium"
                    elif same_anchor and line_close_tight:
                        edge_type = "same_anchor_line_close"
                        confidence = "medium"

                    if edge_type == "":
                        continue
                    edges.append(
                        TransferEdge(
                            src_key_a=a.src_key,
                            src_key_b=b.src_key,
                            edge_type=edge_type,
                            confidence=confidence,
                        )
                    )
        return edges

    def connected_components(self) -> List[IssueComponent]:
        instances = self.source_instances
        if len(instances) == 0:
            return []

        parent: Dict[str, str] = {inst.src_key: inst.src_key for inst in instances}

        def _find_root(key: str) -> str:
            current = key
            while parent[current] != current:
                parent[current] = parent[parent[current]]
                current = parent[current]
            return current

        def _union(a: str, b: str) -> None:
            ra = _find_root(a)
            rb = _find_root(b)
            if ra == rb:
                return
            if ra <= rb:
                parent[rb] = ra
            else:
                parent[ra] = rb

        edges = self.build_edges()
        for edge in edges:
            _union(edge.src_key_a, edge.src_key_b)

        members_by_root: Dict[str, List[str]] = {}
        for inst in instances:
            root = _find_root(inst.src_key)
            members_by_root.setdefault(root, []).append(inst.src_key)

        components: List[IssueComponent] = []
        for idx, root in enumerate(sorted(members_by_root.keys())):
            member_keys = sorted(set(members_by_root[root]))
            sample = self._source_by_key[member_keys[0]]
            signature = (
                sample.source_file,
                sample.obligation_component_key,
                sample.resource_kind,
                sample.guarantee_class,
            )
            edge_count = 0
            member_set = set(member_keys)
            for edge in edges:
                if edge.src_key_a in member_set and edge.src_key_b in member_set:
                    edge_count += 1
            components.append(
                IssueComponent(
                    component_id=idx,
                    signature=signature,
                    member_source_keys=member_keys,
                    edge_count=edge_count,
                )
            )
        return components
