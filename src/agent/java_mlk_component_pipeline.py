from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from agent.java_mlk_issue_graph import IssueComponent, SourceInstance


@dataclass
class ComponentSelection:
    component: IssueComponent
    selected_source_keys: List[str]


class ComponentWitnessSelector:
    """
    Select pre-LLM source witnesses per issue component.
    """

    def __init__(
        self,
        source_by_key: Dict[str, SourceInstance],
        max_witness_per_component: int = 2,
    ) -> None:
        self.source_by_key = source_by_key
        self.max_witness_per_component = max(1, max_witness_per_component)

    def _target_witness_count(self, members: List[SourceInstance]) -> int:
        """
        Tiered witness budget:
        - small component: 2
        - medium component: 2~3 (prefer covering >=2 methods)
        - large component: up to 5 (prefer method coverage first)
        The final value is still capped by max_witness_per_component.
        """
        member_count = len(members)
        method_count = len(
            {
                inst.source_method_uid
                for inst in members
                if inst.source_method_uid.strip() != ""
            }
        )
        if member_count <= 3:
            target = 2
        elif member_count <= 12:
            target = 3 if method_count >= 3 else 2
        else:
            target = min(5, max(3, method_count))
        target = min(target, self.max_witness_per_component)
        return max(1, target)

    def select(self, component: IssueComponent) -> ComponentSelection:
        members = [
            self.source_by_key[key]
            for key in component.member_source_keys
            if key in self.source_by_key
        ]
        # Stable ranking: high information density first.
        members.sort(
            key=lambda inst: (
                inst.source_line,
                inst.source_symbol,
                inst.source_method_uid,
                inst.src_key,
            )
        )
        target_witness_count = self._target_witness_count(members)

        selected: List[str] = []
        seen_method: set[str] = set()
        seen_symbol: set[str] = set()

        # Pass 1: prioritize method coverage (avoid same-method over-selection).
        for inst in members:
            if len(selected) >= target_witness_count:
                break
            method_uid = inst.source_method_uid.strip()
            if method_uid != "" and method_uid in seen_method:
                continue
            selected.append(inst.src_key)
            if method_uid != "":
                seen_method.add(method_uid)
            seen_symbol.add(inst.source_symbol)

        # Pass 2: diversify symbols while allowing repeated methods.
        if len(selected) < target_witness_count:
            for inst in members:
                if len(selected) >= target_witness_count:
                    break
                if inst.src_key in selected:
                    continue
                if inst.source_symbol in seen_symbol and inst.source_symbol != "":
                    continue
                selected.append(inst.src_key)
                seen_symbol.add(inst.source_symbol)

        # Pass 2: backfill if needed.
        if len(selected) < target_witness_count:
            for inst in members:
                if len(selected) >= target_witness_count:
                    break
                if inst.src_key in selected:
                    continue
                selected.append(inst.src_key)

        if len(selected) == 0 and len(members) > 0:
            selected = [members[0].src_key]

        return ComponentSelection(component=component, selected_source_keys=selected)
