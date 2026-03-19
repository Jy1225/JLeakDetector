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

        selected: List[str] = []
        seen_method: set[str] = set()
        seen_symbol: set[str] = set()

        # Pass 1: diversify method+symbol.
        for inst in members:
            if len(selected) >= self.max_witness_per_component:
                break
            key = (inst.source_method_uid, inst.source_symbol)
            if key[0] in seen_method and key[1] in seen_symbol:
                continue
            selected.append(inst.src_key)
            seen_method.add(key[0])
            seen_symbol.add(key[1])

        # Pass 2: backfill if needed.
        if len(selected) < self.max_witness_per_component:
            for inst in members:
                if len(selected) >= self.max_witness_per_component:
                    break
                if inst.src_key in selected:
                    continue
                selected.append(inst.src_key)

        if len(selected) == 0 and len(members) > 0:
            selected = [members[0].src_key]

        return ComponentSelection(component=component, selected_source_keys=selected)

