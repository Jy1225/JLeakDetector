#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

import openpyxl


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET_XLSX = Path(__file__).resolve().parent / "juliet_dataset.xlsx"


@dataclass
class JulietCase:
    case_id: str
    file_relpath: str
    class_name: str
    defect_method: str
    start_line: int
    end_line: int
    key_variables: List[str]
    raw_bug_count_hint: int


@dataclass
class JulietBugUnit:
    bug_id: str
    case_id: str
    file_relpath: str
    class_name: str
    defect_method: str
    start_line: int
    end_line: int
    key_variable: str
    inferred_source_line: Optional[int]
    anchor_line_text: str
    anchor_tokens: Set[str]


@dataclass
class MethodRange:
    name: str
    start_line: int
    end_line: int


def _normalize_path(text: object) -> str:
    return str(text or "").replace("\\", "/").strip()


def _resolve_repo_path(raw: object) -> Path:
    text = str(raw or "").strip()
    path = Path(os.path.expandvars(os.path.expanduser(text)))
    if path.is_absolute():
        return path.resolve()
    return (REPO_ROOT / path).resolve()


def _load_json(path: Path) -> Dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _safe_int(value: object, default: int = 0) -> int:
    try:
        text = str(value or "").strip()
        if text == "":
            return default
        return int(float(text))
    except Exception:
        return default


def _extract_simple_method_name(raw: object) -> str:
    text = str(raw or "").strip()
    if text == "":
        return ""
    if ":" in text and "/" in text:
        text = text.rsplit(":", 1)[-1]
    if "(" in text:
        text = text.split("(", 1)[0]
    if "." in text:
        text = text.rsplit(".", 1)[-1]
    return text.strip()


def _extract_class_name_from_uid(raw: object) -> str:
    text = str(raw or "").strip()
    if text == "":
        return ""
    text = text.split("(", 1)[0]
    parts = text.split(".")
    if len(parts) >= 2:
        return parts[-2].strip()
    return ""


def _resolve_relpath(path_text: object) -> str:
    raw = _normalize_path(path_text)
    if raw == "":
        return ""
    repo_root = _normalize_path(REPO_ROOT)
    if raw.startswith(repo_root + "/"):
        return raw[len(repo_root) + 1 :]
    marker = "benchmark/java/toy/"
    lower = raw.lower()
    idx = lower.find(marker)
    if idx != -1:
        return raw[idx:]
    return raw


def _split_key_variables(raw: object) -> List[str]:
    text = str(raw or "").replace("_x000d_", "").strip()
    if text == "":
        return []
    result = []
    for item in text.split(","):
        cleaned = item.strip()
        if cleaned != "":
            result.append(cleaned)
    return result


def _extract_call_tokens(text: str) -> Set[str]:
    lowered = str(text or "").strip().lower()
    if lowered == "":
        return set()
    tokens: Set[str] = set()
    for match in re.finditer(r"\bnew\s+([a-z_][a-z0-9_]*)\s*\(", lowered):
        tokens.add(match.group(1))
    for match in re.finditer(r"\b([a-z_][a-z0-9_]*)\s*\(", lowered):
        token = match.group(1)
        if token in {"if", "for", "while", "switch", "catch", "return", "throw", "new", "try"}:
            continue
        tokens.add(token)
    return tokens


def _is_bad_method_name(method_name: str) -> bool:
    lowered = str(method_name or "").strip().lower()
    return lowered != "" and "bad" in lowered and "good" not in lowered


def _parse_method_ranges(source_text: str) -> List[MethodRange]:
    lines = source_text.splitlines()
    method_re = re.compile(
        r"^\s*(?:public|protected|private|static|final|native|synchronized|abstract|\s)+"
        r"[\w<>\[\].]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{)]*\)\s*(?:throws[^{]+)?\s*$"
    )
    methods: List[MethodRange] = []
    line_index = 0
    while line_index < len(lines):
        line = lines[line_index]
        line_stripped = line.rstrip()
        inline_match = re.match(
            r"^\s*(?:public|protected|private|static|final|native|synchronized|abstract|\s)+"
            r"[\w<>\[\].]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{)]*\)\s*(?:throws[^{]+)?\{",
            line_stripped,
        )
        match = inline_match if inline_match is not None else method_re.match(line_stripped)
        if match is None:
            line_index += 1
            continue
        method_name = match.group(1).strip()
        start_line = line_index + 1
        brace_depth = line.count("{") - line.count("}")
        cursor = line_index + 1
        while cursor < len(lines) and brace_depth <= 0:
            next_line = lines[cursor]
            brace_depth += next_line.count("{") - next_line.count("}")
            cursor += 1
        while cursor < len(lines) and brace_depth > 0:
            cur = lines[cursor]
            brace_depth += cur.count("{") - cur.count("}")
            cursor += 1
        methods.append(MethodRange(method_name, start_line, cursor))
        line_index = max(cursor, line_index + 1)
    return methods


def _load_detail_rows(dataset_xlsx: Path) -> List[Dict[str, object]]:
    wb = openpyxl.load_workbook(dataset_xlsx, read_only=True, data_only=True)
    ws = wb["details"]
    rows = list(ws.iter_rows(values_only=True))
    headers = [str(c).strip() if c is not None else "" for c in rows[0]]
    result = []
    for row in rows[1:]:
        item = {}
        for idx, header in enumerate(headers):
            item[header] = row[idx] if idx < len(row) else None
        if str(item.get("ID", "")).strip() == "":
            continue
        if _normalize_path(item.get("file")) == "":
            continue
        result.append(item)
    return result


def _build_cases(dataset_xlsx: Path) -> List[JulietCase]:
    rows = _load_detail_rows(dataset_xlsx)
    cases: List[JulietCase] = []
    for row in rows:
        key_variables = _split_key_variables(row.get("key variable name"))
        raw_bug_count_hint = len(key_variables) if key_variables else _safe_int(row.get("number of bugs"), 0)
        relpath = _normalize_path(row.get("file"))
        cases.append(
            JulietCase(
                case_id=str(row.get("ID")),
                file_relpath=relpath,
                class_name=Path(relpath).stem,
                defect_method=_extract_simple_method_name(row.get("defect method")),
                start_line=_safe_int(row.get("start line")),
                end_line=_safe_int(row.get("end line")),
                key_variables=key_variables,
                raw_bug_count_hint=raw_bug_count_hint,
            )
        )
    return cases


def _infer_bug_anchor(case: JulietCase, key_variable: str) -> Tuple[Optional[int], str]:
    source_path = (REPO_ROOT / case.file_relpath).resolve()
    if not source_path.exists():
        return None, ""

    file_text = source_path.read_text(encoding="utf-8", errors="ignore")
    lines = file_text.splitlines()
    key = re.escape(key_variable)
    acquisition_patterns = [
        re.compile(rf"\b{key}\b\.(?:lock|acquire|open|start)\s*\("),
        re.compile(rf"\b{key}\b\s*=\s*(?!\s*null\b).+"),
    ]

    def scan_range(begin_line: int, end_line: int) -> Tuple[Optional[int], str]:
        begin = max(begin_line - 1, 0)
        end = min(end_line, len(lines))
        for pattern in acquisition_patterns:
            for line_no in range(begin, end):
                line = lines[line_no]
                if not pattern.search(line):
                    continue
                lowered = line.lower()
                if any(
                    token in lowered
                    for token in [".close(", ".unlock(", ".delete(", ".deleteifexists(", "= null"]
                ):
                    continue
                return line_no + 1, line.strip()
        return None, ""

    methods = _parse_method_ranges(file_text)
    bad_methods = [method for method in methods if _is_bad_method_name(method.name)]

    for method in bad_methods:
        line_no, anchor = scan_range(method.start_line, method.end_line)
        if line_no is not None:
            return line_no, anchor

    return scan_range(case.start_line, case.end_line)


def _build_bug_units(cases: Sequence[JulietCase]) -> List[JulietBugUnit]:
    units: List[JulietBugUnit] = []
    for case in cases:
        for idx, key_variable in enumerate(case.key_variables, start=1):
            line_no, anchor_line = _infer_bug_anchor(case, key_variable)
            anchor_tokens = _extract_call_tokens(anchor_line)
            units.append(
                JulietBugUnit(
                    bug_id=f"{case.case_id}#{idx}",
                    case_id=case.case_id,
                    file_relpath=case.file_relpath,
                    class_name=case.class_name,
                    defect_method=case.defect_method,
                    start_line=case.start_line,
                    end_line=case.end_line,
                    key_variable=key_variable,
                    inferred_source_line=line_no,
                    anchor_line_text=anchor_line,
                    anchor_tokens=anchor_tokens,
                )
            )
    return units


def _build_report_context(entry: Dict[str, object]) -> Dict[str, object]:
    metadata = entry.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}

    source_file = _resolve_relpath(metadata.get("source_file"))
    source_line_raw = metadata.get("source_line")
    try:
        source_line = int(source_line_raw) if source_line_raw is not None else None
    except Exception:
        source_line = None

    source_method_name = _extract_simple_method_name(
        metadata.get("source_method_uid") or metadata.get("source_method_name") or ""
    )
    relevant_method_uids = metadata.get("relevant_method_uids")
    if not isinstance(relevant_method_uids, list):
        relevant_method_uids = []

    relevant_classes = {_extract_class_name_from_uid(metadata.get("source_method_uid"))}
    relevant_methods = {source_method_name}
    for uid in relevant_method_uids:
        relevant_classes.add(_extract_class_name_from_uid(uid))
        relevant_methods.add(_extract_simple_method_name(uid))

    relevant_files: Set[str] = set()
    relevant_functions = entry.get("relevant_functions")
    if (
        isinstance(relevant_functions, list)
        and len(relevant_functions) >= 2
        and isinstance(relevant_functions[0], list)
        and isinstance(relevant_functions[1], list)
    ):
        for path_item in relevant_functions[0]:
            relevant_files.add(_resolve_relpath(path_item))
        for method_item in relevant_functions[1]:
            relevant_methods.add(_extract_simple_method_name(method_item))

    report_tokens: Set[str] = set()
    report_tokens.update(_extract_call_tokens(str(entry.get("buggy_value", ""))))
    report_tokens.update(_extract_call_tokens(str(metadata.get("source_symbol", ""))))
    report_tokens.update(_extract_call_tokens(source_method_name))
    report_tokens.update(_extract_call_tokens(str(metadata.get("source_method_uid", ""))))
    report_tokens.update(_extract_call_tokens(str(metadata.get("leak_root_method_uid", ""))))
    report_tokens.update(_extract_call_tokens(str(metadata.get("obligation_key", ""))))

    return {
        "source_file": source_file,
        "source_line": source_line,
        "source_method_name": source_method_name,
        "relevant_classes": {item for item in relevant_classes if item != ""},
        "relevant_methods": {item for item in relevant_methods if item != ""},
        "relevant_files": {item for item in relevant_files if item != ""},
        "report_tokens": {item for item in report_tokens if item != ""},
        "buggy_value": str(entry.get("buggy_value", "")),
    }


def _match_report_to_bug_unit(context: Dict[str, object], bug_unit: JulietBugUnit) -> Tuple[int, List[str]]:
    score = 0
    reasons: List[str] = []

    source_file = str(context["source_file"])
    source_line = context["source_line"]
    source_method_name = str(context["source_method_name"])
    relevant_classes: Set[str] = set(context["relevant_classes"])
    relevant_methods: Set[str] = set(context["relevant_methods"])
    relevant_files: Set[str] = set(context["relevant_files"])
    report_tokens: Set[str] = set(context["report_tokens"])

    report_method_names = set(relevant_methods)
    if source_method_name != "":
        report_method_names.add(source_method_name)

    case_connected = (
        bug_unit.class_name in relevant_classes
        or bug_unit.file_relpath in relevant_files
        or source_file == bug_unit.file_relpath
    )
    bad_path_connected = any(_is_bad_method_name(name) for name in report_method_names)
    connected_to_case = case_connected and bad_path_connected

    if source_file == bug_unit.file_relpath and source_line is not None and bug_unit.inferred_source_line is not None:
        if source_line == bug_unit.inferred_source_line:
            score += 100
            reasons.append("exact_source_line_match")

    if connected_to_case and bug_unit.anchor_tokens:
        overlap = bug_unit.anchor_tokens & report_tokens
        if overlap:
            score += 60
            reasons.append(f"anchor_token_overlap={sorted(overlap)}")

    if connected_to_case and bug_unit.key_variable.lower() in str(context["buggy_value"]).lower():
        score += 40
        reasons.append("key_variable_in_buggy_value")

    if connected_to_case and source_file == bug_unit.file_relpath:
        score += 15
        reasons.append("same_benchmark_file_bad_path")

    if connected_to_case and bug_unit.defect_method in report_method_names:
        score += 15
        reasons.append("defect_method_in_bad_path")

    return score, reasons


def summarize_juliet_result(result_dir: Path, dataset_xlsx: Path) -> Dict[str, object]:
    detect_info_raw_path = result_dir / "detect_info_raw.json"
    detect_info_path = result_dir / "detect_info.json"

    if not detect_info_raw_path.exists():
        raise FileNotFoundError(f"detect_info_raw.json not found: {detect_info_raw_path}")

    detect_info_raw = _load_json(detect_info_raw_path)
    detect_info = _load_json(detect_info_path) if detect_info_path.exists() else {}

    cases = _build_cases(dataset_xlsx)
    bug_units = _build_bug_units(cases)
    bug_units_by_id = {unit.bug_id: unit for unit in bug_units}

    tp_bug_ids: Set[str] = set()
    tp_raw_report_ids: List[str] = []
    fp_raw_report_ids: List[str] = []
    raw_report_classification: Dict[str, Dict[str, object]] = {}

    for report_id, entry in detect_info_raw.items():
        report_id_text = str(report_id)
        context = _build_report_context(entry if isinstance(entry, dict) else {})

        scored_matches: List[Tuple[int, JulietBugUnit, List[str]]] = []
        for bug_unit in bug_units:
            score, reasons = _match_report_to_bug_unit(context, bug_unit)
            if score > 0:
                scored_matches.append((score, bug_unit, reasons))

        scored_matches.sort(key=lambda item: item[0], reverse=True)
        best_score = scored_matches[0][0] if scored_matches else 0
        accepted_matches = [
            {
                "bug_id": match.bug_id,
                "case_id": match.case_id,
                "file": match.file_relpath,
                "defect_method": match.defect_method,
                "key_variable": match.key_variable,
                "inferred_source_line": match.inferred_source_line,
                "score": score,
                "reasons": reasons,
            }
            for score, match, reasons in scored_matches
            if score == best_score and score >= 50
        ]

        if accepted_matches:
            tp_raw_report_ids.append(report_id_text)
            for matched in accepted_matches:
                tp_bug_ids.add(str(matched["bug_id"]))
            raw_report_classification[report_id_text] = {
                "label": "TP",
                "matched_bug_ids": [item["bug_id"] for item in accepted_matches],
                "best_score": best_score,
                "matches": accepted_matches,
                "source_file": context["source_file"],
                "source_line": context["source_line"],
                "source_method_name": context["source_method_name"],
            }
        else:
            fp_raw_report_ids.append(report_id_text)
            raw_report_classification[report_id_text] = {
                "label": "FP",
                "matched_bug_ids": [],
                "best_score": best_score,
                "source_file": context["source_file"],
                "source_line": context["source_line"],
                "source_method_name": context["source_method_name"],
                "relevant_classes": sorted(context["relevant_classes"]),
                "relevant_methods": sorted(context["relevant_methods"]),
            }

    fn_bug_ids = [bug_id for bug_id in bug_units_by_id.keys() if bug_id not in tp_bug_ids]

    bug_results: Dict[str, Dict[str, object]] = {}
    bug_to_reports: Dict[str, List[str]] = {}
    for report_id, info in raw_report_classification.items():
        if info["label"] != "TP":
            continue
        for bug_id in info["matched_bug_ids"]:
            bug_to_reports.setdefault(bug_id, []).append(report_id)

    for bug_id, bug_unit in bug_units_by_id.items():
        matched_report_ids = sorted(bug_to_reports.get(bug_id, []))
        bug_results[bug_id] = {
            "status": "TP" if bug_id in tp_bug_ids else "FN",
            "case_id": bug_unit.case_id,
            "file": bug_unit.file_relpath,
            "class_name": bug_unit.class_name,
            "defect_method": bug_unit.defect_method,
            "key_variable": bug_unit.key_variable,
            "inferred_source_line": bug_unit.inferred_source_line,
            "anchor_line_text": bug_unit.anchor_line_text,
            "matched_raw_report_ids": matched_report_ids,
        }

    merged_issue_count = len(detect_info) if isinstance(detect_info, dict) else 0

    return {
        "schema_version": "4.0",
        "dataset_xlsx": str(dataset_xlsx.resolve()),
        "result_dir": str(result_dir.resolve()),
        "detect_info_raw_json": str(detect_info_raw_path.resolve()),
        "detect_info_json": str(detect_info_path.resolve()) if detect_info_path.exists() else "",
        "benchmark_case_total": len(cases),
        "benchmark_total_bug_hint": len(bug_units),
        "tp_bug_count": len(tp_bug_ids),
        "fn_bug_count": len(fn_bug_ids),
        "tp_bug_rate": len(tp_bug_ids) / len(bug_units) if bug_units else 0.0,
        "tp_bug_ids": sorted(tp_bug_ids),
        "fn_bug_ids": fn_bug_ids,
        "tp_raw_report_count": len(tp_raw_report_ids),
        "fp_raw_report_count": len(fp_raw_report_ids),
        "raw_report_total": len(detect_info_raw),
        "merged_issue_count_hint": merged_issue_count,
        "tp_raw_report_ids": tp_raw_report_ids,
        "fp_raw_report_ids": fp_raw_report_ids,
        "bug_results": bug_results,
        "raw_report_classification": raw_report_classification,
        "notes": {
            "evaluation_unit": "Top-level bug recall is evaluated on detect_info_raw, not detect_info.",
            "benchmark_total_bug_hint_definition": "Each key variable in juliet_dataset.xlsx details sheet is treated as one real resource-leak bug unit.",
            "tp_bug_definition": "At least one raw report matches the benchmark bug unit.",
            "fp_raw_report_definition": "A raw report does not match any benchmark bug unit.",
            "merged_issue_count_hint_definition": "detect_info may merge multiple raw reports; it is retained only as a reference count.",
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Summarize Juliet TP/FP/FN metrics for one result directory.")
    parser.add_argument("--result-dir", required=True, help="RepoAudit result directory")
    parser.add_argument("--dataset-xlsx", default=str(DEFAULT_DATASET_XLSX), help="Path to juliet_dataset.xlsx")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    result_dir = Path(args.result_dir).resolve()
    dataset_xlsx = _resolve_repo_path(args.dataset_xlsx)
    payload = summarize_juliet_result(result_dir, dataset_xlsx)
    output_path = result_dir / "juliet_metrics.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    print(f"[OK] wrote Juliet metrics to: {output_path}")


if __name__ == "__main__":
    main()
