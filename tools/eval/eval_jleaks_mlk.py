#!/usr/bin/env python3
import argparse
import csv
import json
import os
import re
from collections import defaultdict
from typing import Dict, List, Set, Tuple, cast


BUG_FILE_RE = re.compile(r"jleaks-bug-(\d+)\.java", re.IGNORECASE)


def _load_json(path: str) -> Dict:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _extract_bug_id_from_text(text: str) -> int:
    match = BUG_FILE_RE.search(text.replace("\\", "/"))
    if match is None:
        return -1
    return int(match.group(1))


def _parse_defect_method(raw: str) -> str:
    text = raw.strip()
    if ":" in text:
        return text.rsplit(":", 1)[-1].strip()
    return text


def _load_ground_truth(metadata_csv: str) -> Dict[int, Dict[str, str]]:
    gt: Dict[int, Dict[str, str]] = {}
    with open(metadata_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                bug_id = int(row["bug_id"])
            except Exception:
                continue
            gt[bug_id] = {
                "bug_file": row.get("bug_file", ""),
                "defect_method": _parse_defect_method(row.get("defect_method", "")),
            }
    return gt


def _extract_report_bug_id(report_entry: Dict) -> int:
    buggy_value = str(report_entry.get("buggy_value", ""))
    bug_id = _extract_bug_id_from_text(buggy_value)
    if bug_id > 0:
        return bug_id
    relevant = report_entry.get("relevant_functions", [])
    if isinstance(relevant, list) and len(relevant) > 0 and isinstance(relevant[0], list):
        for file_path in relevant[0]:
            bug_id = _extract_bug_id_from_text(str(file_path))
            if bug_id > 0:
                return bug_id
    return -1


def _extract_report_method_names(report_entry: Dict) -> List[str]:
    relevant = report_entry.get("relevant_functions", [])
    if not (isinstance(relevant, list) and len(relevant) >= 2 and isinstance(relevant[1], list)):
        return []
    return [str(name) for name in relevant[1]]


def _normalize_method_identity(method_uid: str, method_name: str) -> str:
    uid = method_uid.strip()
    name = method_name.strip()
    if uid != "":
        return uid
    if name != "":
        return name
    return "UNKNOWN_METHOD"


def _safe_int(value: object, default: int = -1) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _iter_payload_entries(payload: Dict) -> List[Dict]:
    if isinstance(payload, dict):
        return [item for item in payload.values() if isinstance(item, dict)]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def _summarize_duplicate_patterns(
    detect_info_payload: Dict,
    gt: Dict[int, Dict[str, str]],
) -> Dict[str, object]:
    reports_by_bug: Dict[int, List[Dict]] = defaultdict(list)
    for report_entry in _iter_payload_entries(detect_info_payload):
        bug_id = _extract_report_bug_id(report_entry)
        if bug_id <= 0:
            continue
        reports_by_bug[bug_id].append(report_entry)

    pattern_summary: Dict[str, Dict[str, int]] = {
        "A_same_source_line_repeat": {"file_count": 0, "extra_reports": 0},
        "B_multi_source_single_method": {"file_count": 0, "extra_reports": 0},
        "C_cross_method_chain_contains_gt": {"file_count": 0, "extra_reports": 0},
        "D_cross_method_gt_missing": {"file_count": 0, "extra_reports": 0},
    }

    for bug_id, report_entries in reports_by_bug.items():
        if len(report_entries) <= 1:
            continue
        extra_reports = len(report_entries) - 1
        source_lines = set()
        source_methods = set()
        for report_entry in report_entries:
            metadata = report_entry.get("metadata", {})
            if not isinstance(metadata, dict):
                metadata = {}
            source_lines.add(int(metadata.get("source_line", -1)))
            source_methods.add(str(metadata.get("source_method_name", "")))

        defect_method = gt.get(bug_id, {}).get("defect_method", "")
        if len(source_lines) < len(report_entries):
            category = "A_same_source_line_repeat"
        elif len(source_methods) == 1 and len(source_lines) > 1:
            category = "B_multi_source_single_method"
        elif len(source_methods) > 1 and defect_method in source_methods:
            category = "C_cross_method_chain_contains_gt"
        else:
            category = "D_cross_method_gt_missing"
        pattern_summary[category]["file_count"] += 1
        pattern_summary[category]["extra_reports"] += extra_reports

    total_extra = sum(item["extra_reports"] for item in pattern_summary.values())
    return {
        "by_pattern": pattern_summary,
        "total_extra_reports": total_extra,
    }


def _collect_detected_bug_ids_from_by_file(by_file_payload: Dict) -> Set[int]:
    detected: Set[int] = set()
    for file_key in by_file_payload.keys():
        bug_id = _extract_bug_id_from_text(str(file_key))
        if bug_id > 0:
            detected.add(bug_id)
    return detected


def _collect_no_source_bug_ids(source_coverage_stats: Dict) -> Set[int]:
    zero_source_files = source_coverage_stats.get("zero_source_files", [])
    result: Set[int] = set()
    if not isinstance(zero_source_files, list):
        return result
    for file_path in zero_source_files:
        bug_id = _extract_bug_id_from_text(str(file_path))
        if bug_id > 0:
            result.add(bug_id)
    return result


def _collect_soot_blocked_bug_ids(soot_events_payload: Dict) -> Set[int]:
    result: Set[int] = set()
    events = soot_events_payload.get("events", [])
    if not isinstance(events, list):
        return result
    for event in events:
        if not isinstance(event, dict):
            continue
        if not bool(event.get("blocked_by_soot", False)):
            continue
        bug_id = _extract_bug_id_from_text(str(event.get("src_file", "")))
        if bug_id > 0:
            result.add(bug_id)
    return result


def _collect_transfer_bug_ids(transfer_payload: Dict) -> Set[int]:
    result: Set[int] = set()
    for src_key, events in transfer_payload.items():
        bug_id = _extract_bug_id_from_text(str(src_key))
        if bug_id > 0:
            result.add(bug_id)
        if isinstance(events, list):
            for event in events:
                if not isinstance(event, dict):
                    continue
                event_bug_id = _extract_bug_id_from_text(
                    str(event.get("terminal_file", ""))
                )
                if event_bug_id > 0:
                    result.add(event_bug_id)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate JLeaks MLK run results.")
    parser.add_argument("--result-dir", required=True, help="Path to one run result dir")
    parser.add_argument(
        "--benchmark-dir",
        default="benchmark/Java/jleaks_mlk_198",
        help="Benchmark directory containing metadata/vulnerability_list.csv",
    )
    parser.add_argument(
        "--output-dir",
        default="",
        help="Output directory (default: result-dir)",
    )
    args = parser.parse_args()

    result_dir = args.result_dir
    output_dir = args.output_dir if args.output_dir.strip() != "" else result_dir
    os.makedirs(output_dir, exist_ok=True)

    metadata_csv = os.path.join(args.benchmark_dir, "metadata", "vulnerability_list.csv")
    gt = _load_ground_truth(metadata_csv)
    gt_bug_ids = set(gt.keys())

    detect_info = _load_json(os.path.join(result_dir, "detect_info.json"))
    detect_info_raw = _load_json(os.path.join(result_dir, "detect_info_raw.json"))
    detect_by_file = _load_json(os.path.join(result_dir, "detect_info_by_file.json"))
    source_coverage_stats = _load_json(
        os.path.join(result_dir, "source_coverage_stats.json")
    )
    soot_source_events = _load_json(
        os.path.join(result_dir, "soot_source_gate_events.json")
    )
    transfer_info = _load_json(os.path.join(result_dir, "transfer_info.json"))

    reports_by_bug: Dict[int, List[Dict]] = defaultdict(list)
    report_method_hits = 0
    detect_entries = _iter_payload_entries(detect_info)
    detect_entries_raw = _iter_payload_entries(detect_info_raw)
    total_reports = 0

    for report_entry in detect_entries:
        bug_id = _extract_report_bug_id(report_entry)
        if bug_id <= 0:
            continue
        total_reports += 1
        reports_by_bug[bug_id].append(report_entry)
        defect_method = gt.get(bug_id, {}).get("defect_method", "")
        method_names = _extract_report_method_names(report_entry)
        if defect_method != "" and defect_method in method_names:
            report_method_hits += 1

    detected_bug_ids = _collect_detected_bug_ids_from_by_file(detect_by_file)
    missing_bug_ids = sorted(gt_bug_ids - detected_bug_ids)
    detected_bug_count = len(detected_bug_ids)
    gt_count = len(gt_bug_ids)
    recall = float(detected_bug_count) / float(gt_count) if gt_count > 0 else 0.0

    report_files = set()
    by_file_entry_by_bug: Dict[int, Dict] = {}
    for file_key in detect_by_file.keys():
        bug_id = _extract_bug_id_from_text(str(file_key))
        if bug_id > 0:
            report_files.add(bug_id)
            file_entry = detect_by_file.get(file_key, {})
            if isinstance(file_entry, dict):
                by_file_entry_by_bug[bug_id] = file_entry
    precision = (
        float(len(report_files & gt_bug_ids)) / float(len(report_files))
        if len(report_files) > 0
        else 0.0
    )

    duplicate_extra_reports = 0
    duplicate_bug_count = 0
    for bug_id in detected_bug_ids:
        report_count = len(reports_by_bug.get(bug_id, []))
        if report_count > 1:
            duplicate_bug_count += 1
            duplicate_extra_reports += report_count - 1

    file_method_hits = 0
    file_method_hits_loose = 0
    for bug_id, file_entry in by_file_entry_by_bug.items():
        defect_method = gt.get(bug_id, {}).get("defect_method", "")
        leaking_methods = file_entry.get("leaking_methods", [])
        primary_method = str(file_entry.get("primary_defect_method", ""))
        reported_method_names = set()
        if isinstance(leaking_methods, list):
            for method_item in leaking_methods:
                if isinstance(method_item, dict):
                    reported_method_names.add(str(method_item.get("method_name", "")))
            if primary_method == "" and len(leaking_methods) > 0:
                first_item = leaking_methods[0]
                if isinstance(first_item, dict):
                    primary_method = str(first_item.get("method_name", ""))

        if defect_method != "" and primary_method == defect_method:
            file_method_hits += 1
        if defect_method != "" and defect_method in reported_method_names:
            file_method_hits_loose += 1

    # Method-level aggregation (new primary evaluation view)
    method_groups: Dict[Tuple[int, str, str], Dict[str, object]] = {}
    for report_entry in detect_entries:
        bug_id = _extract_report_bug_id(report_entry)
        if bug_id <= 0:
            continue
        metadata = report_entry.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
        source_file = str(metadata.get("source_file", "")).replace("\\", "/")
        source_method_uid = str(metadata.get("source_method_uid", "")).strip()
        source_method_name = str(metadata.get("source_method_name", "")).strip()
        if source_method_name == "":
            method_names = _extract_report_method_names(report_entry)
            if len(method_names) > 0:
                source_method_name = method_names[0]
        method_identity = _normalize_method_identity(
            source_method_uid, source_method_name
        )
        group_key = (
            bug_id,
            source_file.lower(),
            method_identity,
        )
        if group_key not in method_groups:
            method_groups[group_key] = {
                "bug_id": bug_id,
                "source_file": source_file,
                "method_uid": source_method_uid,
                "method_name": source_method_name if source_method_name != "" else "UNKNOWN_METHOD",
                "report_count": 0,
                "positions": set(),
                "source_symbols": set(),
                "resource_kinds": set(),
                "release_contexts": set(),
                "guarantee_levels": set(),
                "exact_instance_keys": set(),
            }
        group = method_groups[group_key]
        group["report_count"] = int(group["report_count"]) + 1
        source_line = _safe_int(metadata.get("source_line", -1), -1)
        if source_line >= 0:
            cast(Set[int], group["positions"]).add(source_line)
        issue_source_lines = metadata.get("issue_source_lines", [])
        if isinstance(issue_source_lines, list):
            for line in issue_source_lines:
                line_num = _safe_int(line, -1)
                if line_num >= 0:
                    cast(Set[int], group["positions"]).add(line_num)
        source_symbol = str(metadata.get("source_symbol", "")).strip()
        if source_symbol != "":
            cast(Set[str], group["source_symbols"]).add(source_symbol)
        resource_kind = str(metadata.get("resource_kind", "")).strip()
        if resource_kind != "":
            cast(Set[str], group["resource_kinds"]).add(resource_kind)
        release_context = str(metadata.get("release_context", "")).strip()
        if release_context != "":
            cast(Set[str], group["release_contexts"]).add(release_context)
        guarantee_level = str(metadata.get("guarantee_level", "")).strip()
        if guarantee_level != "":
            cast(Set[str], group["guarantee_levels"]).add(guarantee_level)
        exact_instance_key = (
            str(report_entry.get("buggy_value", "")).strip(),
            source_line,
            resource_kind,
            release_context,
            guarantee_level,
        )
        cast(Set[Tuple[str, int, str, str, str]], group["exact_instance_keys"]).add(
            exact_instance_key
        )

    per_method_rows: List[Dict[str, object]] = []
    method_duplicate_rows: List[Dict[str, object]] = []
    method_bug_hit_set: Set[int] = set()
    method_cluster_gt_hits = 0
    method_position_total = 0
    method_position_duplicate_extra_reports = 0
    method_exact_duplicate_extra_reports = 0

    for _, group in method_groups.items():
        bug_id = cast(int, group["bug_id"])
        defect_method = gt.get(bug_id, {}).get("defect_method", "")
        method_name = str(group.get("method_name", "UNKNOWN_METHOD"))
        report_count = int(group.get("report_count", 0))
        positions = sorted(cast(Set[int], group.get("positions", set())))
        unique_position_count = len(positions)
        method_position_total += unique_position_count
        method_position_duplicate_extra_reports += max(0, report_count - unique_position_count)
        exact_instance_count = len(cast(Set[Tuple[str, int, str, str, str]], group.get("exact_instance_keys", set())))
        method_exact_duplicate_extra_reports += max(0, report_count - exact_instance_count)

        gt_method_hit = int(defect_method != "" and defect_method == method_name)
        if gt_method_hit == 1:
            method_cluster_gt_hits += 1
            method_bug_hit_set.add(bug_id)

        file_entry = by_file_entry_by_bug.get(bug_id, {})
        primary_method = ""
        if isinstance(file_entry, dict):
            primary_method = str(file_entry.get("primary_defect_method", ""))
        is_primary_method = int(primary_method != "" and primary_method == method_name)

        per_method_rows.append(
            {
                "bug_id": bug_id,
                "source_file": str(group.get("source_file", "")),
                "defect_method": defect_method,
                "method_name": method_name,
                "method_uid": str(group.get("method_uid", "")),
                "gt_method_hit": gt_method_hit,
                "is_primary_method": is_primary_method,
                "report_count": report_count,
                "unique_position_count": unique_position_count,
                "positions": "|".join(str(v) for v in positions),
                "source_symbols": "|".join(sorted(cast(Set[str], group.get("source_symbols", set())))),
                "resource_kinds": "|".join(sorted(cast(Set[str], group.get("resource_kinds", set())))),
                "release_contexts": "|".join(sorted(cast(Set[str], group.get("release_contexts", set())))),
                "guarantee_levels": "|".join(sorted(cast(Set[str], group.get("guarantee_levels", set())))),
                "position_duplicate_extra": max(0, report_count - unique_position_count),
                "exact_duplicate_extra": max(0, report_count - exact_instance_count),
            }
        )

        if report_count > 1:
            method_duplicate_rows.append(
                {
                    "bug_id": bug_id,
                    "defect_method": defect_method,
                    "method_name": method_name,
                    "method_uid": str(group.get("method_uid", "")),
                    "report_count": report_count,
                    "unique_position_count": unique_position_count,
                    "position_duplicate_extra": max(0, report_count - unique_position_count),
                    "exact_duplicate_extra": max(0, report_count - exact_instance_count),
                    "positions": "|".join(str(v) for v in positions),
                    "gt_method_hit": gt_method_hit,
                }
            )

    per_method_rows.sort(
        key=lambda row: (
            int(row["bug_id"]),
            -int(row["gt_method_hit"]),
            -int(row["report_count"]),
            str(row["method_name"]),
        )
    )
    method_duplicate_rows.sort(
        key=lambda row: (
            -int(row["position_duplicate_extra"]),
            -int(row["report_count"]),
            int(row["bug_id"]),
            str(row["method_name"]),
        )
    )

    no_source_bug_ids = _collect_no_source_bug_ids(source_coverage_stats)
    soot_blocked_bug_ids = _collect_soot_blocked_bug_ids(soot_source_events)
    transfer_bug_ids = _collect_transfer_bug_ids(transfer_info)

    fn_no_source = sorted([bug_id for bug_id in missing_bug_ids if bug_id in no_source_bug_ids])
    fn_soot_blocked = sorted(
        [
            bug_id
            for bug_id in missing_bug_ids
            if bug_id in soot_blocked_bug_ids and bug_id not in set(fn_no_source)
        ]
    )
    fn_transfer = sorted(
        [
            bug_id
            for bug_id in missing_bug_ids
            if bug_id in transfer_bug_ids
            and bug_id not in set(fn_no_source)
            and bug_id not in set(fn_soot_blocked)
        ]
    )
    categorized = set(fn_no_source) | set(fn_soot_blocked) | set(fn_transfer)
    fn_other = sorted([bug_id for bug_id in missing_bug_ids if bug_id not in categorized])

    summary = {
        "result_dir": result_dir,
        "ground_truth_count": gt_count,
        "detected_bug_count": detected_bug_count,
        "missing_bug_count": len(missing_bug_ids),
        "file_level_recall": recall,
        "file_level_precision": precision,
        "total_reports": total_reports,
        "raw_total_reports": len(detect_entries_raw) if len(detect_entries_raw) > 0 else total_reports,
        "issue_total_reports": total_reports,
        "duplicate_bug_count": duplicate_bug_count,
        "duplicate_extra_reports": duplicate_extra_reports,
        "report_level_defect_method_hit_ratio": (
            float(report_method_hits) / float(total_reports) if total_reports > 0 else 0.0
        ),
        "file_level_primary_defect_method_hit_ratio": (
            float(file_method_hits) / float(detected_bug_count)
            if detected_bug_count > 0
            else 0.0
        ),
        "file_level_loose_defect_method_hit_ratio": (
            float(file_method_hits_loose) / float(detected_bug_count)
            if detected_bug_count > 0
            else 0.0
        ),
        "method_level_total_clusters": len(per_method_rows),
        "method_level_total_positions": method_position_total,
        "method_level_gt_cluster_hit_ratio": (
            float(method_cluster_gt_hits) / float(len(per_method_rows))
            if len(per_method_rows) > 0
            else 0.0
        ),
        "method_level_gt_bug_hit_ratio": (
            float(len(method_bug_hit_set)) / float(detected_bug_count)
            if detected_bug_count > 0
            else 0.0
        ),
        "method_level_position_duplicate_extra_reports": method_position_duplicate_extra_reports,
        "method_level_exact_duplicate_extra_reports": method_exact_duplicate_extra_reports,
        "fn_taxonomy": {
            "no_source": {"count": len(fn_no_source), "bug_ids": fn_no_source},
            "soot_source_blocked": {
                "count": len(fn_soot_blocked),
                "bug_ids": fn_soot_blocked,
            },
            "transfer_drop": {"count": len(fn_transfer), "bug_ids": fn_transfer},
            "other": {"count": len(fn_other), "bug_ids": fn_other},
        },
    }

    duplicate_pattern_summary = _summarize_duplicate_patterns(detect_info, gt)
    duplicate_pattern_summary_path = os.path.join(
        output_dir, "duplicate_pattern_summary.json"
    )
    with open(duplicate_pattern_summary_path, "w", encoding="utf-8") as f:
        json.dump(duplicate_pattern_summary, f, indent=4)

    per_bug_rows: List[Dict[str, object]] = []
    duplicate_rows: List[Dict[str, object]] = []
    for bug_id in sorted(gt_bug_ids):
        defect_method = gt[bug_id]["defect_method"]
        report_count = len(reports_by_bug.get(bug_id, []))
        detected = 1 if bug_id in detected_bug_ids else 0
        file_key = f"jleaks-bug-{bug_id}.java"
        primary_method = ""
        method_count = 0
        reported_methods: List[str] = []
        for k, file_entry in detect_by_file.items():
            if f"jleaks-bug-{bug_id}.java" in str(k):
                primary_method = str(file_entry.get("primary_defect_method", ""))
                leaking_methods = file_entry.get("leaking_methods", [])
                if isinstance(leaking_methods, list):
                    method_count = len(leaking_methods)
                    for item in leaking_methods:
                        if isinstance(item, dict):
                            reported_methods.append(str(item.get("method_name", "")))
                    if primary_method == "" and len(leaking_methods) > 0:
                        first_item = leaking_methods[0]
                        if isinstance(first_item, dict):
                            primary_method = str(first_item.get("method_name", ""))
                break
        reported_methods = sorted(set(reported_methods))
        per_bug_rows.append(
            {
                "bug_id": bug_id,
                "detected": detected,
                "report_count": report_count,
                "defect_method": defect_method,
                "primary_defect_method": primary_method,
                "primary_method_hit": int(primary_method == defect_method and defect_method != ""),
                "method_hit_loose": int(defect_method in reported_methods and defect_method != ""),
                "reported_method_count": method_count,
                "reported_methods": "|".join(reported_methods),
            }
        )
        if report_count > 1:
            duplicate_rows.append(
                {
                    "bug_id": bug_id,
                    "report_count": report_count,
                    "defect_method": defect_method,
                    "primary_defect_method": primary_method,
                    "reported_methods": "|".join(reported_methods),
                }
            )

    summary_path = os.path.join(output_dir, "eval_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=4)

    per_bug_path = os.path.join(output_dir, "eval_per_bug.csv")
    with open(per_bug_path, "w", encoding="utf-8", newline="") as f:
        if len(per_bug_rows) > 0:
            writer = csv.DictWriter(f, fieldnames=list(per_bug_rows[0].keys()))
            writer.writeheader()
            writer.writerows(per_bug_rows)
        else:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "bug_id",
                    "detected",
                    "report_count",
                    "defect_method",
                    "primary_defect_method",
                    "primary_method_hit",
                    "method_hit_loose",
                    "reported_method_count",
                    "reported_methods",
                ]
            )

    duplicate_path = os.path.join(output_dir, "duplicate_clusters.csv")
    with open(duplicate_path, "w", encoding="utf-8", newline="") as f:
        if len(duplicate_rows) > 0:
            writer = csv.DictWriter(f, fieldnames=list(duplicate_rows[0].keys()))
            writer.writeheader()
            writer.writerows(duplicate_rows)
        else:
            writer = csv.writer(f)
            writer.writerow(["bug_id", "report_count", "defect_method", "primary_defect_method", "reported_methods"])

    per_method_path = os.path.join(output_dir, "eval_per_method.csv")
    with open(per_method_path, "w", encoding="utf-8", newline="") as f:
        if len(per_method_rows) > 0:
            writer = csv.DictWriter(f, fieldnames=list(per_method_rows[0].keys()))
            writer.writeheader()
            writer.writerows(per_method_rows)
        else:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "bug_id",
                    "source_file",
                    "defect_method",
                    "method_name",
                    "method_uid",
                    "gt_method_hit",
                    "is_primary_method",
                    "report_count",
                    "unique_position_count",
                    "positions",
                    "source_symbols",
                    "resource_kinds",
                    "release_contexts",
                    "guarantee_levels",
                    "position_duplicate_extra",
                    "exact_duplicate_extra",
                ]
            )

    method_duplicate_path = os.path.join(output_dir, "duplicate_clusters_method.csv")
    with open(method_duplicate_path, "w", encoding="utf-8", newline="") as f:
        if len(method_duplicate_rows) > 0:
            writer = csv.DictWriter(f, fieldnames=list(method_duplicate_rows[0].keys()))
            writer.writeheader()
            writer.writerows(method_duplicate_rows)
        else:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "bug_id",
                    "defect_method",
                    "method_name",
                    "method_uid",
                    "report_count",
                    "unique_position_count",
                    "position_duplicate_extra",
                    "exact_duplicate_extra",
                    "positions",
                    "gt_method_hit",
                ]
            )

    by_method_payload: Dict[str, Dict[str, object]] = {}
    grouped_by_bug: Dict[int, List[Dict[str, object]]] = defaultdict(list)
    for row in per_method_rows:
        grouped_by_bug[int(row["bug_id"])].append(row)
    for bug_id, method_rows in grouped_by_bug.items():
        by_method_payload[f"jleaks-bug-{bug_id}.java"] = {
            "bug_id": bug_id,
            "defect_method": gt.get(bug_id, {}).get("defect_method", ""),
            "method_count": len(method_rows),
            "methods": method_rows,
        }
    by_method_path = os.path.join(output_dir, "detect_info_by_method.json")
    with open(by_method_path, "w", encoding="utf-8") as f:
        json.dump(by_method_payload, f, indent=4)

    print(f"[eval] summary -> {summary_path}")
    print(f"[eval] per bug -> {per_bug_path}")
    print(f"[eval] duplicates -> {duplicate_path}")
    print(f"[eval] per method -> {per_method_path}")
    print(f"[eval] method duplicates -> {method_duplicate_path}")
    print(f"[eval] by method -> {by_method_path}")
    print(f"[eval] duplicate pattern summary -> {duplicate_pattern_summary_path}")
    print(
        "[eval] recall={:.4f}, precision={:.4f}, raw_dup_extra={}, primary_method_hit={:.4f}".format(
            summary["file_level_recall"],
            summary["file_level_precision"],
            summary["duplicate_extra_reports"],
            summary["file_level_primary_defect_method_hit_ratio"],
        )
    )


if __name__ == "__main__":
    main()
