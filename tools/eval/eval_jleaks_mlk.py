#!/usr/bin/env python3
import argparse
import csv
import json
import os
import re
from collections import defaultdict
from typing import Dict, List, Set, Tuple


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
    detect_by_file = _load_json(os.path.join(result_dir, "detect_info_by_file.json"))
    detect_canonical = _load_json(os.path.join(result_dir, "detect_info_canonical.json"))
    source_coverage_stats = _load_json(
        os.path.join(result_dir, "source_coverage_stats.json")
    )
    soot_source_events = _load_json(
        os.path.join(result_dir, "soot_source_gate_events.json")
    )
    transfer_info = _load_json(os.path.join(result_dir, "transfer_info.json"))

    reports_by_bug: Dict[int, List[Dict]] = defaultdict(list)
    report_method_hits = 0
    total_reports = 0

    for _, report_entry in detect_info.items():
        if not isinstance(report_entry, dict):
            continue
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
    for file_key in detect_by_file.keys():
        bug_id = _extract_bug_id_from_text(str(file_key))
        if bug_id > 0:
            report_files.add(bug_id)
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

    canonical_reports_by_bug: Dict[int, List[Dict]] = defaultdict(list)
    canonical_total_reports = 0
    canonical_entries = _iter_payload_entries(detect_canonical)
    if len(canonical_entries) == 0:
        canonical_entries = _iter_payload_entries(detect_info)
    for entry in canonical_entries:
        bug_id = _extract_report_bug_id(entry)
        if bug_id <= 0:
            continue
        canonical_total_reports += 1
        canonical_reports_by_bug[bug_id].append(entry)
    canonical_detected_bug_ids = set(canonical_reports_by_bug.keys())
    canonical_recall = (
        float(len(canonical_detected_bug_ids)) / float(gt_count) if gt_count > 0 else 0.0
    )
    canonical_duplicate_bug_count = 0
    canonical_duplicate_extra_reports = 0
    for bug_id in canonical_detected_bug_ids:
        canonical_count = len(canonical_reports_by_bug.get(bug_id, []))
        if canonical_count > 1:
            canonical_duplicate_bug_count += 1
            canonical_duplicate_extra_reports += canonical_count - 1

    file_method_hits = 0
    file_method_hits_loose = 0
    for file_key, file_entry in detect_by_file.items():
        if not isinstance(file_entry, dict):
            continue
        bug_id = _extract_bug_id_from_text(str(file_key))
        if bug_id <= 0:
            continue
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
        "duplicate_bug_count": duplicate_bug_count,
        "duplicate_extra_reports": duplicate_extra_reports,
        "canonical_total_reports": canonical_total_reports,
        "canonical_detected_bug_count": len(canonical_detected_bug_ids),
        "canonical_file_level_recall": canonical_recall,
        "canonical_duplicate_bug_count": canonical_duplicate_bug_count,
        "canonical_duplicate_extra_reports": canonical_duplicate_extra_reports,
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

    print(f"[eval] summary -> {summary_path}")
    print(f"[eval] per bug -> {per_bug_path}")
    print(f"[eval] duplicates -> {duplicate_path}")
    print(f"[eval] duplicate pattern summary -> {duplicate_pattern_summary_path}")
    print(
        "[eval] recall={:.4f}, precision={:.4f}, raw_dup_extra={}, canonical_dup_extra={}, primary_method_hit={:.4f}".format(
            summary["file_level_recall"],
            summary["file_level_precision"],
            summary["duplicate_extra_reports"],
            summary["canonical_duplicate_extra_reports"],
            summary["file_level_primary_defect_method_hit_ratio"],
        )
    )


if __name__ == "__main__":
    main()
