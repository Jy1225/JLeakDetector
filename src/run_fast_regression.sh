#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

# Fast regression entry for Java MLK.
# Goal: avoid running jleaks_mlk_198 on every code tweak.
#
# Default flow:
#   1) build and run a C/D duplicate stress subset from latest jleaks_mlk_198 result
#   2) (optional) run jleaks_mlk_20
#   3) (optional) run full jleaks_mlk_198
#
# Env knobs:
#   MODEL=deepseek-chat
#   FAST_RUN_QUICK=false
#   FAST_RUN_CD_SUBSET=true
#   FAST_RUN_FULL=false
#   FAST_CD_TOP_N=40
#   FAST_FULL_BENCH=jleaks_mlk_198
#   FAST_QUICK_BENCH=jleaks_mlk_20
#   FAST_SUBSET_DIR=../tmp/jleaks_mlk_cd_top_${FAST_CD_TOP_N}

MODEL="${MODEL:-deepseek-chat}"
FAST_RUN_QUICK="${FAST_RUN_QUICK:-false}"
FAST_RUN_CD_SUBSET="${FAST_RUN_CD_SUBSET:-true}"
FAST_RUN_FULL="${FAST_RUN_FULL:-false}"
FAST_CD_TOP_N="${FAST_CD_TOP_N:-40}"
FAST_FULL_BENCH="${FAST_FULL_BENCH:-jleaks_mlk_198}"
FAST_QUICK_BENCH="${FAST_QUICK_BENCH:-jleaks_mlk_20}"
FAST_SUBSET_DIR="${FAST_SUBSET_DIR:-../tmp/jleaks_mlk_cd_top_${FAST_CD_TOP_N}}"

RESULT_BASE="../result/dfbscan/${MODEL}/MLK/Java"
FULL_BENCH_DIR="../benchmark/Java/${FAST_FULL_BENCH}"
QUICK_BENCH_DIR="../benchmark/Java/${FAST_QUICK_BENCH}"
SUMMARY_FILE="../tmp/fast_regression_summary_${MODEL}_$(date +%Y-%m-%d-%H-%M-%S).txt"

mkdir -p "../tmp"

latest_run_dir() {
  local bench_name="$1"
  local root="${RESULT_BASE}/${bench_name}"
  if [[ ! -d "${root}" ]]; then
    return 1
  fi
  ls -1dt "${root}"/* 2>/dev/null | head -n 1
}

eval_one_run() {
  local result_dir="$1"
  local benchmark_dir="$2"
  python3 ../tools/eval/eval_jleaks_mlk.py \
    --result-dir "${result_dir}" \
    --benchmark-dir "${benchmark_dir}" \
    --output-dir "${result_dir}" >/dev/null
}

print_summary_line() {
  local label="$1"
  local result_dir="$2"
  python3 - "$label" "$result_dir" <<'PY'
import json, os, sys
label = sys.argv[1]
result_dir = sys.argv[2]
summary_path = os.path.join(result_dir, "eval_summary.json")
if not os.path.exists(summary_path):
    print(f"[{label}] NO eval_summary.json @ {result_dir}")
    raise SystemExit(0)
with open(summary_path, "r", encoding="utf-8") as f:
    d = json.load(f)
print(
    f"[{label}] recall={d.get('file_level_recall', 0):.4f} "
    f"precision={d.get('file_level_precision', 0):.4f} "
    f"reports={d.get('total_reports', 0)} "
    f"dup_extra={d.get('duplicate_extra_reports', 0)} "
    f"primary_hit={d.get('file_level_primary_defect_method_hit_ratio', 0):.4f} "
    f"loose_hit={d.get('file_level_loose_defect_method_hit_ratio', 0):.4f} "
    f"result={result_dir}"
)
PY
}

run_one_benchmark() {
  local label="$1"
  local benchmark_dir="$2"
  local benchmark_name="$3"

  echo "==> [${label}] scanning: ${benchmark_dir}"
  bash ./run_repoaudit.sh "${benchmark_dir}" MLK
  local latest
  latest="$(latest_run_dir "${benchmark_name}")"
  if [[ -z "${latest}" ]]; then
    echo "[${label}] ERROR: cannot locate latest run dir for ${benchmark_name}"
    return 1
  fi
  eval_one_run "${latest}" "${benchmark_dir}"
  print_summary_line "${label}" "${latest}" | tee -a "${SUMMARY_FILE}"
}

build_cd_subset_from_latest_198() {
  local latest_198="$1"
  local subset_dir="$2"
  local top_n="$3"
  python3 - "$latest_198" "$FULL_BENCH_DIR" "$subset_dir" "$top_n" <<'PY'
import csv, json, os, re, shutil, sys
from collections import defaultdict

latest_198, full_bench_dir, subset_dir, top_n = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
detect_info_path = os.path.join(latest_198, "detect_info_raw.json")
gt_csv = os.path.join(full_bench_dir, "metadata", "vulnerability_list.csv")
if not os.path.exists(detect_info_path):
    raise SystemExit(f"missing detect_info_raw.json: {detect_info_path}")
if not os.path.exists(gt_csv):
    raise SystemExit(f"missing vulnerability_list.csv: {gt_csv}")

with open(detect_info_path, "r", encoding="utf-8") as f:
    payload = json.load(f)
if isinstance(payload, dict):
    entries = [v for v in payload.values() if isinstance(v, dict)]
elif isinstance(payload, list):
    entries = [v for v in payload if isinstance(v, dict)]
else:
    entries = []

gt = {}
with open(gt_csv, "r", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        try:
            bug_id = int(row.get("bug_id", "0"))
        except Exception:
            continue
        defect_method = row.get("defect_method", "")
        if ":" in defect_method:
            defect_method = defect_method.rsplit(":", 1)[-1].strip()
        gt[bug_id] = row
        gt[bug_id]["defect_method"] = defect_method

bug_file_re = re.compile(r"jleaks-bug-(\d+)\.java", re.IGNORECASE)
def _bug_id_of_report(rep):
    text = str(rep.get("buggy_value", ""))
    m = bug_file_re.search(text.replace("\\", "/"))
    if m:
        return int(m.group(1))
    rf = rep.get("relevant_functions", [])
    if isinstance(rf, list) and len(rf) > 0 and isinstance(rf[0], list):
        for fp in rf[0]:
            m = bug_file_re.search(str(fp).replace("\\", "/"))
            if m:
                return int(m.group(1))
    return -1

reports_by_bug = defaultdict(list)
for rep in entries:
    bug_id = _bug_id_of_report(rep)
    if bug_id > 0:
        reports_by_bug[bug_id].append(rep)

ranked = []
for bug_id, reps in reports_by_bug.items():
    if len(reps) <= 1:
        continue
    source_lines = set()
    source_methods = set()
    for rep in reps:
        metadata = rep.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
        source_lines.add(int(metadata.get("source_line", -1)))
        source_methods.add(str(metadata.get("source_method_name", "")))
    defect_method = gt.get(bug_id, {}).get("defect_method", "")
    if len(source_lines) < len(reps):
        category = "A"
    elif len(source_methods) == 1 and len(source_lines) > 1:
        category = "B"
    elif len(source_methods) > 1 and defect_method in source_methods:
        category = "C"
    else:
        category = "D"
    if category in {"C", "D"}:
        ranked.append((len(reps) - 1, category, bug_id))

ranked.sort(key=lambda item: (-item[0], item[1], item[2]))
selected_bug_ids = [bug_id for _, _, bug_id in ranked[:top_n]]
if len(selected_bug_ids) == 0:
    raise SystemExit("no C/D duplicates found from latest detect_info; cannot build subset")

if os.path.exists(subset_dir):
    shutil.rmtree(subset_dir)
os.makedirs(os.path.join(subset_dir, "bug_files"), exist_ok=True)
os.makedirs(os.path.join(subset_dir, "metadata"), exist_ok=True)

src_bug_dir = os.path.join(full_bench_dir, "bug_files")
for bug_id in selected_bug_ids:
    fn = f"jleaks-bug-{bug_id}.java"
    src = os.path.join(src_bug_dir, fn)
    dst = os.path.join(subset_dir, "bug_files", fn)
    if os.path.exists(src):
        shutil.copy2(src, dst)

rows = []
with open(gt_csv, "r", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        try:
            bug_id = int(row.get("bug_id", "0"))
        except Exception:
            continue
        if bug_id in selected_bug_ids:
            rows.append(row)
rows.sort(key=lambda r: int(r["bug_id"]))

if len(rows) == 0:
    raise SystemExit("selected bug ids exist but no metadata rows were found")

out_csv = os.path.join(subset_dir, "metadata", "vulnerability_list.csv")
with open(out_csv, "w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)

selection_meta = {
    "source_result_dir": latest_198,
    "top_n": top_n,
    "selected_bug_count": len(selected_bug_ids),
    "selected_bug_ids": selected_bug_ids,
}
with open(os.path.join(subset_dir, "metadata", "selection_meta.json"), "w", encoding="utf-8") as f:
    json.dump(selection_meta, f, indent=2)
with open(os.path.join(subset_dir, "README.md"), "w", encoding="utf-8") as f:
    f.write(
        "# Auto-generated C/D duplicate stress subset\n\n"
        f"- source result: `{latest_198}`\n"
        f"- selected bugs: {len(selected_bug_ids)}\n"
    )
print(subset_dir)
PY
}

echo "Fast regression summary file: ${SUMMARY_FILE}"

if [[ "${FAST_RUN_QUICK}" == "true" ]]; then
  run_one_benchmark "quick20" "${QUICK_BENCH_DIR}" "${FAST_QUICK_BENCH}"
fi

if [[ "${FAST_RUN_CD_SUBSET}" == "true" ]]; then
  latest_198="$(latest_run_dir "${FAST_FULL_BENCH}" || true)"
  if [[ -z "${latest_198}" ]]; then
    echo "ERROR: cannot build C/D subset without existing ${FAST_FULL_BENCH} result"
    exit 1
  fi
  subset_path="$(build_cd_subset_from_latest_198 "${latest_198}" "${FAST_SUBSET_DIR}" "${FAST_CD_TOP_N}")"
  subset_name="$(basename -- "${subset_path}")"
  run_one_benchmark "cd_top${FAST_CD_TOP_N}" "${subset_path}" "${subset_name}"
fi

if [[ "${FAST_RUN_FULL}" == "true" ]]; then
  run_one_benchmark "full198" "${FULL_BENCH_DIR}" "${FAST_FULL_BENCH}"
fi

echo "Done. Summary:"
cat "${SUMMARY_FILE}"
