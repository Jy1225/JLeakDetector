#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# 用途：
#   为 typetools/checker-framework 生成“多模块 + 合并”的 soot facts。
#   该项目本身是多模块，同时常依赖兄弟仓库 annotation-tools / stubparser / jspecify。
#
# 使用示例：
#   bash real_world_test/generate_merge_soot_checker_framework.sh ~/Desktop/real_world_repos/checker-framework
#
# 约定：
#   - PROJECT_PATH 只分析 checker-framework 自己的模块
#   - 兄弟仓库若存在，其编译产物只加入 classpath，不作为 input-dir 分析对象

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPOAUDIT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MERGER_PY="$SCRIPT_DIR/merge_soot_facts.py"

PROJECT_PATH="${1:-${PROJECT_PATH:-}}"
if [[ -z "$PROJECT_PATH" ]]; then
  echo "Usage: bash $0 /path/to/checker-framework"
  exit 1
fi
PROJECT_PATH="$(cd "$PROJECT_PATH" && pwd)"
WORKSPACE_ROOT="${CHECKER_WORKSPACE_ROOT:-$(cd "$PROJECT_PATH/.." && pwd)}"

SOOT_JAR="${SOOT_JAR:-$REPOAUDIT_DIR/tools/soot_bridge/target/soot-bridge-all.jar}"
JAVA_BIN="${JAVA_BIN:-${JAVA_HOME:+$JAVA_HOME/bin/java}}"
JAVA_BIN="${JAVA_BIN:-java}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

HEAP_OPTS="${HEAP_OPTS:--Xms512m -Xmx4g}"
BRIDGE_CG="${BRIDGE_CG:-cha}"
BRIDGE_WHOLE_PROGRAM="${BRIDGE_WHOLE_PROGRAM:-false}"
BRIDGE_MAX_METHODS="${BRIDGE_MAX_METHODS:-}"
MODULE_FILTER="${MODULE_FILTER:-}"
CONTINUE_ON_BRIDGE_FAILURE="${CONTINUE_ON_BRIDGE_FAILURE:-true}"

OUT_ROOT="${OUT_ROOT:-$PROJECT_PATH/.repoaudit/checker_bridge}"
MODULE_OUT_DIR="$OUT_ROOT/modules"
MERGED_FACTS="${MERGED_FACTS:-$PROJECT_PATH/.repoaudit/soot_facts_merged.json}"
MANIFEST_PATH="$OUT_ROOT/module_manifest.tsv"
FAIL_LOG="$OUT_ROOT/failed_modules.log"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[Error] command not found: $1" >&2
    exit 1
  }
}

has_class_files() {
  local class_dir="$1"
  local one_file
  one_file="$(find "$class_dir" -type f -name '*.class' -print -quit 2>/dev/null || true)"
  [[ -n "$one_file" ]]
}

sanitize_name() {
  printf '%s' "$1" | sed 's#[/\\:]#_#g; s#[^A-Za-z0-9_.-]#_#g'
}

join_by_colon() {
  local IFS=':'
  echo "$*"
}

dedupe_array() {
  local -n input_ref=$1
  local -n output_ref=$2
  local item
  declare -A seen=()
  output_ref=()
  for item in "${input_ref[@]}"; do
    [[ -z "$item" ]] && continue
    if [[ -z "${seen[$item]+x}" ]]; then
      seen["$item"]=1
      output_ref+=("$item")
    fi
  done
}

run_bridge() {
  local class_dir="$1"
  local module_name="$2"
  local analysis_cp="$3"
  local output_json="$4"
  local runtime_cp="$SOOT_JAR"
  local -a heap_arr=()
  local -a cmd=()

  if [[ -n "$analysis_cp" ]]; then
    runtime_cp="$SOOT_JAR:$analysis_cp"
  else
    analysis_cp="$class_dir"
    runtime_cp="$SOOT_JAR:$class_dir"
  fi

  read -r -a heap_arr <<< "$HEAP_OPTS"
  cmd=("$JAVA_BIN")
  if (( ${#heap_arr[@]} > 0 )); then
    cmd+=("${heap_arr[@]}")
  fi
  cmd+=(
    -cp "$runtime_cp"
    repoaudit.soot.BridgeMain
    --input-dir "$class_dir"
    --classpath "$analysis_cp"
    --output "$output_json"
    --whole-program "$BRIDGE_WHOLE_PROGRAM"
    --cg "$BRIDGE_CG"
  )
  if [[ -n "$BRIDGE_MAX_METHODS" ]]; then
    cmd+=(--max-methods "$BRIDGE_MAX_METHODS")
  fi

  echo "[Info] bridge module: $module_name"
  echo "[Info] class dir: $class_dir"
  "${cmd[@]}"
}

collect_main_class_dirs() {
  local root_path="$1"
  while IFS= read -r -d '' dir_path; do
    if ! has_class_files "$dir_path"; then
      continue
    fi
    echo "$dir_path"
  done < <(find "$root_path" -type d -path '*/build/classes/java/main' -print0)
}

require_cmd "$JAVA_BIN"
require_cmd "$PYTHON_BIN"
[[ -d "$PROJECT_PATH" ]] || { echo "[Error] project path does not exist: $PROJECT_PATH" >&2; exit 1; }
[[ -f "$SOOT_JAR" ]] || { echo "[Error] soot bridge jar does not exist: $SOOT_JAR" >&2; exit 1; }
[[ -f "$MERGER_PY" ]] || { echo "[Error] merger script does not exist: $MERGER_PY" >&2; exit 1; }

mkdir -p "$MODULE_OUT_DIR"
: > "$MANIFEST_PATH"
: > "$FAIL_LOG"

declare -a project_class_dirs=()
declare -a filtered_project_class_dirs=()
declare -a deduped_project_class_dirs=()
declare -a extra_class_dirs=()
declare -a deduped_extra_class_dirs=()
declare -a jar_paths=()
declare -a deduped_jars=()
declare -a cp_entries=()
declare -a module_jsons=()

while IFS= read -r dir_path; do
  [[ -z "$dir_path" ]] && continue
  project_class_dirs+=("$dir_path")
done < <(collect_main_class_dirs "$PROJECT_PATH")

if (( ${#project_class_dirs[@]} == 0 )); then
  echo "[Error] no checker-framework main class directories found. Please finish build first." >&2
  exit 1
fi

for dir_path in "${project_class_dirs[@]}"; do
  if [[ -n "$MODULE_FILTER" && "$dir_path" != *"$MODULE_FILTER"* ]]; then
    continue
  fi
  filtered_project_class_dirs+=("$dir_path")
done
dedupe_array filtered_project_class_dirs deduped_project_class_dirs

if (( ${#deduped_project_class_dirs[@]} == 0 )); then
  echo "[Error] no checker-framework module matched MODULE_FILTER='$MODULE_FILTER'" >&2
  exit 1
fi

for sibling_name in annotation-tools stubparser jspecify; do
  sibling_path="$WORKSPACE_ROOT/$sibling_name"
  if [[ ! -d "$sibling_path" ]]; then
    continue
  fi
  while IFS= read -r dir_path; do
    [[ -z "$dir_path" ]] && continue
    extra_class_dirs+=("$dir_path")
  done < <(collect_main_class_dirs "$sibling_path")
done
dedupe_array extra_class_dirs deduped_extra_class_dirs

while IFS= read -r -d '' jar_path; do
  jar_paths+=("$jar_path")
done < <(
  find "$PROJECT_PATH" "$WORKSPACE_ROOT/annotation-tools" "$WORKSPACE_ROOT/stubparser" "$WORKSPACE_ROOT/jspecify" \
    -type f -name '*.jar' 2>/dev/null -print0
)
dedupe_array jar_paths deduped_jars

cp_entries=("${deduped_project_class_dirs[@]}" "${deduped_extra_class_dirs[@]}" "${deduped_jars[@]}")
GLOBAL_CP="$(join_by_colon "${cp_entries[@]}")"

echo "[Info] checker-framework module count: ${#deduped_project_class_dirs[@]}"
echo "[Info] sibling helper class-dir count: ${#deduped_extra_class_dirs[@]}"
echo "[Info] jar count in workspace: ${#deduped_jars[@]}"
echo -e "module_name\tclass_dir\toutput_json" >> "$MANIFEST_PATH"

for class_dir in "${deduped_project_class_dirs[@]}"; do
  rel_path="${class_dir#$PROJECT_PATH/}"
  module_name="$(sanitize_name "$rel_path")"
  output_json="$MODULE_OUT_DIR/${module_name}.json"
  echo -e "${module_name}\t${class_dir}\t${output_json}" >> "$MANIFEST_PATH"

  if run_bridge "$class_dir" "$module_name" "$GLOBAL_CP" "$output_json"; then
    module_jsons+=("$output_json")
  else
    echo "[Warn] bridge failed for module: $module_name" >&2
    echo -e "${module_name}\t${class_dir}" >> "$FAIL_LOG"
    if [[ "$CONTINUE_ON_BRIDGE_FAILURE" != "true" ]]; then
      exit 1
    fi
  fi
done

if (( ${#module_jsons[@]} == 0 )); then
  echo "[Error] no checker-framework module facts were generated successfully." >&2
  exit 1
fi

"$PYTHON_BIN" "$MERGER_PY" --output "$MERGED_FACTS" "${module_jsons[@]}"

echo "[Info] merged soot facts: $MERGED_FACTS"
echo "[Info] manifest: $MANIFEST_PATH"
if [[ -s "$FAIL_LOG" ]]; then
  echo "[Warn] some modules failed. See: $FAIL_LOG"
fi
