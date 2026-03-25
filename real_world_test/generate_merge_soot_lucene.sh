#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# 用途：
#   为 apache/lucene（历史 Lucene/Solr 单仓，多模块 Ant 项目）
#   逐模块生成 soot_facts.json，并最终合并成一个 merged 文件。
#
# 使用示例：
#   bash real_world_test/generate_merge_soot_lucene.sh ~/Desktop/real_world_repos/lucene
#
# 重要说明：
#   1. 请先确保项目已经完成 `ant compile`
#   2. 默认使用 bridge + CHA + non-whole-program，优先保证大项目能跑动
#   3. 允许单个模块 bridge 失败后继续，最后合并成功模块的结果

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPOAUDIT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MERGER_PY="$SCRIPT_DIR/merge_soot_facts.py"

PROJECT_PATH="${1:-${PROJECT_PATH:-}}"
if [[ -z "$PROJECT_PATH" ]]; then
  echo "Usage: bash $0 /path/to/lucene"
  exit 1
fi
PROJECT_PATH="$(cd "$PROJECT_PATH" && pwd)"

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

OUT_ROOT="${OUT_ROOT:-$PROJECT_PATH/.repoaudit/lucene_bridge}"
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

require_cmd "$JAVA_BIN"
require_cmd "$PYTHON_BIN"
[[ -d "$PROJECT_PATH" ]] || { echo "[Error] project path does not exist: $PROJECT_PATH" >&2; exit 1; }
[[ -f "$SOOT_JAR" ]] || { echo "[Error] soot bridge jar does not exist: $SOOT_JAR" >&2; exit 1; }
[[ -f "$MERGER_PY" ]] || { echo "[Error] merger script does not exist: $MERGER_PY" >&2; exit 1; }

mkdir -p "$MODULE_OUT_DIR"
: > "$MANIFEST_PATH"
: > "$FAIL_LOG"

declare -a discovered_class_dirs=()
declare -a filtered_class_dirs=()
declare -a deduped_class_dirs=()
declare -a jar_paths=()
declare -a deduped_jars=()
declare -a cp_entries=()
declare -a module_jsons=()

while IFS= read -r -d '' dir_path; do
  case "$dir_path" in
    */test-classes|*/classes/test|*/build/test/*|*/target/test-classes/*|*/generated/*)
      continue
      ;;
  esac
  if ! has_class_files "$dir_path"; then
    continue
  fi
  discovered_class_dirs+=("$dir_path")
done < <(
  find "$PROJECT_PATH" -type d \
    \( -path '*/build/classes' -o -path '*/build/classes/java/main' -o -path '*/build/*/classes' -o -path '*/build/*/classes/java' \) \
    -print0
)

if (( ${#discovered_class_dirs[@]} == 0 )); then
  echo "[Error] no compiled Lucene/Solr class directories found. Please run 'ant compile' first." >&2
  exit 1
fi

for dir_path in "${discovered_class_dirs[@]}"; do
  if [[ -n "$MODULE_FILTER" && "$dir_path" != *"$MODULE_FILTER"* ]]; then
    continue
  fi
  filtered_class_dirs+=("$dir_path")
done
dedupe_array filtered_class_dirs deduped_class_dirs

if (( ${#deduped_class_dirs[@]} == 0 )); then
  echo "[Error] no module matched MODULE_FILTER='$MODULE_FILTER'" >&2
  exit 1
fi

while IFS= read -r -d '' jar_path; do
  jar_paths+=("$jar_path")
done < <(find "$PROJECT_PATH" -type f -name '*.jar' -print0)
dedupe_array jar_paths deduped_jars

cp_entries=("${deduped_class_dirs[@]}" "${deduped_jars[@]}")
GLOBAL_CP="$(join_by_colon "${cp_entries[@]}")"

echo "[Info] Lucene module count: ${#deduped_class_dirs[@]}"
echo "[Info] Lucene jar count in repo: ${#deduped_jars[@]}"
echo -e "module_name\tclass_dir\toutput_json" >> "$MANIFEST_PATH"

for class_dir in "${deduped_class_dirs[@]}"; do
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
  echo "[Error] no Lucene module facts were generated successfully." >&2
  exit 1
fi

"$PYTHON_BIN" "$MERGER_PY" --output "$MERGED_FACTS" "${module_jsons[@]}"

echo "[Info] merged soot facts: $MERGED_FACTS"
echo "[Info] manifest: $MANIFEST_PATH"
if [[ -s "$FAIL_LOG" ]]; then
  echo "[Warn] some modules failed. See: $FAIL_LOG"
fi
