#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

# --- Defaults ---
# NOTE: Do NOT use env var LANGUAGE directly (it is commonly set by OS locale,
# e.g. "en_US:en"), which can break RepoAudit --language parsing.
# Use REPOAUDIT_LANGUAGE for overriding scan language.
ANALYSIS_LANGUAGE="${REPOAUDIT_LANGUAGE:-Java}"
MODEL="${MODEL:-deepseek-chat}"  # e.g. deepseek-chat, qwen3.5-plus, kimi-k2.5
DEFAULT_PROJECT_NAME="${DEFAULT_PROJECT_NAME:-jleaks_mlk_198}"
DEFAULT_BUG_TYPE="${DEFAULT_BUG_TYPE:-MLK}"     # allowed: MLK, NPD, UAF
SCAN_TYPE="${SCAN_TYPE:-dfbscan}"
REPOAUDIT_TEMPERATURE="${REPOAUDIT_TEMPERATURE:-0.0}"
REPOAUDIT_CALL_DEPTH="${REPOAUDIT_CALL_DEPTH:-15}"
REPOAUDIT_MAX_NEURAL_WORKERS="${REPOAUDIT_MAX_NEURAL_WORKERS:-16}"
ENABLE_SOOT_PREFILTER="${ENABLE_SOOT_PREFILTER:-true}"  # true/false
SOOT_SHADOW_MODE="${SOOT_SHADOW_MODE:-false}"        # true/false
SOOT_FACTS_PATH="${SOOT_FACTS_PATH:-}"             # path to soot_facts.json
SOOT_TIMEOUT_MS="${SOOT_TIMEOUT_MS:-200}"            # per-path timeout in ms
AUTO_GENERATE_SOOT_FACTS="${AUTO_GENERATE_SOOT_FACTS:-true}"  # true/false
SOOT_FACTS_MODE="${SOOT_FACTS_MODE:-bridge}"            # auto/bridge/ts-fallback
SOOT_BRIDGE_JAR="${SOOT_BRIDGE_JAR:-../tools/soot_bridge/target/soot-bridge-all.jar}"                # path to soot bridge jar for bridge mode
SOOT_BRIDGE_MAIN_CLASS="${SOOT_BRIDGE_MAIN_CLASS:-repoaudit.soot.BridgeMain}"
SOOT_CLASS_DIR="${SOOT_CLASS_DIR:-}"                 # optional class output dir for bridge mode
SOOT_COMPILE_BEFORE="${SOOT_COMPILE_BEFORE:-true}"       # true/false
SOOT_CLASSPATH="${SOOT_CLASSPATH:-}"                 # optional compile/runtime classpath
SOOT_TIMEOUT_SEC="${SOOT_TIMEOUT_SEC:-300}"              # timeout for soot bridge generation
ENABLE_Z3_PREFILTER="${ENABLE_Z3_PREFILTER:-false}"   # true/false
Z3_SHADOW_MODE="${Z3_SHADOW_MODE:-true}"        # true/false
Z3_TIMEOUT_MS="${Z3_TIMEOUT_MS:-200}"            # per-path timeout in ms
Z3_MIN_PARSED_CONSTRAINTS="${Z3_MIN_PARSED_CONSTRAINTS:-2}"  # conservative UNSAT skip threshold
REPOAUDIT_JAVA_MLK_ISSUE_FIRST="${REPOAUDIT_JAVA_MLK_ISSUE_FIRST:-true}"                           # true/false
REPOAUDIT_JAVA_MLK_MAX_WITNESS_PER_COMPONENT="${REPOAUDIT_JAVA_MLK_MAX_WITNESS_PER_COMPONENT:-2}" # 1-5
REPOAUDIT_JAVA_MLK_FAMILY_LINK_MODE="${REPOAUDIT_JAVA_MLK_FAMILY_LINK_MODE:-aggressive}"           # conservative/aggressive
REPOAUDIT_JAVA_MLK_SOURCE_CONFIDENCE_MIN="${REPOAUDIT_JAVA_MLK_SOURCE_CONFIDENCE_MIN:-low}"        # low/medium/high
REPOAUDIT_AUTO_EVAL_JLEAKS_MLK="${REPOAUDIT_AUTO_EVAL_JLEAKS_MLK:-false}"                         # true/false

# Construct the default project *path* from ANALYSIS_LANGUAGE + DEFAULT_PROJECT_NAME
DEFAULT_PROJECT_PATH="../benchmark/${ANALYSIS_LANGUAGE}/${DEFAULT_PROJECT_NAME}"

now_ts() {
  python3 -c 'import time; print(f"{time.time():.6f}")'
}

elapsed_sec() {
  python3 -c 'import sys; print(f"{float(sys.argv[2]) - float(sys.argv[1]):.3f}")' "$1" "$2"
}

PIPELINE_START_TS="$(now_ts)"
SOOT_FACTS_GENERATION_SEC="0.000"

show_usage() {
  cat <<'EOF'
Usage: run_repoaudit.sh [PROJECT_PATH] [BUG_TYPE]

Arguments:
  PROJECT_PATH   Optional absolute/relative path to the subject project.
                 Defaults to: ../benchmark/Java/toy
  BUG_TYPE       Optional bug type. One of: MLK, NPD, UAF. Defaults to: MLK

Bug type meanings:
  MLK  - Memory Leak
  NPD  - Null Pointer Dereference
  UAF  - Use After Free

Examples:
  ./run_repoaudit.sh
  ./run_repoaudit.sh /path/to/my/project
  ./run_repoaudit.sh ./repos/demo UAF
  MODEL=qwen-plus ./run_repoaudit.sh /path/to/java/project MLK
  MODEL=kimi-k2.5 ./run_repoaudit.sh /path/to/java/project MLK
  ./run_repoaudit.sh --help

Model examples:
  deepseek-chat | deepseek-reasoner | qwen-plus | qwen-max | qwen-turbo | kimi-k2.5 | kimi-k2 | kimi-k2-thinking

API keys:
  Qwen: export DASHSCOPE_API_KEY=your_key
  Kimi: export MOONSHOT_API_KEY=your_key
EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  show_usage
  exit 0
fi

# --- Args ---
PROJECT_PATH="${1:-$DEFAULT_PROJECT_PATH}"
BUG_TYPE_RAW="${2:-$DEFAULT_BUG_TYPE}"

# Normalize BUG_TYPE to uppercase (accepts mlk/npd/uaf too)
BUG_TYPE="$(echo "$BUG_TYPE_RAW" | tr '[:lower:]' '[:upper:]')"

# --- Validate BUG_TYPE ---
case "$BUG_TYPE" in
  MLK|NPD|UAF) : ;;
  *)
    echo "Error: BUG_TYPE must be one of: MLK, NPD, UAF (got '$BUG_TYPE_RAW')." >&2
    echo "       MLK = Memory Leak; NPD = Null Pointer Dereference; UAF = Use After Free." >&2
    exit 1
    ;;
esac

# --- Resolve and validate PROJECT_PATH ---
if ! PROJECT_PATH_ABS="$(cd "$(dirname -- "$PROJECT_PATH")" && pwd)/$(basename -- "$PROJECT_PATH")"; then
  echo "Error: Could not resolve PROJECT_PATH: $PROJECT_PATH" >&2
  exit 1
fi

if [[ ! -d "$PROJECT_PATH_ABS" ]]; then
  echo "Error: PROJECT_PATH does not exist or is not a directory: $PROJECT_PATH_ABS" >&2
  exit 1
fi

# JLeaks snippets are often non-compilable standalone Java units.
# If user keeps bridge mode, downgrade to ts-fallback for compatibility.
if [[ "$PROJECT_PATH_ABS" == *"/jleaks"* || "$PROJECT_PATH_ABS" == *"\\jleaks"* ]]; then
  if [[ "$ENABLE_SOOT_PREFILTER" == "true" && "$SOOT_FACTS_MODE" == "bridge" ]]; then
    echo "[Info] Detected JLeaks-like dataset path. Switch SOOT_FACTS_MODE=ts-fallback and SOOT_COMPILE_BEFORE=false."
    SOOT_FACTS_MODE="ts-fallback"
    SOOT_COMPILE_BEFORE="false"
  fi
fi

if [[ "$ENABLE_SOOT_PREFILTER" == "true" && "$AUTO_GENERATE_SOOT_FACTS" == "true" ]]; then
  SOOT_GEN_START_TS="$(now_ts)"
  if [[ -z "$SOOT_FACTS_PATH" ]]; then
    SOOT_FACTS_PATH="$PROJECT_PATH_ABS/.repoaudit/soot_facts.json"
  fi

  SOOT_GEN_FLAGS=(
    --project-path "$PROJECT_PATH_ABS"
    --output "$SOOT_FACTS_PATH"
    --mode "$SOOT_FACTS_MODE"
    --bridge-main-class "$SOOT_BRIDGE_MAIN_CLASS"
    --soot-timeout-sec "$SOOT_TIMEOUT_SEC"
    --java-bin "java"
    --javac-bin "javac"
  )

  if [[ -n "$SOOT_BRIDGE_JAR" ]]; then
    SOOT_GEN_FLAGS+=(--bridge-jar "$SOOT_BRIDGE_JAR")
  fi
  if [[ -n "$SOOT_CLASS_DIR" ]]; then
    SOOT_GEN_FLAGS+=(--class-dir "$SOOT_CLASS_DIR")
  fi
  if [[ -n "$SOOT_CLASSPATH" ]]; then
    SOOT_GEN_FLAGS+=(--classpath "$SOOT_CLASSPATH")
  fi
  if [[ "$SOOT_COMPILE_BEFORE" == "true" ]]; then
    SOOT_GEN_FLAGS+=(--compile-before)
  fi

  if ! python3 tstool/validator/generate_java_soot_facts.py "${SOOT_GEN_FLAGS[@]}"; then
    if [[ "$SOOT_FACTS_MODE" != "ts-fallback" ]]; then
      echo "[Warn] Soot facts generation failed in mode=$SOOT_FACTS_MODE; retry with ts-fallback."
      python3 tstool/validator/generate_java_soot_facts.py \
        --project-path "$PROJECT_PATH_ABS" \
        --output "$SOOT_FACTS_PATH" \
        --mode "ts-fallback"
    else
      echo "[Error] Soot facts generation failed in ts-fallback mode." >&2
      exit 1
    fi
  fi
  SOOT_GEN_END_TS="$(now_ts)"
  SOOT_FACTS_GENERATION_SEC="$(elapsed_sec "$SOOT_GEN_START_TS" "$SOOT_GEN_END_TS")"
fi

# --- Run ---
REACHABILITY_FLAG=()
if [[ "$BUG_TYPE" == "NPD" || "$BUG_TYPE" == "UAF" ]]; then
  REACHABILITY_FLAG=(--is-reachable)
fi

SOOT_FLAGS=()
if [[ "$ENABLE_SOOT_PREFILTER" == "true" ]]; then
  SOOT_FLAGS+=(--enable-soot-prefilter)
fi
if [[ "$SOOT_SHADOW_MODE" == "true" ]]; then
  SOOT_FLAGS+=(--soot-shadow-mode)
fi
if [[ -n "$SOOT_FACTS_PATH" ]]; then
  SOOT_FLAGS+=(--soot-facts-path "$SOOT_FACTS_PATH")
fi
SOOT_FLAGS+=(--soot-timeout-ms "$SOOT_TIMEOUT_MS")

Z3_FLAGS=()
if [[ "$ENABLE_Z3_PREFILTER" == "true" ]]; then
  Z3_FLAGS+=(--enable-z3-prefilter)
fi
if [[ "$Z3_SHADOW_MODE" == "true" ]]; then
  Z3_FLAGS+=(--z3-shadow-mode)
fi
Z3_FLAGS+=(--z3-timeout-ms "$Z3_TIMEOUT_MS")
Z3_FLAGS+=(--z3-min-parsed-constraints "$Z3_MIN_PARSED_CONSTRAINTS")

if ! REPOAUDIT_JAVA_MLK_ISSUE_FIRST="$REPOAUDIT_JAVA_MLK_ISSUE_FIRST" \
REPOAUDIT_JAVA_MLK_MAX_WITNESS_PER_COMPONENT="$REPOAUDIT_JAVA_MLK_MAX_WITNESS_PER_COMPONENT" \
REPOAUDIT_JAVA_MLK_FAMILY_LINK_MODE="$REPOAUDIT_JAVA_MLK_FAMILY_LINK_MODE" \
REPOAUDIT_JAVA_MLK_SOURCE_CONFIDENCE_MIN="$REPOAUDIT_JAVA_MLK_SOURCE_CONFIDENCE_MIN" \
python3 repoaudit.py \
  --language "$ANALYSIS_LANGUAGE" \
  --model-name "$MODEL" \
  --project-path "$PROJECT_PATH_ABS" \
  --bug-type "$BUG_TYPE" \
  "${REACHABILITY_FLAG[@]}" \
  --temperature "$REPOAUDIT_TEMPERATURE" \
  --scan-type "$SCAN_TYPE" \
  --call-depth "$REPOAUDIT_CALL_DEPTH" \
  --max-neural-workers "$REPOAUDIT_MAX_NEURAL_WORKERS" \
  "${SOOT_FLAGS[@]}" \
  "${Z3_FLAGS[@]}"; then
  exit 1
fi

PIPELINE_END_TS="$(now_ts)"
PIPELINE_TOTAL_SEC="$(elapsed_sec "$PIPELINE_START_TS" "$PIPELINE_END_TS")"

if [[ "$SCAN_TYPE" == "dfbscan" ]]; then
  RESULT_ROOT="../result/dfbscan/${MODEL}/${BUG_TYPE}/${ANALYSIS_LANGUAGE}/$(basename -- "$PROJECT_PATH_ABS")"
  LATEST_RESULT_DIR="$(ls -1dt "$RESULT_ROOT"/* 2>/dev/null | head -n 1 || true)"
  if [[ -n "$LATEST_RESULT_DIR" ]]; then
    METRICS_PATH="$LATEST_RESULT_DIR/run_metrics_raw.json"
    python3 - "$METRICS_PATH" "$PIPELINE_TOTAL_SEC" "$SOOT_FACTS_GENERATION_SEC" <<'PY'
import json
import sys
from pathlib import Path

metrics_path = Path(sys.argv[1])
pipeline_total_sec = float(sys.argv[2])
soot_generation_sec = float(sys.argv[3])

if metrics_path.exists():
    with open(metrics_path, "r", encoding="utf-8") as f:
        payload = json.load(f)
else:
    payload = {"schema_version": "1.0", "timing": {}, "llm_usage": {}}

timing = payload.setdefault("timing", {})
timing["pipeline_total_sec"] = round(pipeline_total_sec, 3)
timing["soot_facts_generation_sec"] = round(soot_generation_sec, 3)

with open(metrics_path, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=4)
PY
    echo "[Info] Raw run metrics written to: $METRICS_PATH"
  fi
fi

if [[ "$REPOAUDIT_AUTO_EVAL_JLEAKS_MLK" == "true" \
   && "$ANALYSIS_LANGUAGE" == "Java" \
   && "$BUG_TYPE" == "MLK" \
   && "$PROJECT_PATH_ABS" == *"jleaks_mlk_"* ]]; then
  RESULT_ROOT="../result/dfbscan/${MODEL}/${BUG_TYPE}/${ANALYSIS_LANGUAGE}/$(basename -- "$PROJECT_PATH_ABS")"
  LATEST_RESULT_DIR="$(ls -1dt "$RESULT_ROOT"/* 2>/dev/null | head -n 1 || true)"
  if [[ -n "$LATEST_RESULT_DIR" && -f "../tools/eval/eval_jleaks_mlk.py" ]]; then
    echo "[Info] Auto-evaluating latest run: $LATEST_RESULT_DIR"
    python3 ../tools/eval/eval_jleaks_mlk.py \
      --result-dir "$LATEST_RESULT_DIR" \
      --benchmark-dir "$PROJECT_PATH_ABS" \
      --output-dir "$LATEST_RESULT_DIR" || true
  fi
fi
