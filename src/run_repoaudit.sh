#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

# --- Defaults ---
LANGUAGE="Java"
MODEL="deepseek-chat"
DEFAULT_PROJECT_NAME="toy"
DEFAULT_BUG_TYPE="MLK"     # allowed: MLK, NPD, UAF
SCAN_TYPE="dfbscan"
ENABLE_SOOT_PREFILTER="false"  # true/false
SOOT_SHADOW_MODE="true"        # true/false
SOOT_FACTS_PATH=""             # path to soot_facts.json
SOOT_TIMEOUT_MS=200            # per-path timeout in ms
AUTO_GENERATE_SOOT_FACTS="false"  # true/false
SOOT_FACTS_MODE="auto"            # auto/bridge/ts-fallback
SOOT_BRIDGE_JAR=""                # path to soot bridge jar for bridge mode
SOOT_BRIDGE_MAIN_CLASS="repoaudit.soot.BridgeMain"
SOOT_CLASS_DIR=""                 # optional class output dir for bridge mode
SOOT_COMPILE_BEFORE="false"       # true/false
SOOT_CLASSPATH=""                 # optional compile/runtime classpath
SOOT_TIMEOUT_SEC=300              # timeout for soot bridge generation
ENABLE_Z3_PREFILTER="true"   # true/false
Z3_SHADOW_MODE="false"        # true/false
Z3_TIMEOUT_MS=200            # per-path timeout in ms
Z3_MIN_PARSED_CONSTRAINTS=2  # conservative UNSAT skip threshold

# Construct the default project *path* from LANGUAGE + DEFAULT_PROJECT_NAME
DEFAULT_PROJECT_PATH="../benchmark/${LANGUAGE}/${DEFAULT_PROJECT_NAME}"

show_usage() {
  cat <<'EOF'
Usage: run_scan.sh [PROJECT_PATH] [BUG_TYPE]

Arguments:
  PROJECT_PATH   Optional absolute/relative path to the subject project.
                 Defaults to: ../benchmark/Java/toy
  BUG_TYPE       Optional bug type. One of: MLK, NPD, UAF. Defaults to: MLK

Bug type meanings:
  MLK  - Memory Leak
  NPD  - Null Pointer Dereference
  UAF  - Use After Free

Examples:
  ./run_scan.sh
  ./run_scan.sh /path/to/my/project
  ./run_scan.sh ./repos/demo UAF
  ./run_scan.sh --help
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

if [[ "$ENABLE_SOOT_PREFILTER" == "true" && "$AUTO_GENERATE_SOOT_FACTS" == "true" ]]; then
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

  python3 tstool/validator/generate_java_soot_facts.py "${SOOT_GEN_FLAGS[@]}"
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

python3 repoaudit.py \
  --language "$LANGUAGE" \
  --model-name "$MODEL" \
  --project-path "$PROJECT_PATH_ABS" \
  --bug-type "$BUG_TYPE" \
  "${REACHABILITY_FLAG[@]}" \
  --temperature 0.0 \
  --scan-type "$SCAN_TYPE" \
  --call-depth 15 \
  --max-neural-workers 16 \
  "${SOOT_FLAGS[@]}" \
  "${Z3_FLAGS[@]}"
