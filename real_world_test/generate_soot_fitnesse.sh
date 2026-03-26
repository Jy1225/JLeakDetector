#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPOAUDIT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  generate_soot_fitnesse.sh /path/to/fitnesse

Environment:
  SOOT_JAR         Path to soot bridge fat jar
  PYTHON_BIN       Python executable (default: python3)
  JAVA_BIN         Java executable (default: $JAVA_HOME/bin/java or java)
  JAVAC_BIN        Javac executable (default: $JAVA_HOME/bin/javac or javac)
  SOOT_OUTPUT      Output facts path (default: <project>/.repoaudit/soot_facts.json)
  EXTRA_CLASSPATH  Optional extra classpath entries joined by :
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || $# -lt 1 ]]; then
  usage
  exit 0
fi

PROJECT_PATH_INPUT="$1"
PROJECT_PATH="$(cd "$(dirname -- "$PROJECT_PATH_INPUT")" && pwd)/$(basename -- "$PROJECT_PATH_INPUT")"
SOOT_JAR="${SOOT_JAR:-$REPOAUDIT_DIR/tools/soot_bridge/target/soot-bridge-all.jar}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
JAVA_BIN="${JAVA_BIN:-${JAVA_HOME:+$JAVA_HOME/bin/java}}"
JAVA_BIN="${JAVA_BIN:-java}"
JAVAC_BIN="${JAVAC_BIN:-${JAVA_HOME:+$JAVA_HOME/bin/javac}}"
JAVAC_BIN="${JAVAC_BIN:-javac}"
SOOT_OUTPUT="${SOOT_OUTPUT:-$PROJECT_PATH/.repoaudit/soot_facts.json}"
EXTRA_CLASSPATH="${EXTRA_CLASSPATH:-}"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[Error] command not found: $1" >&2
    exit 1
  }
}

find_class_dir() {
  for candidate in \
    "$PROJECT_PATH/classes" \
    "$PROJECT_PATH/build/classes/java/main" \
    "$PROJECT_PATH/build/classes/main" \
    "$PROJECT_PATH/build/classes"; do
    if [[ -d "$candidate" ]]; then
      local one_class
      one_class="$(find "$candidate" -type f -name '*.class' -print -quit 2>/dev/null || true)"
      if [[ -n "$one_class" ]]; then
        echo "$candidate"
        return
      fi
    fi
  done
}

require_cmd "$PYTHON_BIN"
require_cmd "$JAVA_BIN"
require_cmd "$JAVAC_BIN"
[[ -d "$PROJECT_PATH" ]] || { echo "[Error] project path does not exist: $PROJECT_PATH" >&2; exit 1; }
[[ -f "$SOOT_JAR" ]] || { echo "[Error] soot bridge jar not found: $SOOT_JAR" >&2; exit 1; }

CLASS_DIR="$(find_class_dir)"
if [[ -z "$CLASS_DIR" ]]; then
  echo "[Error] no compiled FitNesse class directory found. Please run 'ant compile' first." >&2
  exit 1
fi

CLASSPATH="$CLASS_DIR"
if [[ -n "$EXTRA_CLASSPATH" ]]; then
  CLASSPATH="$EXTRA_CLASSPATH:$CLASSPATH"
fi

mkdir -p "$(dirname "$SOOT_OUTPUT")"

echo "[Info] FitNesse class dir: $CLASS_DIR"
echo "[Info] FitNesse soot output: $SOOT_OUTPUT"

"$PYTHON_BIN" "$REPOAUDIT_DIR/src/tstool/validator/generate_java_soot_facts.py" \
  --project-path "$PROJECT_PATH" \
  --output "$SOOT_OUTPUT" \
  --mode bridge \
  --bridge-jar "$SOOT_JAR" \
  --class-dir "$CLASS_DIR" \
  --classpath "$CLASSPATH" \
  --java-bin "$JAVA_BIN" \
  --javac-bin "$JAVAC_BIN" \
  --soot-timeout-sec 600

echo "[OK] Generated FitNesse soot facts: $SOOT_OUTPUT"
