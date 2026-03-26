#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'EOF'
Usage:
  build_checker_framework_legacy.sh /path/to/checker-framework

Purpose:
  Build a historical Checker Framework checkout without using the original
  build.sh auto-pull chain. This script reuses already-prepared sibling repos:
    ../jdk
    ../annotation-tools
    ../stubparser
    ../jspecify

Environment variables:
  JDK11_HOME    Path to JDK 11 (default: /usr/lib/jvm/java-11-openjdk-amd64)
  SKIP_PREPARE  true/false, skip auto pinning sibling repos (default: false)
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || $# -lt 1 ]]; then
  usage
  exit 0
fi

CHECKER_DIR_INPUT="$1"
CHECKER_DIR="$(cd "$(dirname -- "$CHECKER_DIR_INPUT")" && pwd)/$(basename -- "$CHECKER_DIR_INPUT")"
RW_ROOT="$(cd "$CHECKER_DIR/.." && pwd)"
JDK11_HOME="${JDK11_HOME:-/usr/lib/jvm/java-11-openjdk-amd64}"
SKIP_PREPARE="${SKIP_PREPARE:-false}"

if [[ ! -d "$CHECKER_DIR/.git" ]]; then
  echo "[Error] checker-framework repo not found: $CHECKER_DIR" >&2
  exit 1
fi

if [[ ! -x "$JDK11_HOME/bin/java" || ! -x "$JDK11_HOME/bin/javac" ]]; then
  echo "[Error] JDK11_HOME is invalid: $JDK11_HOME" >&2
  exit 1
fi

if [[ "$SKIP_PREPARE" != "true" ]]; then
  bash "$SCRIPT_DIR/prepare_checker_framework_legacy_env.sh" "$CHECKER_DIR"
fi

for sibling in jdk annotation-tools stubparser jspecify; do
  if [[ ! -d "$RW_ROOT/$sibling/.git" ]]; then
    echo "[Error] Missing sibling repo: $RW_ROOT/$sibling" >&2
    exit 1
  fi
done

export JAVA_HOME="$JDK11_HOME"
export PATH="$JAVA_HOME/bin:$PATH"
export CHECKERFRAMEWORK="$CHECKER_DIR"

echo "[Info] JAVA_HOME=$JAVA_HOME"
java -version
javac -version

AT_DIR="$RW_ROOT/annotation-tools"
STUBPARSER_DIR="$RW_ROOT/stubparser"
JSPECIFY_DIR="$RW_ROOT/jspecify"

echo "[Info] annotation-tools @ $(git -C "$AT_DIR" rev-parse --short HEAD)"
echo "[Info] stubparser      @ $(git -C "$STUBPARSER_DIR" rev-parse --short HEAD)"
echo "[Info] jspecify        @ $(git -C "$JSPECIFY_DIR" rev-parse --short HEAD)"
echo "[Info] jdk             @ $(git -C "$RW_ROOT/jdk" rev-parse --short HEAD)"

echo "[Step] Building annotation-tools"
(cd "$AT_DIR" && ./.build-without-test.sh)

echo "[Step] Building stubparser"
(cd "$STUBPARSER_DIR" && ./.build-without-test.sh)

echo "[Step] Building jspecify"
(
  cd "$JSPECIFY_DIR"
  export JAVA_HOME="$JDK11_HOME"
  export PATH="$JAVA_HOME/bin:$PATH"
  ./gradlew build
)

echo "[Step] Building checker-framework"
(
  cd "$CHECKER_DIR"
  ./gradlew help > /dev/null 2>&1 || sleep 10
  ./gradlew assemble --console=plain --warning-mode=all -s \
    -Dorg.gradle.internal.http.socketTimeout=60000 \
    -Dorg.gradle.internal.http.connectionTimeout=60000
)

echo "[OK] Checker Framework legacy build completed."
