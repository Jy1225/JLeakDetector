#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

usage() {
  cat <<'EOF'
Usage:
  build_fitnesse_legacy.sh /path/to/fitnesse

Environment:
  JDK8_HOME  Path to JDK 8. Default: /usr/lib/jvm/java-8-openjdk-amd64
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || $# -lt 1 ]]; then
  usage
  exit 0
fi

PROJECT_PATH_INPUT="$1"
PROJECT_PATH="$(cd "$(dirname -- "$PROJECT_PATH_INPUT")" && pwd)/$(basename -- "$PROJECT_PATH_INPUT")"
JDK8_HOME="${JDK8_HOME:-/usr/lib/jvm/java-8-openjdk-amd64}"

if [[ ! -d "$PROJECT_PATH/.git" ]]; then
  echo "[Error] FitNesse repo not found: $PROJECT_PATH" >&2
  exit 1
fi

if [[ ! -x "$JDK8_HOME/bin/java" || ! -x "$JDK8_HOME/bin/javac" ]]; then
  echo "[Error] Invalid JDK8_HOME: $JDK8_HOME" >&2
  exit 1
fi

export JAVA_HOME="$JDK8_HOME"
export PATH="$JAVA_HOME/bin:$PATH"

echo "[Info] JAVA_HOME=$JAVA_HOME"
java -version
javac -version

cd "$PROJECT_PATH"
if [[ ! -x "./gradlew" ]]; then
  echo "[Error] ./gradlew not found in $PROJECT_PATH" >&2
  exit 1
fi

echo "[Step] Building FitNesse with Gradle classes task"
./gradlew classes --no-daemon --stacktrace

echo "[Info] Candidate class directories:"
find build -type d \( -path '*/classes/java/main' -o -path '*/classes/main' -o -path '*/classes' \) 2>/dev/null | sort || true
echo "[OK] FitNesse legacy build completed."
