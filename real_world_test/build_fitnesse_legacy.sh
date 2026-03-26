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

if [[ ! -f "./build.xml" ]]; then
  echo "[Error] build.xml not found in $PROJECT_PATH" >&2
  exit 1
fi

echo "[Step] Preparing FitNesse antlib jars"
mkdir -p antlib
if grep -q 'http://repo2.maven.org/maven2' build.xml; then
  sed -i 's#http://repo2.maven.org/maven2#https://repo.maven.apache.org/maven2#g' build.xml
fi

curl -L https://repo.maven.apache.org/maven2/org/apache/ivy/ivy/2.4.0/ivy-2.4.0.jar -o antlib/ivy.jar
curl -L https://repo.maven.apache.org/maven2/org/bouncycastle/bcprov-jdk16/1.46/bcprov-jdk16-1.46.jar -o antlib/bcprov.jar
curl -L https://repo.maven.apache.org/maven2/org/bouncycastle/bcpg-jdk16/1.46/bcpg-jdk16-1.46.jar -o antlib/bcpg.jar

echo "[Step] Building FitNesse with Ant compile task"
ant compile

echo "[Info] Candidate class directories:"
find . -maxdepth 2 -type d \( -name 'classes' -o -path '*/classes/java/main' -o -path '*/classes/main' \) 2>/dev/null | sort || true
echo "[OK] FitNesse legacy build completed."
