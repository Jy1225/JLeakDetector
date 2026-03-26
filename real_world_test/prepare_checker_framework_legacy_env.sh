#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

usage() {
  cat <<'EOF'
Usage:
  prepare_checker_framework_legacy_env.sh /path/to/checker-framework

Purpose:
  Prepare sibling repositories for a historical Checker Framework checkout by
  pinning each sibling repo to the latest commit *before* the current
  checker-framework commit time. This avoids pulling incompatible modern heads.

Sibling repos handled:
  ../jdk
  ../annotation-tools
  ../stubparser
  ../jspecify
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || $# -lt 1 ]]; then
  usage
  exit 0
fi

CHECKER_DIR_INPUT="$1"
CHECKER_DIR="$(cd "$(dirname -- "$CHECKER_DIR_INPUT")" && pwd)/$(basename -- "$CHECKER_DIR_INPUT")"

if [[ ! -d "$CHECKER_DIR/.git" ]]; then
  echo "[Error] checker-framework repo not found: $CHECKER_DIR" >&2
  exit 1
fi

RW_ROOT="$(cd "$CHECKER_DIR/.." && pwd)"
CF_DATE="$(git -C "$CHECKER_DIR" show -s --format=%cI HEAD)"

echo "[Info] Checker Framework repo: $CHECKER_DIR"
echo "[Info] Sibling root: $RW_ROOT"
echo "[Info] Checker Framework commit date: $CF_DATE"

clone_if_missing() {
  local repo_url="$1"
  local dest_dir="$2"
  if [[ -d "$dest_dir/.git" ]]; then
    echo "[Info] Repo exists: $dest_dir"
    return
  fi
  echo "[Info] Cloning $repo_url -> $dest_dir"
  git clone "$repo_url" "$dest_dir"
}

ensure_full_history() {
  local repo_dir="$1"
  git -C "$repo_dir" fetch --tags origin >/dev/null 2>&1 || true
  git -C "$repo_dir" fetch --unshallow origin >/dev/null 2>&1 || true
}

detect_origin_branch() {
  local repo_dir="$1"
  local branch
  branch="$(git -C "$repo_dir" symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null || true)"
  branch="${branch#origin/}"
  if [[ -n "$branch" ]]; then
    echo "$branch"
    return
  fi
  if git -C "$repo_dir" show-ref --verify --quiet refs/remotes/origin/main; then
    echo "main"
    return
  fi
  if git -C "$repo_dir" show-ref --verify --quiet refs/remotes/origin/master; then
    echo "master"
    return
  fi
  echo ""
}

pin_repo_by_date() {
  local repo_name="$1"
  local repo_dir="$2"
  local branch
  local ref
  branch="$(detect_origin_branch "$repo_dir")"
  if [[ -z "$branch" ]]; then
    echo "[Error] Cannot detect origin branch for $repo_name at $repo_dir" >&2
    exit 1
  fi

  ref="$(git -C "$repo_dir" rev-list -n 1 --before="$CF_DATE" "origin/$branch")"
  if [[ -z "$ref" ]]; then
    echo "[Error] Failed to compute historical ref for $repo_name before $CF_DATE" >&2
    exit 1
  fi

  git -C "$repo_dir" checkout -q "$ref"
  echo "[Pinned] $repo_name -> $(git -C "$repo_dir" show -s --format='%H %cI %s' HEAD)"
}

declare -A REPO_URLS=(
  ["jdk"]="https://github.com/typetools/jdk.git"
  ["annotation-tools"]="https://github.com/typetools/annotation-tools.git"
  ["stubparser"]="https://github.com/typetools/stubparser.git"
  ["jspecify"]="https://github.com/jspecify/jspecify.git"
)

for repo_name in "jdk" "annotation-tools" "stubparser" "jspecify"; do
  repo_dir="$RW_ROOT/$repo_name"
  clone_if_missing "${REPO_URLS[$repo_name]}" "$repo_dir"
  ensure_full_history "$repo_dir"
  pin_repo_by_date "$repo_name" "$repo_dir"
done

echo
echo "[OK] Historical sibling repos are prepared."
echo "[Next] Run:"
echo "  bash real_world_test/build_checker_framework_legacy.sh \"$CHECKER_DIR\""
