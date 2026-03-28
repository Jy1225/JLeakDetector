#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence


BASE_DIR = Path(__file__).resolve().parent
REPO_ROOT = BASE_DIR.parent
SRC_DIR = REPO_ROOT / "src"
DEFAULT_CONFIG = BASE_DIR / "experiment_config.json"


@dataclass
class JulietConfig:
    enabled: bool
    dataset_root: Path
    java_home: Optional[Path]
    bug_type: str
    language: str
    repeat_count: int
    soot_strategy: str
    variants: List[Dict[str, object]]


def _expand_path(raw: str) -> Path:
    expanded = os.path.expandvars(os.path.expanduser(raw))
    return Path(expanded).resolve()


def _resolve_repo_path(raw: str) -> Path:
    expanded = os.path.expandvars(os.path.expanduser(raw))
    path = Path(expanded)
    if path.is_absolute():
        return path.resolve()
    return (REPO_ROOT / path).resolve()


def _load_config(config_path: Path) -> Dict[str, object]:
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


def _build_juliet_config(config: Dict[str, object]) -> JulietConfig:
    section = config.get("juliet")
    if not isinstance(section, dict):
        raise ValueError("Missing 'juliet' section in config")
    java_home_raw = str(section.get("java_home", "") or "").strip()
    java_home = _expand_path(java_home_raw) if java_home_raw != "" else None
    variants = section.get("variants", [])
    if not isinstance(variants, list) or len(variants) == 0:
        raise ValueError("juliet.variants must be a non-empty list")
    return JulietConfig(
        enabled=bool(section.get("enabled", False)),
        dataset_root=_resolve_repo_path(str(section.get("dataset_root", ""))),
        java_home=java_home,
        bug_type=str(section.get("bug_type", config.get("bug_type", "MLK"))),
        language=str(section.get("language", config.get("language", "Java"))),
        repeat_count=int(section.get("repeat_count", 1)),
        soot_strategy=str(section.get("soot_strategy", "ts-fallback")),
        variants=[v for v in variants if isinstance(v, dict)],
    )


def _timestamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S", time.localtime())


def _run_command(
    cmd: Sequence[str],
    *,
    cwd: Optional[Path] = None,
    env: Optional[Dict[str, str]] = None,
    log_file: Optional[Path] = None,
    dry_run: bool = False,
) -> subprocess.CompletedProcess[str]:
    pretty = " ".join(cmd)
    print(f"[CMD] {pretty}")
    if dry_run:
        return subprocess.CompletedProcess(cmd, 0, "", "")

    proc = subprocess.run(
        list(cmd),
        cwd=str(cwd) if cwd is not None else None,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"$ {pretty}\n")
            f.write(proc.stdout)
            if not proc.stdout.endswith("\n"):
                f.write("\n")
            f.write("\n")
    if proc.returncode != 0:
        raise RuntimeError(f"Command failed ({proc.returncode}): {pretty}\n{proc.stdout}")
    return proc


def _ensure_file(path: Path, label: str) -> None:
    if not path.exists():
        raise FileNotFoundError(f"{label} not found: {path}")


def _make_env(java_home: Optional[Path]) -> Dict[str, str]:
    env = dict(os.environ)
    if java_home is not None:
        env["JAVA_HOME"] = str(java_home)
        env["PATH"] = str(java_home / "bin") + os.pathsep + env.get("PATH", "")
    return env


def _write_json(path: Path, payload: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def _write_csv(path: Path, rows: List[Dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        return
    headers = list(rows[0].keys())
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)


def _result_root(model_name: str, bug_type: str, language: str, project_name: str) -> Path:
    return REPO_ROOT / "result" / "dfbscan" / model_name / bug_type / language / project_name


def _list_result_dirs(root: Path) -> List[Path]:
    if not root.exists():
        return []
    return [p.resolve() for p in root.iterdir() if p.is_dir()]


def _latest_new_result_dir(before: List[Path], after: List[Path]) -> Optional[Path]:
    before_set = {p.resolve() for p in before}
    new_dirs = [p for p in after if p.resolve() not in before_set]
    if new_dirs:
        return sorted(new_dirs, key=lambda p: p.name)[-1]
    if after:
        return sorted(after, key=lambda p: p.name)[-1]
    return None


def _generate_juliet_soot(
    config: Dict[str, object],
    juliet: JulietConfig,
    *,
    log_file: Path,
    dry_run: bool,
) -> Path:
    env = _make_env(juliet.java_home)
    output_path = juliet.dataset_root / ".repoaudit" / "soot_facts.json"

    if juliet.soot_strategy == "ts-fallback":
        cmd = [
            sys.executable,
            str(SRC_DIR / "tstool" / "validator" / "generate_java_soot_facts.py"),
            "--project-path",
            str(juliet.dataset_root),
            "--output",
            str(output_path),
            "--mode",
            "ts-fallback",
        ]
        _run_command(cmd, cwd=REPO_ROOT, env=env, log_file=log_file, dry_run=dry_run)
        return output_path

    class_dir = juliet.dataset_root / ".repoaudit_soot_classes"
    if not dry_run:
        _ensure_file(class_dir, "Juliet compiled class dir")
    cmd = [
        sys.executable,
        str(SRC_DIR / "tstool" / "validator" / "generate_java_soot_facts.py"),
        "--project-path",
        str(juliet.dataset_root),
        "--output",
        str(output_path),
        "--mode",
        "bridge",
        "--bridge-jar",
        str(_resolve_repo_path(str(config["soot_bridge_jar"]))),
        "--class-dir",
        str(class_dir),
        "--classpath",
        str(class_dir),
        "--java-bin",
        str((juliet.java_home / "bin" / "java") if juliet.java_home else "java"),
        "--javac-bin",
        str((juliet.java_home / "bin" / "javac") if juliet.java_home else "javac"),
        "--soot-timeout-sec",
        "600",
    ]
    _run_command(cmd, cwd=REPO_ROOT, env=env, log_file=log_file, dry_run=dry_run)
    return output_path


def _variant_env(
    config: Dict[str, object],
    juliet: JulietConfig,
    variant: Dict[str, object],
    soot_facts_path: Path,
) -> Dict[str, str]:
    env = _make_env(juliet.java_home)
    env["MODEL"] = str(config["model_name"])
    env["REPOAUDIT_TEMPERATURE"] = str(config["temperature"])
    env["REPOAUDIT_CALL_DEPTH"] = str(config["call_depth"])
    env["REPOAUDIT_MAX_NEURAL_WORKERS"] = str(config["max_neural_workers"])
    env["REPOAUDIT_LANGUAGE"] = juliet.language
    env["AUTO_GENERATE_REVIEW_XLSX"] = "false"
    env["AUTO_GENERATE_SOOT_FACTS"] = "false"
    env["REPOAUDIT_JAVA_MLK_ISSUE_FIRST"] = "true" if bool(variant.get("issue_first", True)) else "false"
    env["ENABLE_SOOT_PREFILTER"] = "true" if bool(variant.get("enable_soot", True)) else "false"
    if bool(variant.get("enable_soot", True)):
        env["SOOT_FACTS_PATH"] = str(soot_facts_path)
        env["SOOT_FACTS_MODE"] = "bridge" if juliet.soot_strategy == "bridge" else "ts-fallback"
    else:
        env.pop("SOOT_FACTS_PATH", None)
        env["SOOT_FACTS_MODE"] = "ts-fallback"
    return env


def run_juliet_experiments(config_path: Path, *, dry_run: bool = False, force: bool = False) -> Path:
    config = _load_config(config_path)
    juliet = _build_juliet_config(config)
    if not juliet.enabled and not force:
        raise RuntimeError("Juliet is disabled in config. Set juliet.enabled=true or pass --force.")

    if not dry_run:
        _ensure_file(_resolve_repo_path(str(config["run_repoaudit_script"])), "run_repoaudit.sh")
        _ensure_file(_resolve_repo_path(str(config["soot_bridge_jar"])), "soot bridge jar")
        _ensure_file(juliet.dataset_root, "Juliet dataset root")
        if juliet.java_home is not None:
            _ensure_file(juliet.java_home / "bin" / "java", "Juliet java binary")
            _ensure_file(juliet.java_home / "bin" / "javac", "Juliet javac binary")

    controller_run_id = f"{_timestamp()}_{config['model_name']}_juliet"
    ledger_dir = BASE_DIR / "juliet_runs" / controller_run_id
    ledger_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(config_path, ledger_dir / "config_snapshot.json")
    log_file = ledger_dir / "controller.log"

    rows: List[Dict[str, object]] = []

    print("\n=== Juliet Phase 1: generate soot facts ===")
    soot_started = time.time()
    soot_status = "success"
    soot_error = ""
    soot_facts_path: Optional[Path] = None
    try:
        soot_facts_path = _generate_juliet_soot(config, juliet, log_file=log_file, dry_run=dry_run)
        if not dry_run:
            _ensure_file(soot_facts_path, "Juliet soot facts")
    except Exception as err:
        soot_status = "failed"
        soot_error = str(err)
        if not dry_run:
            raise
    rows.append(
        {
            "controller_run_id": controller_run_id,
            "variant": "__soot_generation__",
            "repeat_index": 0,
            "enable_soot": True,
            "issue_first": True,
            "result_dir": "",
            "metrics_json": "",
            "status": soot_status,
            "error_message": soot_error,
            "elapsed_sec": round(time.time() - soot_started, 3),
            "dataset_root": str(juliet.dataset_root),
            "soot_facts_path": str(soot_facts_path) if soot_facts_path else "",
        }
    )
    _write_json(ledger_dir / "juliet_runs.json", {"runs": rows})
    _write_csv(ledger_dir / "juliet_runs.csv", rows)

    if soot_facts_path is None:
        raise RuntimeError("Juliet soot facts generation failed")

    print("\n=== Juliet Phase 2: run RepoAudit variants ===")
    for variant in juliet.variants:
        for repeat_index in range(1, juliet.repeat_count + 1):
            result_root = _result_root(str(config["model_name"]), juliet.bug_type, juliet.language, juliet.dataset_root.name)
            before = _list_result_dirs(result_root)
            env = _variant_env(config, juliet, variant, soot_facts_path)
            started_at = time.time()
            status = "success"
            error_message = ""
            result_dir = ""
            metrics_json = ""
            try:
                _run_command(
                    [
                        "bash",
                        str(_resolve_repo_path(str(config["run_repoaudit_script"]))),
                        str(juliet.dataset_root),
                        str(juliet.bug_type),
                    ],
                    cwd=SRC_DIR,
                    env=env,
                    log_file=log_file,
                    dry_run=dry_run,
                )
                after = _list_result_dirs(result_root)
                latest = _latest_new_result_dir(before, after)
                if latest is not None:
                    result_dir = str(latest)
                    metrics_json = str(latest / "run_metrics_raw.json")
            except Exception as err:
                status = "failed"
                error_message = str(err)

            rows.append(
                {
                    "controller_run_id": controller_run_id,
                    "variant": str(variant.get("name", "")),
                    "repeat_index": repeat_index,
                    "enable_soot": bool(variant.get("enable_soot", True)),
                    "issue_first": bool(variant.get("issue_first", True)),
                    "result_dir": result_dir,
                    "metrics_json": metrics_json,
                    "status": status,
                    "error_message": error_message,
                    "elapsed_sec": round(time.time() - started_at, 3),
                    "dataset_root": str(juliet.dataset_root),
                    "soot_facts_path": str(soot_facts_path),
                }
            )
            _write_json(ledger_dir / "juliet_runs.json", {"runs": rows})
            _write_csv(ledger_dir / "juliet_runs.csv", rows)

    print(f"[OK] Juliet experiment ledger written to: {ledger_dir}")
    return ledger_dir


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Juliet experiments.")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), help="Path to experiment_config.json")
    parser.add_argument("--dry-run", action="store_true", help="Print commands without executing")
    parser.add_argument("--force", action="store_true", help="Run even if juliet.enabled=false in config")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    run_juliet_experiments(_resolve_repo_path(args.config), dry_run=args.dry_run, force=args.force)


if __name__ == "__main__":
    main()
