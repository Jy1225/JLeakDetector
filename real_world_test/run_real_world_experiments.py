#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence


BASE_DIR = Path(__file__).resolve().parent
REPO_ROOT = BASE_DIR.parent
SRC_DIR = REPO_ROOT / "src"
DEFAULT_CONFIG = BASE_DIR / "experiment_config.json"


VARIANTS = [
    {
        "name": "baseline",
        "enable_soot": True,
        "issue_first": True,
        "description": "soot on + issue_first on",
    },
    {
        "name": "no_soot",
        "enable_soot": False,
        "issue_first": True,
        "description": "soot off + issue_first on",
    },
    {
        "name": "no_issue_first",
        "enable_soot": True,
        "issue_first": False,
        "description": "soot on + issue_first off",
    },
    {
        "name": "no_soot_no_issue_first",
        "enable_soot": False,
        "issue_first": False,
        "description": "soot off + issue_first off",
    },
]


@dataclass
class ProjectConfig:
    name: str
    path: Path
    java_home: Optional[Path]
    soot_strategy: str


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


def _build_project_configs(config: Dict[str, object]) -> List[ProjectConfig]:
    projects = []
    for item in config.get("projects", []):
        if not isinstance(item, dict):
            continue
        java_home_raw = str(item.get("java_home", "") or "").strip()
        java_home = _expand_path(java_home_raw) if java_home_raw != "" else None
        projects.append(
            ProjectConfig(
                name=str(item["name"]),
                path=_expand_path(str(item["path"])),
                java_home=java_home,
                soot_strategy=str(item["soot_strategy"]),
            )
        )
    return projects


def _validate_config(config: Dict[str, object], projects: Sequence[ProjectConfig]) -> None:
    required_keys = [
        "model_name",
        "temperature",
        "call_depth",
        "max_neural_workers",
        "bug_type",
        "language",
        "repeat_count",
        "run_repoaudit_script",
        "review_builder_script",
        "review_benchmark_xlsx",
        "soot_bridge_jar",
    ]
    for key in required_keys:
        if key not in config:
            raise KeyError(f"Missing config key: {key}")
    if len(projects) == 0:
        raise ValueError("No projects configured")


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


def _make_base_env(project: ProjectConfig) -> Dict[str, str]:
    env = dict(os.environ)
    if project.java_home is not None:
        env["JAVA_HOME"] = str(project.java_home)
        existing_path = env.get("PATH", "")
        env["PATH"] = str(project.java_home / "bin") + os.pathsep + existing_path
    return env


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


def _ensure_file(path: Path, label: str) -> None:
    if not path.exists():
        raise FileNotFoundError(f"{label} not found: {path}")


def _write_json(path: Path, payload: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def _append_ledger_csv(path: Path, rows: List[Dict[str, object]]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    headers = list(rows[0].keys())
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)


def _generate_triplea_soot(
    project: ProjectConfig,
    config: Dict[str, object],
    *,
    log_file: Path,
    dry_run: bool,
) -> Path:
    class_dir = project.path / "build" / "classes" / "java" / "main"
    if not dry_run:
        _ensure_file(class_dir, "TripleA class dir")

    init_gradle = tempfile.NamedTemporaryFile("w", delete=False, suffix=".gradle", encoding="utf-8")
    try:
        init_gradle.write(
            """
gradle.rootProject {
  afterEvaluate {
    tasks.create(name: "printMainCompileClasspath") {
      doLast {
        println sourceSets.main.compileClasspath.asPath
      }
    }
  }
}
"""
        )
        init_gradle.close()
        env = _make_base_env(project)
        proc = _run_command(
            ["./gradlew", "-q", "-I", init_gradle.name, "printMainCompileClasspath", "--no-daemon"],
            cwd=project.path,
            env=env,
            log_file=log_file,
            dry_run=dry_run,
        )
        cp_lines = [line.strip() for line in proc.stdout.splitlines() if line.strip() != ""]
        compile_cp = cp_lines[-1] if cp_lines else ""
        soot_output = project.path / ".repoaudit" / "soot_facts.json"
        cmd = [
            sys.executable,
            str(SRC_DIR / "tstool" / "validator" / "generate_java_soot_facts.py"),
            "--project-path",
            str(project.path),
            "--output",
            str(soot_output),
            "--mode",
            "bridge",
            "--bridge-jar",
            str(_resolve_repo_path(str(config["soot_bridge_jar"]))),
            "--class-dir",
            str(class_dir),
            "--classpath",
            f"{compile_cp}:{class_dir}" if compile_cp else str(class_dir),
            "--java-bin",
            env.get("JAVA_HOME", "") + "/bin/java" if env.get("JAVA_HOME") else "java",
            "--javac-bin",
            env.get("JAVA_HOME", "") + "/bin/javac" if env.get("JAVA_HOME") else "javac",
            "--soot-timeout-sec",
            "600",
        ]
        _run_command(cmd, cwd=REPO_ROOT, env=env, log_file=log_file, dry_run=dry_run)
        return soot_output
    finally:
        try:
            os.unlink(init_gradle.name)
        except OSError:
            pass


def _generate_corenlp_soot(
    project: ProjectConfig,
    config: Dict[str, object],
    *,
    log_file: Path,
    dry_run: bool,
) -> Path:
    env = _make_base_env(project)
    class_dir = project.path / "target" / "classes"
    if not dry_run:
        _ensure_file(class_dir, "CoreNLP class dir")
    cp_file = tempfile.NamedTemporaryFile("w", delete=False, suffix=".cp", encoding="utf-8")
    cp_file.close()
    try:
        _run_command(
            [
                "mvn",
                "-q",
                "-DskipTests",
                "dependency:build-classpath",
                f"-Dmdep.outputFile={cp_file.name}",
            ],
            cwd=project.path,
            env=env,
            log_file=log_file,
            dry_run=dry_run,
        )
        compile_cp = ""
        if not dry_run and Path(cp_file.name).exists():
            compile_cp = Path(cp_file.name).read_text(encoding="utf-8").strip().replace("\r", "")
        soot_output = project.path / ".repoaudit" / "soot_facts.json"
        cmd = [
            sys.executable,
            str(SRC_DIR / "tstool" / "validator" / "generate_java_soot_facts.py"),
            "--project-path",
            str(project.path),
            "--output",
            str(soot_output),
            "--mode",
            "bridge",
            "--bridge-jar",
            str(_resolve_repo_path(str(config["soot_bridge_jar"]))),
            "--class-dir",
            str(class_dir),
            "--classpath",
            f"{compile_cp}:{class_dir}" if compile_cp else str(class_dir),
            "--java-bin",
            env.get("JAVA_HOME", "") + "/bin/java" if env.get("JAVA_HOME") else "java",
            "--javac-bin",
            env.get("JAVA_HOME", "") + "/bin/javac" if env.get("JAVA_HOME") else "javac",
            "--soot-timeout-sec",
            "600",
        ]
        _run_command(cmd, cwd=REPO_ROOT, env=env, log_file=log_file, dry_run=dry_run)
        return soot_output
    finally:
        try:
            os.unlink(cp_file.name)
        except OSError:
            pass


def _generate_project_soot(
    project: ProjectConfig,
    config: Dict[str, object],
    *,
    log_file: Path,
    dry_run: bool,
) -> Path:
    env = _make_base_env(project)
    strategy = project.soot_strategy
    if strategy == "lucene_merge":
        _run_command(
            ["bash", str(BASE_DIR / "generate_merge_soot_lucene.sh"), str(project.path)],
            cwd=REPO_ROOT,
            env=env,
            log_file=log_file,
            dry_run=dry_run,
        )
        return project.path / ".repoaudit" / "soot_facts_merged.json"
    if strategy == "vaadin_merge":
        _run_command(
            ["bash", str(BASE_DIR / "generate_merge_soot_vaadin.sh"), str(project.path)],
            cwd=REPO_ROOT,
            env=env,
            log_file=log_file,
            dry_run=dry_run,
        )
        return project.path / ".repoaudit" / "soot_facts_merged.json"
    if strategy == "fitnesse_bridge":
        _run_command(
            ["bash", str(BASE_DIR / "generate_soot_fitnesse.sh"), str(project.path)],
            cwd=REPO_ROOT,
            env=env,
            log_file=log_file,
            dry_run=dry_run,
        )
        return project.path / ".repoaudit" / "soot_facts.json"
    if strategy == "triplea_bridge":
        return _generate_triplea_soot(project, config, log_file=log_file, dry_run=dry_run)
    if strategy == "corenlp_bridge":
        return _generate_corenlp_soot(project, config, log_file=log_file, dry_run=dry_run)
    raise ValueError(f"Unsupported soot_strategy: {strategy}")


def _variant_env(
    config: Dict[str, object],
    project: ProjectConfig,
    variant: Dict[str, object],
    soot_facts_path: Path,
) -> Dict[str, str]:
    env = _make_base_env(project)
    env["MODEL"] = str(config["model_name"])
    env["REPOAUDIT_TEMPERATURE"] = str(config["temperature"])
    env["REPOAUDIT_CALL_DEPTH"] = str(config["call_depth"])
    env["REPOAUDIT_MAX_NEURAL_WORKERS"] = str(config["max_neural_workers"])
    env["REPOAUDIT_LANGUAGE"] = str(config["language"])
    env["AUTO_GENERATE_REVIEW_XLSX"] = "true"
    env["AUTO_GENERATE_SOOT_FACTS"] = "false"
    env["REVIEW_BUILDER_SCRIPT"] = str(_resolve_repo_path(str(config["review_builder_script"])))
    env["REVIEW_BENCHMARK_XLSX"] = str(_resolve_repo_path(str(config["review_benchmark_xlsx"])))
    env["REPOAUDIT_JAVA_MLK_ISSUE_FIRST"] = "true" if variant["issue_first"] else "false"
    env["ENABLE_SOOT_PREFILTER"] = "true" if variant["enable_soot"] else "false"
    if variant["enable_soot"]:
        env["SOOT_FACTS_PATH"] = str(soot_facts_path)
        env["SOOT_FACTS_MODE"] = "bridge"
    else:
        env.pop("SOOT_FACTS_PATH", None)
        env["SOOT_FACTS_MODE"] = "ts-fallback"
    return env


def _ensure_review_excel(result_dir: Path, config: Dict[str, object], dry_run: bool, log_file: Path) -> None:
    review_xlsx = result_dir / "review_units.xlsx"
    metrics_json = result_dir / "run_metrics_raw.json"
    if review_xlsx.exists() and metrics_json.exists():
        return
    env = dict(os.environ)
    _run_command(
        [
            sys.executable,
            str(_resolve_repo_path(str(config["review_builder_script"]))),
            "--result-dir",
            str(result_dir),
            "--benchmark-xlsx",
            str(_resolve_repo_path(str(config["review_benchmark_xlsx"]))),
        ],
        cwd=REPO_ROOT,
        env=env,
        log_file=log_file,
        dry_run=dry_run,
    )


def _write_run_meta(result_dir: Path, payload: Dict[str, object]) -> None:
    _write_json(result_dir / "experiment_run_meta.json", payload)


def _execute_one_run(
    config: Dict[str, object],
    project: ProjectConfig,
    variant: Dict[str, object],
    repeat_index: int,
    soot_facts_path: Path,
    *,
    dry_run: bool,
    log_file: Path,
    controller_run_id: str,
) -> Dict[str, object]:
    result_root = _result_root(
        model_name=str(config["model_name"]),
        bug_type=str(config["bug_type"]),
        language=str(config["language"]),
        project_name=project.path.name,
    )
    before = _list_result_dirs(result_root)
    env = _variant_env(config, project, variant, soot_facts_path)

    started_at = time.time()
    status = "success"
    error_message = ""
    result_dir: Optional[Path] = None

    try:
        _run_command(
            ["bash", str(_resolve_repo_path(str(config["run_repoaudit_script"]))), str(project.path), str(config["bug_type"])],
            cwd=SRC_DIR,
            env=env,
            log_file=log_file,
            dry_run=dry_run,
        )
        after = _list_result_dirs(result_root)
        result_dir = _latest_new_result_dir(before, after)
        if result_dir is None and not dry_run:
            raise RuntimeError(f"Failed to locate result dir under {result_root}")
        if result_dir is not None and not dry_run:
            _ensure_review_excel(result_dir, config, dry_run=dry_run, log_file=log_file)
            _ensure_file(result_dir / "review_units.xlsx", "review workbook")
            _ensure_file(result_dir / "run_metrics_raw.json", "run metrics")
            _write_run_meta(
                result_dir,
                {
                    "controller_run_id": controller_run_id,
                    "project_name": project.name,
                    "project_path": str(project.path),
                    "variant": variant["name"],
                    "variant_description": variant["description"],
                    "repeat_index": repeat_index,
                    "model_name": config["model_name"],
                    "temperature": config["temperature"],
                    "call_depth": config["call_depth"],
                    "max_neural_workers": config["max_neural_workers"],
                    "enable_soot": variant["enable_soot"],
                    "issue_first": variant["issue_first"],
                    "soot_facts_path": str(soot_facts_path) if variant["enable_soot"] else "",
                    "generated_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                },
            )
    except Exception as err:
        status = "failed"
        error_message = str(err)

    ended_at = time.time()
    return {
        "controller_run_id": controller_run_id,
        "project_name": project.name,
        "project_path": str(project.path),
        "variant": variant["name"],
        "variant_description": variant["description"],
        "repeat_index": repeat_index,
        "model_name": config["model_name"],
        "temperature": config["temperature"],
        "call_depth": config["call_depth"],
        "max_neural_workers": config["max_neural_workers"],
        "enable_soot": variant["enable_soot"],
        "issue_first": variant["issue_first"],
        "soot_facts_path": str(soot_facts_path) if variant["enable_soot"] else "",
        "result_dir": str(result_dir) if result_dir is not None else "",
        "review_excel": str(result_dir / "review_units.xlsx") if result_dir is not None else "",
        "metrics_json": str(result_dir / "run_metrics_raw.json") if result_dir is not None else "",
        "status": status,
        "error_message": error_message,
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(started_at)),
        "ended_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ended_at)),
        "elapsed_sec": round(ended_at - started_at, 3),
    }


def run_experiments(config_path: Path, *, dry_run: bool = False) -> Path:
    config = _load_config(config_path)
    projects = _build_project_configs(config)
    _validate_config(config, projects)
    if not dry_run:
        _ensure_file(_resolve_repo_path(str(config["run_repoaudit_script"])), "run_repoaudit.sh")
        _ensure_file(_resolve_repo_path(str(config["review_builder_script"])), "review builder script")
        _ensure_file(_resolve_repo_path(str(config["review_benchmark_xlsx"])), "review benchmark xlsx")
        _ensure_file(_resolve_repo_path(str(config["soot_bridge_jar"])), "soot bridge jar")
        for project in projects:
            _ensure_file(project.path, f"project path for {project.name}")
            if project.java_home is not None:
                _ensure_file(project.java_home / "bin" / "java", f"java binary for {project.name}")
                _ensure_file(project.java_home / "bin" / "javac", f"javac binary for {project.name}")
    controller_run_id = f"{_timestamp()}_{config['model_name']}"
    ledger_dir = BASE_DIR / "experiment_runs" / controller_run_id
    ledger_dir.mkdir(parents=True, exist_ok=True)
    log_file = ledger_dir / "controller.log"
    config_snapshot = ledger_dir / "config_snapshot.json"
    shutil.copyfile(config_path, config_snapshot)

    ledger_rows: List[Dict[str, object]] = []

    for project in projects:
        print(f"\n=== Project: {project.name} ===")
        project_log = ledger_dir / f"{project.name}.log"
        soot_started = time.time()
        soot_status = "success"
        soot_error = ""
        soot_facts_path: Optional[Path] = None
        try:
            soot_facts_path = _generate_project_soot(
                project,
                config,
                log_file=project_log,
                dry_run=dry_run,
            )
            if not dry_run:
                _ensure_file(soot_facts_path, "soot facts")
        except Exception as err:
            soot_status = "failed"
            soot_error = str(err)
            if not dry_run:
                print(f"[Error] soot generation failed for {project.name}: {err}")
                raise
        soot_elapsed = round(time.time() - soot_started, 3)

        ledger_rows.append(
            {
                "controller_run_id": controller_run_id,
                "project_name": project.name,
                "project_path": str(project.path),
                "variant": "__soot_generation__",
                "variant_description": project.soot_strategy,
                "repeat_index": 0,
                "model_name": config["model_name"],
                "temperature": config["temperature"],
                "call_depth": config["call_depth"],
                "max_neural_workers": config["max_neural_workers"],
                "enable_soot": True,
                "issue_first": True,
                "soot_facts_path": str(soot_facts_path) if soot_facts_path is not None else "",
                "result_dir": "",
                "review_excel": "",
                "metrics_json": "",
                "status": soot_status,
                "error_message": soot_error,
                "started_at": "",
                "ended_at": "",
                "elapsed_sec": soot_elapsed,
            }
        )

        if soot_facts_path is None:
            raise RuntimeError(f"Soot facts path missing for project {project.name}")

        for variant in VARIANTS:
            for repeat_index in range(1, int(config["repeat_count"]) + 1):
                print(
                    f"\n--- Run project={project.name} variant={variant['name']} repeat={repeat_index} ---"
                )
                row = _execute_one_run(
                    config,
                    project,
                    variant,
                    repeat_index,
                    soot_facts_path,
                    dry_run=dry_run,
                    log_file=project_log,
                    controller_run_id=controller_run_id,
                )
                ledger_rows.append(row)
                _write_json(ledger_dir / "experiment_runs.json", {"runs": ledger_rows})
                _append_ledger_csv(ledger_dir / "experiment_runs.csv", ledger_rows)
                if row["status"] != "success" and not dry_run:
                    print(f"[Warn] run failed: {row['error_message']}")

    _write_json(ledger_dir / "experiment_runs.json", {"runs": ledger_rows})
    _append_ledger_csv(ledger_dir / "experiment_runs.csv", ledger_rows)
    return ledger_dir


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run real-world RepoAudit experiments automatically."
    )
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG),
        help="Path to experiment_config.json",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print commands only without executing them",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config_path = _expand_path(args.config)
    ledger_dir = run_experiments(config_path, dry_run=args.dry_run)
    print(f"[OK] experiment ledger written to: {ledger_dir}")


if __name__ == "__main__":
    main()
