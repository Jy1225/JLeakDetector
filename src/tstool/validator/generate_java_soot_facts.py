from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Set


ROOT_PATH = Path(__file__).resolve().parents[2]
if str(ROOT_PATH) not in sys.path:
    sys.path.append(str(ROOT_PATH))

from memory.syntactic.function import Function
from tstool.analyzer.Java_TS_analyzer import Java_TSAnalyzer
from tstool.dfbscan_extractor.Java.Java_MLK_extractor import Java_MLK_Extractor


def _collect_java_sources(project_path: str) -> Dict[str, str]:
    code_in_files: Dict[str, str] = {}
    for root, _dirs, files in os.walk(project_path):
        for file_name in files:
            if not file_name.endswith(".java"):
                continue
            file_path = os.path.join(root, file_name)
            with open(file_path, "r", encoding="utf-8", errors="ignore") as source_file:
                code_in_files[file_path] = source_file.read()
    return code_in_files


def _safe_rel_line(function: Function, file_line: int) -> int:
    rel = function.file_line2function_line(file_line)
    return rel if rel > 0 else -1


def _build_ts_fallback_facts(project_path: str) -> Dict[str, object]:
    code_in_files = _collect_java_sources(project_path)
    try:
        analyzer = Java_TSAnalyzer(code_in_files, "Java", max_symbolic_workers_num=8)
        extractor = Java_MLK_Extractor(analyzer)
    except Exception as err:
        fallback_payload = _build_regex_fallback_facts(code_in_files)
        fallback_payload["warning"] = f"ts-fallback failed, use regex-fallback: {err}"
        return fallback_payload

    methods: Dict[str, Dict[str, object]] = {}
    for function in analyzer.function_env.values():
        function_uid = function.function_uid
        if function_uid == "":
            continue

        if_nodes = []
        for (if_start, _if_end), if_info in function.if_statements.items():
            (_, _, condition_str, true_scope, else_scope) = if_info
            true_scope_rel = [
                _safe_rel_line(function, true_scope[0]),
                _safe_rel_line(function, true_scope[1]),
            ]
            false_scope_rel = [
                _safe_rel_line(function, else_scope[0]),
                _safe_rel_line(function, else_scope[1]),
            ]
            if_nodes.append(
                {
                    "line": _safe_rel_line(function, if_start),
                    "condition": condition_str.strip(),
                    "true_scope": true_scope_rel,
                    "false_scope": false_scope_rel,
                    "true_unreachable": False,
                    "false_unreachable": False,
                }
            )

        source_lines: Set[int] = set()
        sink_lines: Set[int] = set()
        for source in extractor.extract_sources(function):
            source_lines.add(_safe_rel_line(function, source.line_number))
        for sink in extractor.extract_sinks(function):
            sink_lines.add(_safe_rel_line(function, sink.line_number))

        close_sites = [{"line": line} for line in sorted(line for line in sink_lines if line > 0)]
        methods[function_uid] = {
            "function_uid": function_uid,
            "file": function.file_path.replace("\\", "/"),
            "method_name": function.function_name,
            "if_nodes": if_nodes,
            "close_sites": close_sites,
            "must_close_source_lines": [],
            "source_lines": sorted(line for line in source_lines if line > 0),
            "generator": "ts-fallback",
        }

    return {
        "generator": "ts-fallback",
        "generated_at": int(time.time()),
        "methods": methods,
    }


def _normalize_param_types(raw_params: str) -> List[str]:
    params = []
    for item in raw_params.split(","):
        token = item.strip()
        if token == "":
            continue
        parts = token.split()
        if len(parts) == 0:
            continue
        params.append(parts[0])
    return params


def _build_regex_fallback_facts(code_in_files: Dict[str, str]) -> Dict[str, object]:
    method_re = re.compile(
        r"^\s*(?:public|protected|private|static|final|native|synchronized|abstract|\s)+"
        r"[\w<>\[\].]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*(?:throws[^{]+)?\{"
    )
    if_re = re.compile(r"\bif\s*\((.*)\)")
    package_re = re.compile(r"^\s*package\s+([A-Za-z0-9_\.]+)\s*;")
    class_re = re.compile(r"\bclass\s+([A-Za-z_][A-Za-z0-9_]*)")

    resource_hint_re = re.compile(
        r"\b(new\s+\w*(?:Stream|Reader|Writer|Socket|Channel|Connection|Statement|ResultSet|"
        r"Lock|Semaphore|Executor|ThreadPool|WatchService|Selector)\b|"
        r"getConnection\s*\(|prepareStatement\s*\(|executeQuery\s*\(|"
        r"createTempFile\s*\(|createTempDirectory\s*\(|"
        r"new(?:Fixed|Cached|SingleThread|Scheduled|WorkStealing)\w*Pool\s*\(|"
        r"newVirtualThreadPerTaskExecutor\s*\(|newThreadPerTaskExecutor\s*\(|"
        r"\.(?:lock|tryLock|acquire)\s*\()"
    )
    close_hint_re = re.compile(
        r"\.(?:close|disconnect|shutdown|shutdownNow|unlock|release|delete|deleteIfExists|deleteOnExit)\s*\("
    )

    methods: Dict[str, Dict[str, object]] = {}
    for file_path, source in code_in_files.items():
        lines = source.splitlines()
        package_name = ""
        owner_class = ""
        for line in lines:
            package_match = package_re.match(line)
            if package_match is not None:
                package_name = package_match.group(1).strip()
                continue
            class_match = class_re.search(line)
            if class_match is not None:
                owner_class = class_match.group(1).strip()
                break

        line_index = 0
        while line_index < len(lines):
            line = lines[line_index]
            method_match = method_re.match(line)
            if method_match is None:
                line_index += 1
                continue

            method_name = method_match.group(1).strip()
            params = _normalize_param_types(method_match.group(2))
            owner_name = owner_class
            if package_name != "" and owner_name != "":
                owner_name = f"{package_name}.{owner_name}"
            elif package_name != "":
                owner_name = package_name
            params_str = ",".join(params)
            if owner_name != "":
                function_uid = f"{owner_name}.{method_name}({params_str})"
            else:
                function_uid = f"{method_name}({params_str})"

            start_line = line_index + 1
            brace_depth = line.count("{") - line.count("}")
            cursor = line_index + 1
            if_nodes = []
            source_lines: Set[int] = set()
            close_lines: Set[int] = set()

            while cursor < len(lines) and brace_depth > 0:
                cur_line = lines[cursor]
                brace_depth += cur_line.count("{") - cur_line.count("}")
                relative_line = cursor - line_index + 1

                if_match = if_re.search(cur_line)
                if if_match is not None:
                    if_nodes.append(
                        {
                            "line": relative_line,
                            "condition": if_match.group(1).strip(),
                            "true_scope": [relative_line + 1, relative_line + 1],
                            "false_scope": [0, 0],
                            "true_unreachable": False,
                            "false_unreachable": False,
                        }
                    )
                if resource_hint_re.search(cur_line) is not None:
                    source_lines.add(relative_line)
                if close_hint_re.search(cur_line) is not None:
                    close_lines.add(relative_line)
                cursor += 1

            methods[function_uid] = {
                "function_uid": function_uid,
                "file": file_path.replace("\\", "/"),
                "method_name": method_name,
                "if_nodes": if_nodes,
                "close_sites": [{"line": line_no} for line_no in sorted(close_lines)],
                "must_close_source_lines": [],
                "source_lines": sorted(source_lines),
                "generator": "regex-fallback",
                "start_line": start_line,
            }
            line_index = max(cursor, line_index + 1)

    return {
        "generator": "regex-fallback",
        "generated_at": int(time.time()),
        "methods": methods,
    }


def _compile_java_sources(
    project_path: str,
    class_dir: str,
    javac_bin: str,
    classpath: str,
) -> None:
    code_in_files = _collect_java_sources(project_path)
    if len(code_in_files) == 0:
        raise RuntimeError(f"no java files found under {project_path}")
    os.makedirs(class_dir, exist_ok=True)

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".list", encoding="utf-8") as temp_list:
        list_path = temp_list.name
        for file_path in code_in_files.keys():
            temp_list.write(file_path + "\n")

    cmd = [javac_bin, "-g", "-encoding", "UTF-8", "-d", class_dir]
    if classpath != "":
        cmd.extend(["-cp", classpath])
    cmd.append(f"@{list_path}")

    try:
        proc = subprocess.run(
            cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
    finally:
        try:
            os.remove(list_path)
        except OSError:
            pass

    if proc.returncode != 0:
        raise RuntimeError(f"javac failed with exit code {proc.returncode}\n{proc.stdout}")


def _run_soot_bridge(
    java_bin: str,
    bridge_jar: str,
    bridge_main_class: str,
    class_dir: str,
    classpath: str,
    output_path: str,
    timeout_sec: int,
) -> None:
    if bridge_jar == "":
        raise RuntimeError("bridge mode requires --bridge-jar")
    if not os.path.exists(bridge_jar):
        raise RuntimeError(f"bridge jar does not exist: {bridge_jar}")

    analysis_classpath = classpath if classpath != "" else class_dir
    run_cp = bridge_jar
    if classpath != "":
        run_cp = bridge_jar + os.pathsep + classpath

    cmd = [
        java_bin,
        "-Xmx4g",
        "-cp",
        run_cp,
        bridge_main_class,
        "--input-dir",
        class_dir,
        "--classpath",
        analysis_classpath,
        "--output",
        output_path,
    ]
    proc = subprocess.run(
        cmd,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout_sec,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"soot bridge failed with exit code {proc.returncode}\n{proc.stdout}"
        )
    if not os.path.exists(output_path):
        raise RuntimeError(
            "soot bridge finished successfully but no output file was generated"
        )


def _write_json(output_path: str, payload: Dict[str, object]) -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as output_file:
        json.dump(payload, output_file, indent=4)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate soot_facts.json for RepoAudit")
    parser.add_argument("--project-path", required=True, help="Java project source path")
    parser.add_argument("--output", required=True, help="Output path for soot_facts.json")
    parser.add_argument(
        "--mode",
        choices=["auto", "bridge", "ts-fallback"],
        default="auto",
        help="Generation mode",
    )
    parser.add_argument(
        "--bridge-jar",
        default="",
        help="Path to soot bridge runnable jar",
    )
    parser.add_argument(
        "--bridge-main-class",
        default="repoaudit.soot.BridgeMain",
        help="Main class inside soot bridge jar",
    )
    parser.add_argument(
        "--class-dir",
        default="",
        help="Compiled class output directory for bridge mode",
    )
    parser.add_argument(
        "--compile-before",
        action="store_true",
        help="Compile project sources before running bridge mode",
    )
    parser.add_argument(
        "--classpath",
        default="",
        help="Extra classpath for javac/soot bridge",
    )
    parser.add_argument("--java-bin", default="java", help="Java executable path")
    parser.add_argument("--javac-bin", default="javac", help="Javac executable path")
    parser.add_argument(
        "--soot-timeout-sec",
        type=int,
        default=300,
        help="Timeout for soot bridge execution in seconds",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_path = os.path.abspath(args.output)
    project_path = os.path.abspath(args.project_path)
    class_dir = args.class_dir
    if class_dir == "":
        class_dir = os.path.join(project_path, ".repoaudit_soot_classes")
    class_dir = os.path.abspath(class_dir)

    mode = args.mode
    if mode == "auto":
        if args.bridge_jar != "":
            mode = "bridge"
        else:
            mode = "ts-fallback"

    if mode == "bridge":
        if args.compile_before:
            _compile_java_sources(
                project_path=project_path,
                class_dir=class_dir,
                javac_bin=args.javac_bin,
                classpath=args.classpath,
            )
        _run_soot_bridge(
            java_bin=args.java_bin,
            bridge_jar=args.bridge_jar,
            bridge_main_class=args.bridge_main_class,
            class_dir=class_dir,
            classpath=args.classpath,
            output_path=output_path,
            timeout_sec=args.soot_timeout_sec,
        )
        return

    payload = _build_ts_fallback_facts(project_path)
    _write_json(output_path, payload)


if __name__ == "__main__":
    main()
