#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Merge multiple module-level soot_facts.json files into one facts file."
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path of merged soot_facts.json",
    )
    parser.add_argument(
        "--prefer-last",
        action="store_true",
        help="When duplicate function_uid appears, keep the later one instead of the first one.",
    )
    parser.add_argument(
        "inputs",
        nargs="+",
        help="Input module soot_facts.json files",
    )
    return parser.parse_args()


def iter_methods(payload: Dict[str, object], source_path: Path) -> Iterable[Tuple[str, Dict[str, object]]]:
    methods_obj = payload.get("methods", {})
    if isinstance(methods_obj, dict):
        for key, value in methods_obj.items():
            if isinstance(value, dict):
                uid = str(value.get("function_uid", key)).strip() or str(key).strip()
                yield uid, value
        return

    if isinstance(methods_obj, list):
        for index, value in enumerate(methods_obj):
            if not isinstance(value, dict):
                continue
            uid = str(value.get("function_uid", "")).strip()
            if uid == "":
                file_name = str(value.get("file", "")).strip()
                method_name = str(value.get("method_name", "")).strip()
                uid = f"__fallback__::{source_path.name}::{file_name}::{method_name}::{index}"
            yield uid, value
        return

    raise ValueError(f"'methods' in {source_path} must be dict or list")


def main() -> int:
    args = parse_args()
    output_path = Path(args.output).resolve()
    input_paths = [Path(item).resolve() for item in args.inputs]

    merged_methods: Dict[str, Dict[str, object]] = {}
    line_mode = "absolute"
    duplicates: List[Tuple[str, str, str]] = []
    method_count_by_file: List[Tuple[str, int]] = []

    for input_path in input_paths:
        if not input_path.is_file():
            raise FileNotFoundError(f"Input file does not exist: {input_path}")
        with input_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if str(payload.get("line_mode", "")).strip() != "":
            line_mode = str(payload["line_mode"])

        local_count = 0
        for uid, method_payload in iter_methods(payload, input_path):
            local_count += 1
            if uid in merged_methods:
                duplicates.append((uid, str(input_path), "replaced" if args.prefer_last else "kept-first"))
                if not args.prefer_last:
                    continue
            merged_methods[uid] = method_payload
        method_count_by_file.append((str(input_path), local_count))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    merged_payload = {
        "generator": "soot-bridge-merged",
        "generated_at": int(time.time() * 1000),
        "line_mode": line_mode,
        "methods": merged_methods,
    }
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(merged_payload, handle, ensure_ascii=False, indent=2)

    print(f"[Info] merged file written to: {output_path}")
    print(f"[Info] total input files: {len(input_paths)}")
    print(f"[Info] merged methods: {len(merged_methods)}")
    print(f"[Info] duplicate function_uid count: {len(duplicates)}")
    for file_name, local_count in method_count_by_file:
        print(f"[Info] {file_name}: {local_count} methods")

    if duplicates:
        preview = duplicates[:20]
        print("[Warn] duplicate preview:")
        for uid, source_name, action in preview:
            print(f"  - {uid} ({action}, source={source_name})")
        if len(duplicates) > len(preview):
            print(f"  ... and {len(duplicates) - len(preview)} more duplicates")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as err:  # pragma: no cover - CLI error path
        print(f"[Error] {err}", file=sys.stderr)
        raise
