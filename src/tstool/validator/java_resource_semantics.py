from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Tuple

RESOURCE_KIND_AUTOCLOSEABLE = "autocloseable"
RESOURCE_KIND_LOCK = "lock"
RESOURCE_KIND_EXECUTOR = "executor"
RESOURCE_KIND_TEMP_RESOURCE = "temp_resource"

KNOWN_RESOURCE_KINDS = {
    RESOURCE_KIND_AUTOCLOSEABLE,
    RESOURCE_KIND_LOCK,
    RESOURCE_KIND_EXECUTOR,
    RESOURCE_KIND_TEMP_RESOURCE,
}

RELEASE_CONTEXT_FINALLY = "finally"
RELEASE_CONTEXT_TWR = "twr"
RELEASE_CONTEXT_NORMAL = "normal"
RELEASE_CONTEXT_UNKNOWN = "unknown"

GUARANTEE_ALL_EXIT_PATHS = "all_exit_paths"
GUARANTEE_NORMAL_ONLY = "normal_only"
GUARANTEE_NONE = "none"


@dataclass(frozen=True)
class JavaResourceSemantics:
    kind: str
    acquire_ops: Tuple[str, ...]
    release_ops: Tuple[str, ...]
    strong_release_contexts: Tuple[str, ...] = (
        RELEASE_CONTEXT_FINALLY,
        RELEASE_CONTEXT_TWR,
    )


SEMANTICS_BY_KIND: Dict[str, JavaResourceSemantics] = {
    RESOURCE_KIND_AUTOCLOSEABLE: JavaResourceSemantics(
        kind=RESOURCE_KIND_AUTOCLOSEABLE,
        acquire_ops=(
            "new",
            "open",
            "openStream",
            "getInputStream",
            "getOutputStream",
            "getConnection",
            "executeQuery",
        ),
        release_ops=("close", "disconnect", "shutdown", "release", "abort"),
    ),
    RESOURCE_KIND_LOCK: JavaResourceSemantics(
        kind=RESOURCE_KIND_LOCK,
        acquire_ops=("lock", "tryLock", "lockInterruptibly", "acquire"),
        release_ops=("unlock", "tryUnlock", "release"),
    ),
    RESOURCE_KIND_EXECUTOR: JavaResourceSemantics(
        kind=RESOURCE_KIND_EXECUTOR,
        acquire_ops=(
            "newFixedThreadPool",
            "newCachedThreadPool",
            "newSingleThreadExecutor",
            "newSingleThreadScheduledExecutor",
            "newScheduledThreadPool",
            "newWorkStealingPool",
            "newVirtualThreadPerTaskExecutor",
            "newThreadPerTaskExecutor",
            "submit",
            "execute",
        ),
        release_ops=("shutdown", "shutdownNow", "close"),
    ),
    RESOURCE_KIND_TEMP_RESOURCE: JavaResourceSemantics(
        kind=RESOURCE_KIND_TEMP_RESOURCE,
        acquire_ops=("createTempFile", "createTempDirectory"),
        release_ops=("delete", "deleteIfExists", "deleteOnExit"),
    ),
}

_RESOURCE_KIND_MARKER_RE = re.compile(r"^__RESOURCE_KIND_([A-Z0-9_]+)__$")
_RELEASE_CONTEXT_MARKER_RE = re.compile(r"^__RELEASE_CONTEXT_([A-Z0-9_]+)__$")
_GUARANTEE_LEVEL_MARKER_RE = re.compile(r"^__GUARANTEE_LEVEL_([A-Z0-9_]+)__$")


def normalize_resource_kind(kind: str) -> str:
    normalized = kind.strip().lower()
    if normalized in KNOWN_RESOURCE_KINDS:
        return normalized
    return RESOURCE_KIND_AUTOCLOSEABLE


def normalize_release_context(raw_context: str) -> str:
    normalized = raw_context.strip().lower().replace("-", "_").replace(" ", "_")
    mapping = {
        "finally": RELEASE_CONTEXT_FINALLY,
        "try_finally": RELEASE_CONTEXT_FINALLY,
        "twr": RELEASE_CONTEXT_TWR,
        "try_with_resources": RELEASE_CONTEXT_TWR,
        "trywithresources": RELEASE_CONTEXT_TWR,
        "normal": RELEASE_CONTEXT_NORMAL,
        "normal_path": RELEASE_CONTEXT_NORMAL,
        "unknown": RELEASE_CONTEXT_UNKNOWN,
        "none": RELEASE_CONTEXT_UNKNOWN,
    }
    return mapping.get(normalized, RELEASE_CONTEXT_UNKNOWN)


def normalize_guarantee_level(raw_level: str) -> str:
    normalized = raw_level.strip().lower().replace("-", "_").replace(" ", "_")
    mapping = {
        "all_exit_paths": GUARANTEE_ALL_EXIT_PATHS,
        "all_paths": GUARANTEE_ALL_EXIT_PATHS,
        "all_exit_path": GUARANTEE_ALL_EXIT_PATHS,
        "normal_only": GUARANTEE_NORMAL_ONLY,
        "normal": GUARANTEE_NORMAL_ONLY,
        "normal_path_only": GUARANTEE_NORMAL_ONLY,
        "partial": GUARANTEE_NORMAL_ONLY,
        "none": GUARANTEE_NONE,
        "unknown": GUARANTEE_NONE,
    }
    return mapping.get(normalized, GUARANTEE_NONE)


def is_all_exit_guaranteed(guarantee_level: str) -> bool:
    return normalize_guarantee_level(guarantee_level) == GUARANTEE_ALL_EXIT_PATHS


def should_trigger_strict_recheck(
    release_context: str,
    guarantee_level: str,
) -> bool:
    normalized_context = normalize_release_context(release_context)
    normalized_guarantee = normalize_guarantee_level(guarantee_level)
    return (
        normalized_context not in {RELEASE_CONTEXT_FINALLY, RELEASE_CONTEXT_TWR}
        and normalized_guarantee != GUARANTEE_ALL_EXIT_PATHS
    )


def is_servlet_context(file_path: str) -> bool:
    lowered = file_path.lower()
    return "servlet_temp_file" in lowered or "servlet" in lowered


def classify_resource_kind(src_name: str, file_path: str = "") -> str:
    lowered = src_name.lower()
    lowered_no_space = lowered.replace(" ", "")

    if any(
        token in lowered_no_space
        for token in [
            ".lock(",
            ".trylock(",
            ".lockinterruptibly(",
            ".acquire(",
            ".acquireuninterruptibly(",
            "reentrantlock",
            "readwritelock",
            "stampedlock",
            "semaphore",
        ]
    ):
        return RESOURCE_KIND_LOCK

    if any(
        token in lowered_no_space
        for token in [
            "executor",
            "threadpool",
            "newfixedthreadpool(",
            "newcachedthreadpool(",
            "newsinglethreadexecutor(",
            "newsinglethreadscheduledexecutor(",
            "newscheduledthreadpool(",
            "newworkstealingpool(",
            "newvirtualthreadpertaskexecutor(",
            "newthreadpertaskexecutor(",
        ]
    ):
        return RESOURCE_KIND_EXECUTOR

    if any(
        token in lowered_no_space
        for token in [
            "createtempfile(",
            "createtempdirectory(",
        ]
    ):
        return RESOURCE_KIND_TEMP_RESOURCE

    if "temp_file" in file_path.lower():
        return RESOURCE_KIND_TEMP_RESOURCE

    return RESOURCE_KIND_AUTOCLOSEABLE


def build_intra_resource_rules(resource_kind: str, servlet_context: bool) -> List[str]:
    kind = normalize_resource_kind(resource_kind)
    if kind == RESOURCE_KIND_LOCK:
        return [
            "Resource kind is lock: focus on lock()/acquire() matched with unlock()/release().",
            "For lock resources, release in finally or try-with-resources style is strong guarantee.",
            "Unlock in normal flow only is weak when exceptions can bypass it.",
        ]
    if kind == RESOURCE_KIND_EXECUTOR:
        return [
            "Resource kind is executor: track task submission/execution and lifecycle shutdown.",
            "shutdown()/shutdownNow() must be guaranteed on all exits to be considered safe.",
        ]
    if kind == RESOURCE_KIND_TEMP_RESOURCE:
        rules = [
            "Resource kind is temp_resource: track createTempFile/createTempDirectory cleanup.",
            "delete()/deleteIfExists() are explicit cleanup operations.",
            "deleteOnExit() is delayed cleanup and should be treated with scenario-aware semantics.",
        ]
        if servlet_context:
            rules.append(
                "Servlet context detected: deleteOnExit() is weak and does not guarantee timely cleanup."
            )
        else:
            rules.append(
                "Non-servlet context: deleteOnExit() can be treated as acceptable cleanup for this benchmark profile."
            )
        return rules
    return [
        "Resource kind is autocloseable: track close/disconnect/shutdown/release lifecycle.",
        "Explicit release in finally or try-with-resources is strong guarantee.",
        "Release only in normal flow is weak when exceptions can bypass it.",
    ]


def build_path_resource_rules(resource_kind: str, servlet_context: bool) -> List[str]:
    kind = normalize_resource_kind(resource_kind)
    if kind == RESOURCE_KIND_LOCK:
        return [
            "For lock resources, unlock/release outside finally is not a full guarantee.",
            "Answer No only when unlock/release is guaranteed on all exits (finally/twr style).",
        ]
    if kind == RESOURCE_KIND_EXECUTOR:
        return [
            "For executor resources, shutdown lifecycle must hold on all exits.",
            "A shutdown on normal path only is insufficient when exceptions may skip it.",
        ]
    if kind == RESOURCE_KIND_TEMP_RESOURCE:
        rules = [
            "For temp resources, prefer delete/deleteIfExists as direct cleanup semantics.",
        ]
        if servlet_context:
            rules.append(
                "Servlet context: deleteOnExit should be treated as weak/insufficient cleanup."
            )
        else:
            rules.append(
                "Non-servlet context: deleteOnExit may be considered acceptable benchmark cleanup."
            )
        return rules
    return [
        "For autocloseable resources, explicit close in finally/twr is strong guarantee.",
        "If release can be skipped by exception, prefer Answer Yes.",
    ]


def encode_resource_kind_marker(resource_kind: str) -> str:
    normalized = normalize_resource_kind(resource_kind).upper()
    return f"__RESOURCE_KIND_{normalized}__"


def encode_release_context_marker(release_context: str) -> str:
    normalized = normalize_release_context(release_context).upper()
    return f"__RELEASE_CONTEXT_{normalized}__"


def encode_guarantee_level_marker(guarantee_level: str) -> str:
    normalized = normalize_guarantee_level(guarantee_level).upper()
    return f"__GUARANTEE_LEVEL_{normalized}__"


def decode_resource_kind_marker(marker_name: str) -> str:
    match = _RESOURCE_KIND_MARKER_RE.match(marker_name.strip())
    if match is None:
        return ""
    return normalize_resource_kind(match.group(1).lower())


def decode_release_context_marker(marker_name: str) -> str:
    match = _RELEASE_CONTEXT_MARKER_RE.match(marker_name.strip())
    if match is None:
        return ""
    return normalize_release_context(match.group(1).lower())


def decode_guarantee_level_marker(marker_name: str) -> str:
    match = _GUARANTEE_LEVEL_MARKER_RE.match(marker_name.strip())
    if match is None:
        return ""
    return normalize_guarantee_level(match.group(1).lower())
