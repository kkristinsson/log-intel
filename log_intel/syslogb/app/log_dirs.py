from __future__ import annotations

from pathlib import Path

from log_intel.syslogb.app import config
from log_intel.syslogb.app.local_log_dirs import is_local_log_subdir
from log_intel.syslogb.app.scanner import is_under_dir

LOCALHOST_GROUP_LABEL = "localhost"
LOCALHOST_GROUP_SUFFIX = "#localhost"


def log_dirs() -> list[Path]:
    return list(config.LOG_DIRS)


def display_name_for_dir(log_dir: Path) -> str:
    resolved = log_dir.resolve()
    dirs = log_dirs()
    if len(dirs) > 1:
        return str(resolved)
    return config.LOG_DIR_LABELS.get(resolved, resolved.name or str(resolved))


def localhost_group_path(root: Path) -> str:
    return f"{root.resolve()}{LOCALHOST_GROUP_SUFFIX}"


def is_localhost_group_scope(scope: str) -> bool:
    return scope.strip().endswith(LOCALHOST_GROUP_SUFFIX)


def group_path_key(group_dir: Path, label: str) -> str:
    if label == LOCALHOST_GROUP_LABEL:
        return localhost_group_path(group_dir)
    return str(group_dir.resolve())


def local_subdir_for_path(path: Path, root: Path | None = None) -> str:
    """First path segment under root for local facility dirs (e.g. apt, auth); else ""."""
    resolved = path.resolve()
    root_resolved = (root or root_for_path(resolved))
    if root_resolved is None:
        return ""
    try:
        rel = resolved.relative_to(root_resolved.resolve())
    except ValueError:
        return ""
    if len(rel.parts) >= 2 and is_local_log_subdir(rel.parts[0]):
        return rel.parts[0]
    return ""


def belongs_to_localhost_group(path: Path, root: Path | None = None) -> bool:
    """True for files at log root or under well-known local subdirs (apt, auth, …)."""
    resolved = path.resolve()
    root_resolved = (root or root_for_path(resolved))
    if root_resolved is None:
        return False
    try:
        rel = resolved.relative_to(root_resolved.resolve())
    except ValueError:
        return False
    if len(rel.parts) < 2:
        return True
    return is_local_log_subdir(rel.parts[0])


def group_for_path(path: Path, root: Path | None = None) -> tuple[Path, str] | None:
    """Group log files: local root + facility dirs → localhost; host dirs → subdir name."""
    if not config.LOG_RECURSIVE:
        return None
    resolved = path.resolve()
    root_resolved = (root or root_for_path(resolved))
    if root_resolved is None:
        return None
    try:
        rel = resolved.relative_to(root_resolved.resolve())
    except ValueError:
        return None
    if len(rel.parts) < 2:
        return root_resolved.resolve(), LOCALHOST_GROUP_LABEL
    first = rel.parts[0]
    if is_local_log_subdir(first):
        return root_resolved.resolve(), LOCALHOST_GROUP_LABEL
    group_dir = root_resolved / first
    return group_dir.resolve(), first


def list_log_groups() -> list[dict[str, str]]:
    """Distinct first-level host/subdirs under each LOG_DIRS root that contain log files."""
    if not config.LOG_RECURSIVE:
        return []
    from log_intel.syslogb.app.scanner import list_log_files

    seen: dict[str, dict[str, str]] = {}
    for root in log_dirs():
        root_resolved = root.resolve()
        for fp in list_log_files(root):
            grouped = group_for_path(fp, root_resolved)
            if not grouped:
                continue
            group_dir, label = grouped
            key = group_path_key(group_dir, label)
            if key not in seen:
                seen[key] = {
                    "path": key,
                    "label": label,
                    "log_dir": str(root_resolved),
                    "log_dir_label": display_name_for_dir(root_resolved),
                }
    return sorted(seen.values(), key=lambda g: g["label"].lower())


def log_dirs_info() -> list[dict[str, str]]:
    return [
        {"path": str(d), "label": display_name_for_dir(d)}
        for d in log_dirs()
    ]


def root_for_path(path: Path) -> Path | None:
    resolved = path.resolve()
    for root in log_dirs():
        if is_under_dir(resolved, root):
            return root.resolve()
    return None


def resolve_log_dir(user_path: str) -> Path:
    raw = user_path.strip()
    if is_localhost_group_scope(raw):
        raw = raw[: -len(LOCALHOST_GROUP_SUFFIX)]
    candidate = Path(raw).expanduser()
    resolved = candidate.resolve()
    if root_for_path(resolved) is None:
        roots = ", ".join(str(d) for d in log_dirs())
        raise PermissionError(f"Not a configured log directory ({roots}): {resolved}")
    if not resolved.is_dir():
        raise PermissionError(f"Not a directory: {resolved}")
    return resolved


def resolve_log_dir_scope(user_path: str) -> tuple[Path, bool]:
    """Resolve search scope; True second value = only files directly under log root."""
    localhost_only = is_localhost_group_scope(user_path)
    return resolve_log_dir(user_path), localhost_only


def file_matches_group(path: Path, group_path: str, root: Path | None = None) -> bool:
    """True if path belongs to the sidebar group identified by group_path."""
    if is_localhost_group_scope(group_path):
        root_resolved = (root or root_for_path(path))
        return belongs_to_localhost_group(path, root_resolved)
    grouped = group_for_path(path, root)
    if grouped is None:
        return False
    return group_path_key(grouped[0], grouped[1]) == group_path


def resolve_safe_path(user_path: str) -> Path:
    """Resolve path and ensure it stays under a configured log directory."""
    candidate = Path(user_path)
    if candidate.as_posix().startswith("journal://"):
        return candidate
    if not candidate.is_absolute():
        roots = log_dirs()
        if not roots:
            raise PermissionError("No log directories configured")
        candidate = roots[0] / candidate
    resolved = candidate.resolve()
    if root_for_path(resolved) is None:
        roots = ", ".join(str(d) for d in log_dirs())
        raise PermissionError(f"Path outside configured log directories ({roots}): {resolved}")
    return resolved
