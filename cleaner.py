"""执行清理：白名单校验、跳过占用文件、统计释放空间。"""
import ctypes
import os
import stat
import subprocess
import time

import safepath
import scanner
from utils import (fmt_size, is_runtime_path, is_within, norm_path,
                   remove_empty_dirs, schedule_delete, walk_files)


class CleanResult:
    def __init__(self, cat):
        self.key = cat.key
        self.name = cat.name
        self.freed = 0
        self.deleted = 0
        self.skipped = 0
        self.pending = 0
        self.pending_size = 0
        self.errors = []
        self.message = ""


def _decode(data: bytes) -> str:
    for encoding in ("utf-8", "mbcs", "gbk"):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", "replace")


def clean_category(cat, log=lambda message: None):
    result = CleanResult(cat)
    if cat.kind == "recyclebin":
        return _empty_recycle_bin(cat, result, log)
    if cat.kind == "eventlogs":
        return _clear_event_logs(cat, result, log)
    if cat.kind == "searchindex":
        return _reset_search_index(cat, result, log)
    if cat.kind == "command":
        return _run_command(cat, result, log)
    return _clean_files(cat, result, log)


def _clean_files(cat, result, log):
    allowed = [norm_path(path) for path in cat.paths]
    untrusted = bool(getattr(cat, "untrusted", False))

    for root in cat.paths:
        if safepath.is_reparse_point(root) or os.path.islink(root):
            result.skipped += 1
            continue
        if not os.path.lexists(root):
            continue
        if os.path.isfile(root):
            _delete_file(root, allowed, cat.patterns, result, untrusted)
            continue
        for entry in walk_files(root):
            _delete_file(entry.path, allowed, cat.patterns, result, untrusted)
        if cat.prune_dirs:
            removed = remove_empty_dirs(root)
            if removed:
                log(f"    移除空目录 {removed} 个")

    if result.errors:
        for message in result.errors[:5]:
            log(f"    {message}")
    return result


def _delete_file(path, allowed, patterns, result, untrusted=False):
    if is_runtime_path(path):
        return
    if safepath.execution_forbidden(path, untrusted=untrusted):
        result.skipped += 1
        return
    if safepath.is_password_store(path):
        result.skipped += 1
        return
    if not scanner.match_name(os.path.basename(path), patterns):
        return
    if not is_within(path, allowed):
        result.skipped += 1
        return
    # 删除前再看一次，避免遍历之后目录被换成链接。
    if safepath.is_reparse_point(path) or os.path.islink(path):
        result.skipped += 1
        return
    parent = os.path.dirname(path)
    while parent and parent not in (os.path.dirname(parent),):
        if safepath.is_reparse_point(parent) or os.path.islink(parent):
            result.skipped += 1
            return
        if any(is_within(parent, [root]) or norm_path(parent) == norm_path(root) for root in allowed):
            break
        parent = os.path.dirname(parent)

    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0

    try:
        if safepath.execution_forbidden(path, untrusted=untrusted):
            result.skipped += 1
            return
        safepath.unlink_regular(path, allowed)
    except safepath.UnsafeUnlinkError as exc:
        # Never schedule a path whose directory entry changed during deletion.
        result.skipped += 1
        result.errors.append(str(exc))
        return
    except PermissionError:
        try:
            os.chmod(path, stat.S_IWRITE)
            safepath.unlink_regular(path, allowed)
        except safepath.UnsafeUnlinkError as exc:
            result.skipped += 1
            result.errors.append(str(exc))
            return
        except OSError:
            _mark_pending(path, size, result)
            return
    except OSError:
        _mark_pending(path, size, result)
        return

    result.deleted += 1
    result.freed += size


def _mark_pending(path, size, result):
    """删不掉的文件登记到重启后删除。"""
    if schedule_delete(path):
        result.pending += 1
        result.pending_size += size
    else:
        result.skipped += 1


def _dir_size(path):
    total = 0
    for entry in walk_files(path):
        try:
            total += entry.stat(follow_symlinks=False).st_size
        except OSError:
            pass
    return total


def _service_running(name):
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             f"(Get-Service -Name '{name}' -ErrorAction SilentlyContinue).Status"],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=30,
        )
    except Exception:
        return False
    return "Running" in _decode(proc.stdout or b"")


def _clear_event_logs(cat, result, log):
    if not cat.paths:
        return result
    target = cat.paths[0]
    before = _dir_size(target)

    cleared = _bulk_clear_event_logs()
    if cleared is None:
        log("    批量清空失败，改用逐条方式…")
        cleared = _fallback_clear_event_logs()

    result.deleted = cleared
    result.freed = max(before - _dir_size(target), 0)
    log(f"    已清空 {cleared} 个事件日志")
    if cleared == 0:
        result.errors.append("没有日志被清空，可能需要管理员权限")
    return result


_EVENT_LOG_SCRIPT = (
    "$n=0; $s=New-Object System.Diagnostics.Eventing.Reader.EventLogSession; "
    "Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | "
    "Where-Object { $_.RecordCount -gt 0 } | "
    "ForEach-Object { try { $s.ClearLog($_.LogName); $n++ } catch {} }; $n"
)


def _bulk_clear_event_logs():
    """一次 PowerShell 调用清空所有有记录的日志，失败返回 None。"""
    script = _EVENT_LOG_SCRIPT
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=300,
        )
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    for line in reversed(_decode(proc.stdout or b"").strip().splitlines()):
        line = line.strip()
        if line.isdigit():
            return int(line)
    return None


def _fallback_clear_event_logs():
    try:
        listed = subprocess.run(
            ["wevtutil", "el"],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=120,
        )
    except Exception:
        return 0

    names = [line.strip() for line in _decode(listed.stdout or b"").splitlines()
             if line.strip()]
    cleared = 0
    for name in names:
        try:
            proc = subprocess.run(
                ["wevtutil", "cl", name],
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=60,
            )
            if proc.returncode == 0:
                cleared += 1
        except Exception:
            continue
    return cleared


def _reset_search_index(cat, result, log):
    if not cat.paths:
        return result
    target = cat.paths[0]
    before = _dir_size(target)
    was_running = _service_running("WSearch")

    if was_running:
        log("    正在停止 Windows Search 服务…")
        try:
            subprocess.run(
                ["net.exe", "stop", "WSearch"],
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=90,
            )
        except Exception as exc:
            result.errors.append(f"停止搜索服务失败：{exc}")
            return result
        time.sleep(1)

    allowed = [norm_path(target)]
    for entry in walk_files(target):
        _delete_file(entry.path, allowed, ("*",), result)
    remove_empty_dirs(target)

    if was_running:
        try:
            subprocess.run(
                ["net.exe", "start", "WSearch"],
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=90,
            )
        except Exception:
            pass

    result.freed = max(before - _dir_size(target), 0)
    log(f"    索引文件已删除 {result.deleted} 个")
    if result.skipped:
        log(f"    跳过 {result.skipped} 个被占用的文件，可重启后再试")
    if was_running:
        log("    搜索服务已重新启动，索引将在后台重建")
    return result


def _empty_recycle_bin(cat, result, log):
    drives = cat.paths or ["C:\\"]
    flags = 0x1 | 0x2 | 0x4  # 不确认、不显示进度、不播放声音
    freed = 0
    items = 0
    emptied = 0

    for drive in drives:
        size, count = scanner.recycle_bin_size([drive])
        if size == 0 and count == 0:
            emptied += 1
            continue
        try:
            hr = ctypes.windll.shell32.SHEmptyRecycleBinW(None, drive, flags)
        except Exception as exc:
            result.errors.append(f"{drive} 清空失败：{exc}")
            continue
        if hr == 0:
            freed += size
            items += count
            emptied += 1
        else:
            result.errors.append(f"{drive} 清空失败，错误码 0x{hr & 0xFFFFFFFF:08X}")

    result.freed = freed
    result.deleted = items
    log(f"    已清空 {emptied}/{len(drives)} 个磁盘的回收站，释放 {fmt_size(freed)}")
    return result


def _run_command(cat, result, log):
    size_before = 0
    if cat.size_fn is not None:
        try:
            size_before = int(cat.size_fn() or 0)
        except Exception:
            size_before = 0

    log(f"    执行：{' '.join(cat.command)}")
    try:
        proc = subprocess.run(
            cat.command,
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=3600,
        )
    except Exception as exc:
        result.errors.append(f"命令执行失败：{exc}")
        return result

    output = _decode((proc.stdout or b"") + (proc.stderr or b""))
    for line in [l.strip() for l in output.splitlines() if l.strip()][-6:]:
        log(f"    {line}")

    if proc.returncode != 0:
        result.errors.append(f"命令返回码 {proc.returncode}")
        return result

    if cat.key == "hibernate":
        result.freed = max(size_before, 0)
        result.deleted = 1
        result.message = "休眠已关闭"
    else:
        result.message = "组件清理完成"
    return result
