"""快速文件枚举：优先调用 Rust MFT 读取器，失败时回退并行/串行遍历。

Rust 读取器（mftreader.exe）直接解析 NTFS $MFT，全盘枚举只要约 10 秒，
比递归访问每个文件快得多；它按 MFT 记录去重，硬链接不会重复计数。
"""
import os
import queue
import subprocess
import sys
import threading

import utils

CREATE_NO_WINDOW = 0x08000000


def _mft_exe():
    base = getattr(sys, "_MEIPASS", None) or os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(base, "mftreader.exe")
    return path if os.path.exists(path) else None


def cache_dir():
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    path = os.path.join(base, "C盘清理工具", "mftcache")
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        return ""
    return path


def _run_mft(exe, root, skip_top, min_size, force=False):
    args = [exe, root, str(int(min_size)), cache_dir()]
    if force:
        args.append("--refresh")
    try:
        proc = subprocess.run(args, capture_output=True,
                              creationflags=CREATE_NO_WINDOW, timeout=300)
    except Exception:
        return None
    if proc.returncode != 0 or not proc.stdout:
        return None

    skip = {name.lower() for name in (skip_top or ())}
    root_len = len(os.path.abspath(root).rstrip("\\")) + 1
    out = []
    for line in proc.stdout.split(b"\n"):
        if not line:
            continue
        tab = line.find(b"\t")
        if tab < 0:
            continue
        try:
            size = int(line[:tab])
        except ValueError:
            continue
        if size < min_size:
            continue
        raw = line[tab + 1:]
        try:
            path = raw.decode("utf-8", "replace")
        except Exception:
            continue
        rel = path[root_len:] if len(path) > root_len else path
        first = rel.split("\\", 1)[0].lower()
        if first in skip:
            continue
        if any(part.startswith("$") for part in path.split("\\")):
            continue
        out.append((path, size))
    return out


def iter_files_parallel(root, workers=8, skip_top=None, min_size=0):
    """返回 [(path, size), ...]。失败时返回 None，调用方可回退到串行扫描。"""
    if _linked_root(root):
        return []
    if not os.path.isdir(root):
        return None
    skip_top = {name.lower() for name in (skip_top or ())}

    results = []
    results_lock = threading.Lock()
    dir_q = queue.Queue()
    dir_q.put(root)
    active = [1]  # 尚未处理完的目录数（排队中 + 处理中）
    cond = threading.Condition()

    def worker():
        while True:
            with cond:
                while dir_q.empty() and active[0] > 0:
                    cond.wait(0.2)
                if dir_q.empty() and active[0] == 0:
                    return
                current = dir_q.get()
            subdirs = []
            try:
                with os.scandir(current) as it:
                    for entry in it:
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                if utils.is_link_like(entry):
                                    continue
                                if current == root and entry.name.lower() in skip_top:
                                    continue
                                subdirs.append(entry.path)
                            elif entry.is_file(follow_symlinks=False):
                                try:
                                    size = entry.stat(follow_symlinks=False).st_size
                                except OSError:
                                    continue
                                if size < min_size:
                                    continue
                                with results_lock:
                                    results.append((entry.path, size))
                        except OSError:
                            continue
            except OSError:
                pass
            with cond:
                for path in subdirs:
                    dir_q.put(path)
                active[0] += len(subdirs) - 1
                cond.notify_all()

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(max(1, workers))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return results


def _linked_root(root) -> bool:
    if not root or os.path.islink(root):
        return True
    try:
        import safepath
        return safepath.is_reparse_point(root)
    except Exception:
        return True


def iter_files(root, skip_top=None, min_size=0, force=False):
    """按场景选择：整盘/大文件扫描用 MFT，小目录用并行遍历，最后串行。"""
    if _linked_root(root):
        return []
    exe = _mft_exe()
    drive_part = os.path.splitdrive(os.path.abspath(root))[1]
    use_mft = bool(exe) and (drive_part in ("\\", "") or min_size >= 10 * 1024 * 1024)
    if use_mft:
        data = _run_mft(exe, root, skip_top, min_size, force)
        if data is not None:
            return data
    try:
        data = iter_files_parallel(root, skip_top=skip_top, min_size=min_size)
    except Exception:
        data = None
    if data is not None:
        return data
    skip_top = {name.lower() for name in (skip_top or ())}
    out = []
    for entry in utils.walk_files(root):
        try:
            size = entry.stat(follow_symlinks=False).st_size
        except OSError:
            continue
        if size >= min_size:
            out.append((entry.path, size))
    return out
