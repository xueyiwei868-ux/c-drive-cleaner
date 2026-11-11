"""通用工具：权限、路径安全、遍历、大小格式化。"""
import ctypes
import os
import subprocess
import sys

FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    """以管理员身份重新启动当前程序，成功返回 True。"""
    if getattr(sys, "frozen", False):
        exe, params, workdir = sys.executable, "", os.path.dirname(sys.executable)
    else:
        exe = sys.executable
        if exe.lower().endswith("python.exe"):
            candidate = exe[:-len("python.exe")] + "pythonw.exe"
            if os.path.exists(candidate):
                exe = candidate
        script = os.path.abspath(sys.argv[0])
        params = " ".join(f'"{arg}"' for arg in [script] + sys.argv[1:])
        workdir = os.path.dirname(script)
    try:
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, workdir, 1)
        return rc > 32
    except Exception:
        return False


def fmt_size(num) -> str:
    num = int(num or 0)
    if num < 1024:
        return f"{num} B"
    value = float(num)
    for unit in ("KB", "MB", "GB", "TB"):
        value /= 1024.0
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}"
    return f"{num} B"


def fmt_size_compact(num) -> str:
    """侧栏用的短格式，例如 23.2G。"""
    num = int(num or 0)
    if num < 1024:
        return f"{num}B"
    value = float(num)
    for unit in ("K", "M", "G", "T"):
        value /= 1024.0
        if value < 1024 or unit == "T":
            if value >= 100 or abs(value - round(value)) < 0.05:
                return f"{int(round(value))}{unit}"
            return f"{value:.1f}{unit}"
    return f"{num}B"


def norm_path(path: str) -> str:
    return os.path.normcase(os.path.abspath(path)).rstrip("\\")


def is_within(path: str, roots) -> bool:
    """path 是否位于 roots 中某个目录之下（含等于）。"""
    p = norm_path(path)
    for root in roots:
        r = norm_path(root).rstrip("/")
        if p == r or p.startswith(r + "\\") or p.startswith(r + "/"):
            return True
    return False


def is_link_like(entry) -> bool:
    """junction / 符号链接 / 无法读取属性的条目，一律视为不可进入。"""
    try:
        if entry.is_symlink():
            return True
    except OSError:
        return True
    is_junction = getattr(entry, "is_junction", None)
    if callable(is_junction):
        try:
            if is_junction():
                return True
        except OSError:
            return True
    try:
        st = entry.stat(follow_symlinks=False)
    except OSError:
        return True
    attributes = getattr(st, "st_file_attributes", 0) or 0
    return bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT)


def is_runtime_path(path: str) -> bool:
    """打包成 exe 后，程序自身解压到临时目录的文件不能删。"""
    base = getattr(sys, "_MEIPASS", None)
    return bool(base) and is_within(path, [base])


def fixed_drives():
    """返回所有本地固定磁盘根目录，例如 ['C:\\\\', 'D:\\\\']。"""
    drives = []
    try:
        mask = ctypes.windll.kernel32.GetLogicalDrives()
    except Exception:
        return ["C:\\"]
    for index in range(26):
        if not mask & (1 << index):
            continue
        root = f"{chr(65 + index)}:\\"
        try:
            if ctypes.windll.kernel32.GetDriveTypeW(root) == 3:
                drives.append(root)
        except Exception:
            continue
    return drives or ["C:\\"]


def current_user_sid():
    """当前登录账户的 SID，读不到返回空串。"""
    try:
        exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                           "System32", "whoami.exe")
        proc = subprocess.run(
            [exe, "/user"],
            capture_output=True,
            text=True,
            encoding="mbcs",
            errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        lines = [line for line in (proc.stdout or "").strip().splitlines() if line.strip()]
        if lines:
            return lines[-1].split()[-1]
    except Exception:
        pass
    return ""


def schedule_delete(path: str) -> bool:
    """被占用的文件安排到下次重启时删除。"""
    try:
        return bool(ctypes.windll.kernel32.MoveFileExW(
            path, None, 0x4))  # MOVEFILE_DELAY_UNTIL_REBOOT
    except Exception:
        return False


def walk_files(root):
    """遍历 root 下所有文件。根或中间目录是链接时直接停，不跟随。"""
    if not root or os.path.islink(root):
        return
    try:
        import safepath
        if safepath.is_reparse_point(root):
            return
    except Exception:
        return
    stack = [root]
    while stack:
        current = stack.pop()
        if os.path.islink(current):
            continue
        try:
            import safepath
            if safepath.is_reparse_point(current):
                continue
        except Exception:
            continue
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        if is_link_like(entry):
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            yield entry
                    except OSError:
                        continue
        except OSError:
            continue


def remove_empty_dirs(root: str) -> int:
    """自底向上删除 root 之下的空目录，不删除 root 本身。"""
    root_norm = norm_path(root)
    dirs = []
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=False) and not is_link_like(entry):
                            dirs.append(entry.path)
                            stack.append(entry.path)
                    except OSError:
                        continue
        except OSError:
            continue
    removed = 0
    for path in sorted(dirs, key=len, reverse=True):
        if norm_path(path) == root_norm:
            continue
        try:
            os.rmdir(path)
            removed += 1
        except OSError:
            pass
    return removed
