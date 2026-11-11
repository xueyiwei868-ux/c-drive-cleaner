"""路径安全判断：系统目录保护、用户文档库、浏览器密码库。

Windows 盘符路径在 Linux 上不能交给 os.path.abspath（会被拼到当前目录）。
这里对「盘符:」开头的路径按 Windows 规则规范化，其余路径仍走本机绝对路径。
"""
import os
import secrets
import stat
import sys

FILE_ATTRIBUTE_REPARSE_POINT = 0x400


PASSWORD_FILENAMES = {
    "login data",
    "login data-journal",
    "login data for account",
    "login data for account-journal",
    "logins.json",
    "logins-backup.json",
    "key4.db",
    "key3.db",
}

_CRITICAL_FILES = {
    "pagefile.sys", "hiberfil.sys", "swapfile.sys", "bootmgr", "ntldr",
    "ntuser.dat", "ntuser.dat.log",
}

# 紧跟盘符的系统目录。比较时要求目录边界，避免把 Windows.old 误判成 Windows。
_SYSTEM_ROOTS = (
    "\\windows",
    "\\program files",
    "\\program files (x86)",
    "\\programdata",
    "\\system volume information",
    "\\$recycle.bin",
    "\\recovery",
    "\\boot",
    "\\perflogs",
)

_LIBRARY_NAMES = (
    "documents", "desktop", "downloads",
    "my documents", "文档", "桌面", "下载",
    "pictures", "music", "videos",
)


def basename(path: str) -> str:
    """同时认识 Windows 反斜杠和本机分隔符。"""
    text = str(path or "").replace("/", "\\").rstrip("\\")
    if "\\" in text:
        return text.rsplit("\\", 1)[-1]
    return os.path.basename(text)


def normalize(path: str) -> str:
    """返回去掉末尾分隔符的规范路径。盘符路径保持 Windows 形态。"""
    if not path:
        return ""
    text = str(path).strip().strip('"').replace("/", "\\")
    if len(text) >= 2 and text[1] == ":":
        drive = text[:2].upper()
        rest = text[2:].replace("\\\\", "\\")
        while "\\\\" in rest:
            rest = rest.replace("\\\\", "\\")
        if rest in ("", "\\"):
            return drive + "\\"
        if not rest.startswith("\\"):
            rest = "\\" + rest
        return (drive + rest).rstrip("\\")
    return os.path.normcase(os.path.abspath(text)).rstrip("\\/")


def _tail(path: str) -> str:
    """盘符之后的部分，统一成小写且以反斜杠开头。"""
    norm = normalize(path)
    if len(norm) >= 2 and norm[1] == ":":
        rest = norm[2:]
    else:
        rest = norm
    rest = rest.replace("/", "\\").lower()
    if not rest.startswith("\\"):
        rest = "\\" + rest
    return rest


def _is_under(tail: str, marker: str) -> bool:
    marker = marker.lower()
    if not marker.startswith("\\"):
        marker = "\\" + marker
    return tail == marker or tail.startswith(marker + "\\")


def _env_roots():
    roots = []
    for name in ("SystemRoot", "WINDIR", "ProgramFiles", "ProgramFiles(x86)", "ProgramData"):
        value = os.environ.get(name)
        if value:
            roots.append(normalize(value).lower())
    return roots


def is_drive_root(path: str) -> bool:
    norm = normalize(path)
    if len(norm) == 2 and norm[1] == ":":
        return True
    if len(norm) == 3 and norm[1] == ":" and norm[2] in "\\/":
        return True
    return False


def is_password_store(path: str) -> bool:
    """浏览器保存的密码库。隐私清理默认不能删这些文件。"""
    return basename(path).lower() in PASSWORD_FILENAMES


def is_reparse_point(path: str) -> bool:
    """符号链接、联接或其他重解析点。读不到属性时不当成链接。"""
    try:
        info = os.lstat(path)
    except OSError:
        return False
    attributes = getattr(info, "st_file_attributes", 0) or 0
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT:
        return True
    return stat.S_ISLNK(info.st_mode)


_REMOTE_CACHE_PARTS = {
    "cache", "caches", "code cache", "gpucache", "gpu cache", "htmlcache",
    "logs", "log",
}


def _path_parts(path: str):
    return [part for part in str(path).replace("/", "\\").split("\\") if part]


def path_syntax_error(path: str) -> str:
    """拒绝 ..、UNC 和盘符之外的冒号（备用数据流）。合法时返回空串。"""
    if path is None:
        return "路径为空"
    text = str(path).strip()
    if not text:
        return "路径为空"
    if text.startswith("\\\\") or text.startswith("//"):
        return "不能指向网络路径"
    body = text[2:] if len(text) >= 2 and text[1] == ":" else text
    if ":" in body:
        return "不能包含备用数据流"
    if ".." in _path_parts(text):
        return "路径不能包含 .."
    return ""


def _expand_env(path: str, environ) -> str:
    import re
    env = environ if environ is not None else os.environ

    def repl(match):
        return env.get(match.group(1), match.group(0))

    return re.sub(r"%([^%]+)%", repl, str(path))


def _within_root(path: str, root: str) -> bool:
    if not path or not root:
        return False
    target = normalize(path).lower().rstrip("\\/")
    base = normalize(root).lower().rstrip("\\/")
    if not base:
        return False
    if target == base:
        return True
    return target.startswith(base + "\\") or target.startswith(base + "/")


def _remote_pattern_ok(path: str) -> bool:
    """未展开时，只接受明确的临时目录或 AppData 下的缓存目录前缀。"""
    folded = str(path).replace("/", "\\")
    low = folded.lower()
    if path_syntax_error(folded):
        return False
    if low == "%temp%" or low.startswith("%temp%\\"):
        return True
    if low == "%tmp%" or low.startswith("%tmp%\\"):
        return True
    if low == "%localappdata%\\temp" or low.startswith("%localappdata%\\temp\\"):
        return True
    if low.startswith("%localappdata%\\") or low.startswith("%appdata%\\"):
        parts = [part.lower() for part in _path_parts(folded)]
        return any(part in _REMOTE_CACHE_PARTS for part in parts)
    return False


def _allow_roots(environ):
    env = environ if environ is not None else os.environ
    roots = []
    for key in ("TEMP", "TMP"):
        value = env.get(key)
        if value and not path_syntax_error(value):
            roots.append(value)
    local = env.get("LOCALAPPDATA") or ""
    if local:
        roots.append(os.path.join(local, "Temp"))
    return roots


def under_remote_allowlist(path: str, environ=None) -> bool:
    """解析后的路径必须落在用户临时目录，或 Local/Roaming 下的已知缓存目录。"""
    if path_syntax_error(path):
        return False
    expanded = _expand_env(path, environ)
    if path_syntax_error(expanded):
        return False
    # 变量没设时，只认明确的 %TEMP% / %LOCALAPPDATA%\\Temp / AppData 缓存写法。
    if "%" in expanded:
        return _remote_pattern_ok(path) and _remote_pattern_ok(expanded)
    normalized = normalize(expanded)
    if is_system_path(normalized) or is_user_library(normalized, environ):
        return False
    for root in _allow_roots(environ):
        if _within_root(normalized, root):
            return True
    env = environ if environ is not None else os.environ
    for key in ("LOCALAPPDATA", "APPDATA"):
        base = env.get(key) or ""
        if not base or not _within_root(normalized, base):
            continue
        parts = [part.lower() for part in _path_parts(normalize(normalized))]
        if any(part in _REMOTE_CACHE_PARTS for part in parts):
            return True
    return False


def execution_forbidden(path: str, untrusted=False, environ=None) -> bool:
    """删除前再检查。不可信规则还必须落在远程允许的根目录里，且不能碰系统目录。"""
    if not path or path_syntax_error(path):
        return True
    if is_reparse_point(path) or os.path.islink(path):
        return True
    if is_password_store(path) or is_user_library(path, environ):
        return True
    if is_drive_root(path) or is_critical_file(path):
        return True
    if untrusted:
        if is_system_path(path) or not under_remote_allowlist(path, environ):
            return True
    return False


def _within_allowed(path: str, allowed) -> bool:
    if not allowed:
        return True
    target = normalize(path).lower()
    for root in allowed:
        if not root:
            continue
        base = normalize(root).lower().rstrip("\\/")
        if target == base or target.startswith(base + "\\") or target.startswith(base + "/"):
            return True
    return False


def _parents_are_plain(path: str, allowed) -> bool:
    """删除前 lstat 文件本身，以及直到文件系统根的每一级父目录。"""
    if not _within_allowed(path, allowed):
        return False
    current = path
    seen = set()
    while current and current not in seen:
        seen.add(current)
        if os.path.islink(current) or is_reparse_point(current):
            return False
        parent = os.path.dirname(current)
        if not parent or parent == current:
            return True
        current = parent
    return True


class UnsafeUnlinkError(OSError):
    """目录项已变化或无法安全恢复；调用方不得把它当成普通占用文件。"""


def _same_inode(left, right):
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _unlink_name_if_inode(name: str, dirfd: int, expected, path="", validate=None,
                          expected_kind="regular"):
    """原子捕获目录项，核对 inode 后删除；不匹配时尽力无覆盖地放回。"""
    for _ in range(32):
        quarantine = ".c-drive-cleaner-delete-" + secrets.token_hex(12)
        try:
            os.mkdir(quarantine, 0o700, dir_fd=dirfd)
            break
        except FileExistsError:
            continue
    else:
        raise UnsafeUnlinkError("无法创建安全删除隔离目录")

    quarantine_fd = None
    entry = "captured"
    base = os.path.dirname(path) if path else ""
    quarantine_path = (os.path.join(base, quarantine, entry) if base
                       else os.path.join(quarantine, entry))
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        quarantine_fd = os.open(quarantine, flags, dir_fd=dirfd)
        try:
            os.rename(name, entry, src_dir_fd=dirfd, dst_dir_fd=quarantine_fd)
        except FileNotFoundError as exc:
            raise UnsafeUnlinkError(f"目录项已变化，未删除：{path or name}") from exc
        moved = os.stat(entry, dir_fd=quarantine_fd, follow_symlinks=False)
        expected_type = (stat.S_ISLNK(moved.st_mode) if expected_kind == "symlink"
                         else stat.S_ISREG(moved.st_mode))
        if expected_type and _same_inode(moved, expected):
            if validate is None:
                try:
                    os.unlink(entry, dir_fd=quarantine_fd)
                except OSError as exc:
                    raise UnsafeUnlinkError(
                        f"文件已安全隔离但未删除：{quarantine_path}") from exc
                return
            guard = "guard"
            try:
                os.link(entry, guard, src_dir_fd=quarantine_fd,
                        dst_dir_fd=quarantine_fd, follow_symlinks=False)
            except OSError as exc:
                raise UnsafeUnlinkError(
                    f"无法建立删除保护，备份保留在 {quarantine_path}") from exc
            try:
                os.unlink(entry, dir_fd=quarantine_fd)
            except OSError as exc:
                try:
                    os.link(guard, name, src_dir_fd=quarantine_fd,
                            dst_dir_fd=dirfd, follow_symlinks=False)
                except OSError:
                    raise UnsafeUnlinkError(
                        f"删除失败，文件保留在 {quarantine_path}") from exc
                raise UnsafeUnlinkError(
                    f"删除失败，文件已还原：{path or name}") from exc
            try:
                keep = bool(validate())
            except Exception:
                keep = False
            if not keep:
                try:
                    os.link(guard, name, src_dir_fd=quarantine_fd,
                            dst_dir_fd=dirfd, follow_symlinks=False)
                except OSError as exc:
                    raise UnsafeUnlinkError(
                        f"校验失败，文件保留在 {quarantine_path}") from exc
                try:
                    os.unlink(guard, dir_fd=quarantine_fd)
                except OSError:
                    pass
                raise UnsafeUnlinkError(f"删除后校验失败，文件已还原：{path or name}")
            try:
                os.unlink(guard, dir_fd=quarantine_fd)
            except OSError as exc:
                try:
                    os.link(guard, name, src_dir_fd=quarantine_fd,
                            dst_dir_fd=dirfd, follow_symlinks=False)
                except OSError:
                    raise UnsafeUnlinkError(
                        f"删除保护无法清理，文件保留在 {quarantine_path}") from exc
                raise UnsafeUnlinkError(
                    f"删除保护无法清理，文件已还原：{path or name}") from exc
            return

        # The name was exchanged after it was opened. Restore the captured
        # entry without replacing anything that may now occupy the original name.
        try:
            os.link(entry, name, src_dir_fd=quarantine_fd, dst_dir_fd=dirfd,
                    follow_symlinks=False)
        except OSError as exc:
            raise UnsafeUnlinkError(
                f"目录项已变化，未删除；已保留在 {quarantine_path}") from exc
        try:
            staged = os.stat(entry, dir_fd=quarantine_fd, follow_symlinks=False)
            restored = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
        except OSError as exc:
            raise UnsafeUnlinkError(
                f"目录项已变化，未删除；已保留在 {quarantine_path}") from exc
        if not _same_inode(staged, moved) or not _same_inode(restored, moved):
            raise UnsafeUnlinkError(
                f"目录项已变化，未删除；已保留在 {quarantine_path}")
        try:
            os.unlink(entry, dir_fd=quarantine_fd)
        except OSError as exc:
            raise UnsafeUnlinkError(
                f"目录项已变化，原项已恢复；隔离副本仍在 {quarantine_path}") from exc
        raise UnsafeUnlinkError(f"目录项已变化，未删除：{path or name}")
    finally:
        if quarantine_fd is not None:
            os.close(quarantine_fd)
        try:
            os.rmdir(quarantine, dir_fd=dirfd)
        except OSError:
            # If safe restoration was impossible, retain the captured entry.
            pass


def unlink_regular(path: str, allowed=()):
    """确认不是链接后删除。逐级 O_NOFOLLOW 打开，避免父目录在检查后被换成链接。"""
    if not _parents_are_plain(path, allowed):
        raise OSError(f"拒绝删除链接路径：{path}")
    if os.name == "nt":
        _windows_unlink_noreparse(path, allowed)
        return
    absolute = os.path.abspath(path)
    parts = [part for part in absolute.split(os.sep) if part]
    if not parts:
        raise OSError("拒绝删除根路径")
    dir_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        dir_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        dir_flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        dir_flags |= os.O_CLOEXEC
    dirfd = os.open(os.sep, dir_flags)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, dir_flags, dir_fd=dirfd)
            os.close(dirfd)
            dirfd = next_fd
            info = os.fstat(dirfd)
            if not stat.S_ISDIR(info.st_mode):
                raise OSError("父级不是普通目录")
        name = parts[-1]
        file_flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            file_flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            file_flags |= os.O_CLOEXEC
        fd = os.open(name, file_flags, dir_fd=dirfd)
        try:
            file_info = os.fstat(fd)
            if not stat.S_ISREG(file_info.st_mode):
                raise OSError("拒绝删除非普通文件")
            if not _parents_are_plain(absolute, allowed):
                raise OSError(f"拒绝删除链接路径：{absolute}")
            _unlink_name_if_inode(name, dirfd, file_info, absolute)
        finally:
            os.close(fd)
    finally:
        os.close(dirfd)


def _windows_unlink_noreparse(path: str, allowed):
    """用 FILE_FLAG_OPEN_REPARSE_POINT 打开句柄，确认不是重解析点后按句柄删除。"""
    import ctypes
    from ctypes import wintypes
    if not _parents_are_plain(path, allowed):
        raise OSError(f"拒绝删除链接路径：{path}")
    delete_access = 0x00010000
    generic_read = 0x80000000
    share = 0x1 | 0x2 | 0x4
    open_existing = 3
    flag = 0x00200000 | 0x02000000  # OPEN_REPARSE_POINT | BACKUP_SEMANTICS
    kernel = ctypes.windll.kernel32
    handle = kernel.CreateFileW(
        path, delete_access | generic_read, share, None, open_existing, flag, None)
    invalid = ctypes.c_void_p(-1).value
    if handle in (0, invalid, -1):
        raise OSError("无法打开文件")
    try:
        class _ByHandle(ctypes.Structure):
            _fields_ = [
                ("dwFileAttributes", wintypes.DWORD),
                ("ftCreationTime", wintypes.FILETIME),
                ("ftLastAccessTime", wintypes.FILETIME),
                ("ftLastWriteTime", wintypes.FILETIME),
                ("dwVolumeSerialNumber", wintypes.DWORD),
                ("nFileSizeHigh", wintypes.DWORD),
                ("nFileSizeLow", wintypes.DWORD),
                ("nNumberOfLinks", wintypes.DWORD),
                ("nFileIndexHigh", wintypes.DWORD),
                ("nFileIndexLow", wintypes.DWORD),
            ]

        class _Disposition(ctypes.Structure):
            _fields_ = [("DeleteFile", wintypes.BOOLEAN)]

        info = _ByHandle()
        if not kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
            raise OSError("无法读取文件属性")
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT:
            raise OSError("拒绝删除重解析点")
        if not _parents_are_plain(path, allowed):
            raise OSError(f"拒绝删除链接路径：{path}")
        mark = _Disposition(True)
        if not kernel.SetFileInformationByHandle(handle, 4, ctypes.byref(mark), ctypes.sizeof(mark)):
            raise OSError("无法按句柄删除文件")
    finally:
        kernel.CloseHandle(handle)


def clean_forbidden(path: str, environ=None) -> bool:
    """清理执行时再拦一次：文档库、密码库、链接、盘符根和关键系统文件。"""
    return execution_forbidden(path, untrusted=False, environ=environ)


def is_critical_file(path: str) -> bool:
    return basename(path).lower() in _CRITICAL_FILES


def _under_env_root(path: str) -> bool:
    target = normalize(path).lower().rstrip("\\")
    for root in _env_roots():
        root = root.rstrip("\\/")
        if not root:
            continue
        if target == root or target.startswith(root + "\\") or target.startswith(root + "/"):
            return True
    return False


def _under_marker(path: str, markers) -> bool:
    tail = _tail(path)
    return any(_is_under(tail, marker) for marker in markers)


def is_system_path(path: str) -> bool:
    """Windows 目录、盘符根、关键系统文件、卷信息。粉碎和搬家都不能碰。"""
    if not path or not str(path).strip():
        return True
    if is_drive_root(path) or is_critical_file(path):
        return True
    if _under_marker(path, ("\\windows", "\\system volume information",
                            "\\recovery", "\\boot", "\\$recycle.bin")):
        return True
    system = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
    if system:
        root = normalize(system).lower().rstrip("\\/")
        target = normalize(path).lower().rstrip("\\/")
        if target == root or target.startswith(root + "\\") or target.startswith(root + "/"):
            return True
    return False


def is_protected_path(path: str) -> bool:
    """粉碎保护：系统目录、Program Files、ProgramData、用户配置根本身、本程序。"""
    if is_system_path(path):
        return True
    if _under_marker(path, ("\\program files", "\\program files (x86)", "\\programdata",
                            "\\perflogs")):
        return True
    if _under_env_root(path):
        return True
    profile = os.environ.get("USERPROFILE")
    if profile and normalize(path).lower().rstrip("\\") == normalize(profile).lower().rstrip("\\"):
        return True
    exe = getattr(sys, "executable", "") or ""
    if exe:
        home = normalize(os.path.dirname(exe)).lower().rstrip("\\")
        target = normalize(path).lower().rstrip("\\")
        # 只在解释器位于受保护目录时才连坐，避免挡住用户目录里的普通文件。
        if home and (is_system_path(home) or _under_marker(home, ("\\program files",
                     "\\program files (x86)", "\\programdata"))):
            if target == home or target.startswith(home + "\\"):
                return True
    return False


def user_library_roots(environ=None):
    env = environ if environ is not None else os.environ
    roots = []
    bases = []
    for key in ("USERPROFILE", "HOME"):
        value = env.get(key)
        if value:
            bases.append(value)
    one = env.get("OneDrive") or env.get("OneDriveConsumer")
    if one:
        bases.append(one)
    for base in bases:
        for name in ("Documents", "Desktop", "Downloads", "My Documents",
                     "文档", "桌面", "下载", "Pictures", "Music", "Videos"):
            roots.append(normalize(os.path.join(base, name)))
    return roots


def is_user_library(path: str, environ=None) -> bool:
    """文档、桌面、下载及其子路径。软件搬家不能提供这些目录。"""
    if not path:
        return False
    target = normalize(path).lower().rstrip("\\")
    for root in user_library_roots(environ):
        root = root.lower().rstrip("\\")
        if target == root or target.startswith(root + "\\"):
            return True
    # 环境变量缺失时，仍识别「用户目录下的已知库文件夹」。
    parts = [part for part in _tail(path).split("\\") if part]
    if len(parts) >= 3 and parts[0] == "users" and parts[2] in _LIBRARY_NAMES:
        return True
    if len(parts) >= 2 and parts[0] == "users" and parts[1] in _LIBRARY_NAMES:
        return True
    return False


def migration_forbidden(path: str, environ=None) -> bool:
    """软件搬家候选：拒绝系统根、整个 Program Files、以及文档/桌面/下载。

    Program Files 里的单个软件目录允许搬家；目录本身不允许。
    """
    if not path or is_system_path(path) or is_user_library(path, environ):
        return True
    tail = _tail(path)
    exact = {
        "\\program files", "\\program files (x86)", "\\programdata", "\\users",
    }
    if tail in exact:
        return True
    profile = (environ or os.environ).get("USERPROFILE")
    if profile and normalize(path).lower().rstrip("\\") == normalize(profile).lower().rstrip("\\"):
        return True
    return False
