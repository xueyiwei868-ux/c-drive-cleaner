"""文件粉碎：覆盖写后删除，以及删除后清理空目录。

系统路径直接拒绝。粉碎本身不可恢复，不走回收站。
打开文件时不跟随链接，只覆盖事先 lstat 到的那个普通文件。
"""
import os
import stat

import safepath
import utils


class ShredError(Exception):
    pass


def assert_shreddable(path: str):
    if not path or not os.path.lexists(path):
        raise ShredError("文件不存在")
    if safepath.is_reparse_point(path):
        raise ShredError(f"不能粉碎符号链接或目录联接：{path}")
    if safepath.is_protected_path(path):
        raise ShredError(f"为保护系统，拒绝粉碎：{path}")


def _open_regular_nofollow(path):
    """不跟随链接地打开普通文件，并核对设备号和 inode 与打开前的 lstat 一致。"""
    if os.name == "nt":
        return _open_regular_windows(path)
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise ShredError(f"文件不存在：{path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ShredError(f"不能粉碎符号链接或目录联接：{path}")
    if safepath.is_reparse_point(path):
        raise ShredError(f"不能粉碎符号链接或目录联接：{path}")
    flags = os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ShredError(f"无法安全打开文件：{path}") from exc
    try:
        current = os.fstat(fd)
        attributes = getattr(current, "st_file_attributes", 0) or 0
        if (not stat.S_ISREG(current.st_mode)
                or attributes & safepath.FILE_ATTRIBUTE_REPARSE_POINT
                or current.st_dev != info.st_dev
                or current.st_ino != info.st_ino):
            raise ShredError(f"文件在打开前被替换：{path}")
        return os.fdopen(fd, "r+b")
    except Exception:
        os.close(fd)
        raise


def _open_regular_windows(path):
    import ctypes
    import msvcrt
    from ctypes import wintypes
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise ShredError(f"文件不存在：{path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ShredError(f"不能粉碎符号链接或目录联接：{path}")
    if getattr(info, "st_file_attributes", 0) & safepath.FILE_ATTRIBUTE_REPARSE_POINT:
        raise ShredError(f"不能粉碎符号链接或目录联接：{path}")
    generic_read = 0x80000000
    generic_write = 0x40000000
    share = 0x1 | 0x2 | 0x4
    open_existing = 3
    flag = 0x00200000  # FILE_FLAG_OPEN_REPARSE_POINT
    kernel = ctypes.windll.kernel32
    handle = kernel.CreateFileW(
        str(path), generic_read | generic_write, share, None,
        open_existing, flag, None)
    invalid = ctypes.c_void_p(-1).value
    if handle in (0, invalid, -1):
        raise ShredError(f"无法安全打开文件：{path}")

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

    try:
        got = _ByHandle()
        if not kernel.GetFileInformationByHandle(handle, ctypes.byref(got)):
            raise ShredError(f"无法读取文件属性：{path}")
        file_id = (got.nFileIndexHigh << 32) | got.nFileIndexLow
        if (got.dwFileAttributes & safepath.FILE_ATTRIBUTE_REPARSE_POINT
                or got.dwVolumeSerialNumber != info.st_dev
                or file_id != info.st_ino):
            raise ShredError(f"文件在打开前被替换：{path}")
        fd = msvcrt.open_osfhandle(handle, getattr(os, "O_BINARY", 0))
    except Exception:
        kernel.CloseHandle(handle)
        raise
    try:
        current = os.fstat(fd)
        if (not stat.S_ISREG(current.st_mode)
                or current.st_dev != info.st_dev
                or current.st_ino != info.st_ino):
            raise ShredError(f"文件在打开前被替换：{path}")
        return os.fdopen(fd, "r+b")
    except Exception:
        os.close(fd)
        raise


def shred_file(path, passes=1):
    handle = _open_regular_nofollow(path)
    try:
        size = os.fstat(handle.fileno()).st_size
        for _ in range(max(1, passes)):
            handle.seek(0)
            left = size
            while left > 0:
                block = min(1 << 20, left)
                handle.write(os.urandom(block))
                left -= block
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        handle.close()
    safepath.unlink_regular(path, [os.path.dirname(path) or "."])


def _remove_empty_dirs(root):
    stack = [root]
    dirs = []
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if utils.is_link_like(entry):
                                try:
                                    os.rmdir(entry.path)
                                except OSError:
                                    pass
                            else:
                                dirs.append(entry.path)
                                stack.append(entry.path)
                    except OSError:
                        continue
        except OSError:
            continue
    for path in sorted(dirs, key=len, reverse=True):
        try:
            os.rmdir(path)
        except OSError:
            pass


def run_batch(paths, shred_fn=None):
    """逐个粉碎。失败记为 failed，不会当成已完成。"""
    shred_fn = shred_fn or shred_path
    records = []
    for path in paths or []:
        try:
            shred_fn(path)
            records.append({"path": path, "status": "ok"})
        except Exception as exc:
            records.append({"path": path, "status": "failed", "error": str(exc)})
    return records


def shred_path(path, passes=1, log=lambda _message: None):
    assert_shreddable(path)
    if os.path.isfile(path):
        shred_file(path, passes)
        log(path)
        return 1
    if os.path.isdir(path):
        count = 0
        for entry in utils.walk_files(path):
            try:
                shred_file(entry.path, passes)
                count += 1
            except OSError:
                pass
        _remove_empty_dirs(path)
        try:
            os.rmdir(path)
        except OSError:
            pass
        return count
    return 0
