"""数据迁移：把大目录搬到其他盘，并在原位置建立目录联接（junction）。

安全策略：
1. 先完整复制到目标盘，并用整文件 SHA-256 校验。
2. 把源目录改名为备份，再建立联接并确认联接能解析。
3. 只删除清单中的文件：打开后在同一个句柄上核对大小和摘要，匹配才删除。
   清单外或对不上的文件留在备份里，结果记为部分完成。
任何一步失败都不会丢数据：目标副本在建立联接前一直保留。
"""
import ctypes
import hashlib
import os
import shutil
import stat
import subprocess

import safepath
import utils

FILE_ATTRIBUTE_REPARSE_POINT = 0x400
CREATE_NO_WINDOW = 0x08000000


class MigrateError(Exception):
    pass


def is_junction(path: str) -> bool:
    try:
        attrs = ctypes.windll.kernel32.GetFileAttributesW(path)
    except Exception:
        return False
    if attrs is None or attrs == -1:
        return False
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)


def junction_target(path: str) -> str:
    """返回联接/符号链接指向的真实路径，失败返回空串。"""
    try:
        return os.path.realpath(path)
    except Exception:
        return ""


def count_files(root: str) -> int:
    return sum(1 for _ in utils.walk_files(root))


def dir_size(root: str) -> int:
    total = 0
    for entry in utils.walk_files(root):
        try:
            total += entry.stat(follow_symlinks=False).st_size
        except OSError:
            pass
    return total


def _protected_roots():
    names = ["SystemRoot", "ProgramFiles", "ProgramFiles(x86)",
             "ProgramData", "USERPROFILE", "LOCALAPPDATA", "APPDATA"]
    roots = []
    for name in names:
        value = os.environ.get(name)
        if value:
            roots.append(os.path.normcase(os.path.abspath(value)).rstrip("\\"))
    return roots


def _drive_of(path: str) -> str:
    return os.path.splitdrive(os.path.abspath(path))[0].upper()


def validate(src: str, dest_root: str):
    """校验并返回 (src, dest)。不合法时抛出 MigrateError。"""
    src = os.path.abspath(src)
    dest_root = os.path.abspath(dest_root)

    if not os.path.isdir(src):
        raise MigrateError("源目录不存在")
    if is_junction(src):
        raise MigrateError("该目录已经是联接，无需迁移")
    if len(src.rstrip("\\")) <= 2:
        raise MigrateError("不能迁移整个磁盘根目录")

    norm_src = os.path.normcase(src).rstrip("\\")
    if norm_src in _protected_roots():
        raise MigrateError("该目录属于系统或用户配置根目录，不能迁移")

    if not _drive_of(dest_root):
        raise MigrateError("目标位置需要指定盘符")
    if _drive_of(src) == _drive_of(dest_root):
        raise MigrateError("目标盘必须与源目录所在盘不同")

    name = os.path.basename(src.rstrip("\\"))
    if not name:
        raise MigrateError("无法确定目录名")
    dest = os.path.join(dest_root, name)
    if os.path.exists(dest):
        raise MigrateError(f"目标已存在：{dest}")
    return src, dest


def _robocopy(src: str, dst: str, move: bool) -> int:
    args = ["robocopy", src, dst, "/E", "/R:1", "/W:1",
            "/NFL", "/NDL", "/NJH", "/NJS", "/NP"]
    if move:
        args.append("/MOVE")
    try:
        proc = subprocess.run(args, capture_output=True,
                              creationflags=CREATE_NO_WINDOW)
    except Exception as exc:
        raise MigrateError(f"无法运行 robocopy：{exc}")
    return proc.returncode


def create_junction(link: str, target: str):
    try:
        proc = subprocess.run(["cmd", "/c", "mklink", "/J", link, target],
                              capture_output=True, creationflags=CREATE_NO_WINDOW)
    except Exception as exc:
        raise MigrateError(f"无法运行 mklink：{exc}")
    if proc.returncode != 0 or not is_junction(link):
        message = (proc.stderr or proc.stdout or b"").decode("mbcs", "replace").strip()
        raise MigrateError(f"创建联接失败：{message or '未知错误'}")


def junction_works(link: str, target: str) -> bool:
    """校验联接不仅能列出根目录，还能真正进入子目录。

    某些环境（如安全软件的文件过滤驱动）下，跨卷联接在 AppData 等位置
    会返回 ERROR_MOUNT_POINT_NOT_RESOLVED，根目录可列出但子目录不可访问。
    这里以目标盘的真实内容为参照，从联接路径进入同一子目录来验证。
    """
    try:
        target_items = os.listdir(target)
    except OSError:
        return False
    if not target_items:
        return True
    for name in target_items:
        if os.path.isdir(os.path.join(target, name)):
            try:
                os.listdir(os.path.join(link, name))
            except OSError:
                return False
            return True
    name = target_items[0]
    return os.path.exists(os.path.join(link, name))


# (dev, ino) -> 完整校验/恢复读取次数（不含复制工具本身的传输读取）。
_full_read_counts = {}


def _note_full_read(info):
    if hasattr(info, "nFileIndexHigh"):
        file_id = (int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow)
        key = (int(info.dwVolumeSerialNumber), file_id)
    else:
        key = (int(getattr(info, "st_dev", 0) or 0),
               int(getattr(info, "st_ino", 0) or 0))
    _full_read_counts[key] = _full_read_counts.get(key, 0) + 1


def _identity_tuple(info):
    """核对时刻的快照。Windows 用文件号、大小和最后写入时间。"""
    mtime = getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000))
    if os.name == "nt":
        return (int(getattr(info, "st_dev", 0) or 0),
                int(getattr(info, "st_ino", 0) or 0),
                int(info.st_size), mtime)
    ctime = getattr(info, "st_ctime_ns", int(getattr(info, "st_ctime", 0) * 1_000_000_000))
    return (int(info.st_dev), int(info.st_ino), int(info.st_size), mtime, ctime)


def _fingerprint_with_snap(path: str):
    """返回 (大小, 摘要, 快照)。读的过程中快照变了则返回 None。"""
    try:
        info = os.lstat(path)
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode) or safepath.is_reparse_point(path):
        return None
    digest = hashlib.sha256()
    fd = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        fd = os.open(path, flags)
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_dev != info.st_dev
                or opened.st_ino != info.st_ino):
            return None
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        after = os.fstat(fd)
        _note_full_read(after)
        if _identity_tuple(after) != _identity_tuple(opened):
            return None
        return (after.st_size, digest.hexdigest(), _identity_tuple(after))
    except OSError:
        return None
    finally:
        if fd is not None:
            os.close(fd)


def _fingerprint(path: str):
    """文件的 (大小, 摘要)。链接返回 None，避免把链接目标当成副本。"""
    marked = _fingerprint_with_snap(path)
    if marked is None:
        return None
    size, digest, _snap = marked
    return (size, digest)


def _inventory_verified(root: str):
    """返回 (相对路径 -> (大小, 摘要), 相对路径 -> 核对时的快照)。"""
    found = {}
    snaps = {}
    if not root or os.path.islink(root) or not os.path.isdir(root) or safepath.is_reparse_point(root):
        return found, snaps
    base = os.path.abspath(root)
    for entry in utils.walk_files(base):
        marked = _fingerprint_with_snap(entry.path)
        if marked is None:
            continue
        size, digest, snap = marked
        rel = os.path.relpath(entry.path, base)
        found[rel] = (size, digest)
        snaps[rel] = snap
    return found, snaps


def _inventory_metadata(root: str):
    """只收集源目录文件大小和快照，不先整读源文件。"""
    found = {}
    snaps = {}
    if not root or os.path.islink(root) or not os.path.isdir(root) or safepath.is_reparse_point(root):
        return found, snaps
    base = os.path.abspath(root)
    for entry in utils.walk_files(base):
        try:
            info = os.lstat(entry.path)
        except OSError:
            continue
        if not stat.S_ISREG(info.st_mode) or safepath.is_reparse_point(entry.path):
            continue
        rel = os.path.relpath(entry.path, base)
        found[rel] = info.st_size
        snaps[rel] = _identity_tuple(info)
    return found, snaps


def _inventory_covers_sizes(have: dict, need: dict) -> bool:
    return all(rel in have and have[rel][0] == size
               for rel, size in (need or {}).items())


def _tree_metadata_still(root: str, expected_sizes: dict, snaps: dict) -> bool:
    """检查源目录的文件名、大小及元数据快照，不做额外整文件读取。"""
    if not root or os.path.islink(root) or not os.path.isdir(root):
        return False
    base = os.path.abspath(root)
    current = {}
    for entry in utils.walk_files(base):
        try:
            info = os.lstat(entry.path)
        except OSError:
            return False
        if not stat.S_ISREG(info.st_mode) or safepath.is_reparse_point(entry.path):
            return False
        current[os.path.relpath(entry.path, base)] = info
    if set(current) != set(expected_sizes):
        return False
    for rel, info in current.items():
        if info.st_size != expected_sizes[rel]:
            return False
        snap = snaps.get(rel)
        if snap is not None and _identity_tuple(info) != snap:
            return False
    return True


def _survivor_still(path: str, snap, expected) -> bool:
    """仅在安全的平台上复用稳定快照；Windows 始终重新核对内容。"""
    if snap is None:
        return _fingerprint(path) == expected
    try:
        info = os.lstat(path)
    except OSError:
        return False
    if not stat.S_ISREG(info.st_mode) or safepath.is_reparse_point(path):
        return False
    # Windows 的文件号、大小与最后写入时间可在同长度内容被改后恢复；
    # 不能据此复用旧摘要，必须重新读取存活副本。
    if os.name != "nt" and _identity_tuple(info) == snap:
        return True
    return _fingerprint(path) == expected


def _tree_still_verified(root: str, marks: dict, snaps: dict) -> bool:
    """检查目录文件集和内容；逐个重新核对源文件摘要，不复用元数据快照。"""
    if not root or os.path.islink(root) or not os.path.isdir(root):
        return False
    base = os.path.abspath(root)
    current = {}
    for entry in utils.walk_files(base):
        try:
            info = os.lstat(entry.path)
        except OSError:
            return False
        if not stat.S_ISREG(info.st_mode) or safepath.is_reparse_point(entry.path):
            return False
        current[os.path.relpath(entry.path, base)] = info
    if set(current) != set(marks):
        return False
    for rel, info in current.items():
        snap = snaps.get(rel)
        if snap is not None and _identity_tuple(info) != snap:
            return False
        # 快照匹配也不能跳过摘要读取：时间戳可能不足以证明内容没变。
        if _fingerprint(entry_path(base, rel)) != marks.get(rel):
            return False
    return True


def entry_path(base: str, rel: str) -> str:
    return base if rel in (".", "") else os.path.join(base, rel)


def _manifest(root: str) -> dict:
    """普通文件的相对路径 -> (大小, mtime_ns, 整文件摘要)。不进入链接。"""
    found = {}
    if not root or os.path.islink(root) or not os.path.isdir(root) or safepath.is_reparse_point(root):
        return found
    base = os.path.abspath(root)
    for entry in utils.walk_files(base):
        try:
            info = os.lstat(entry.path)
        except OSError:
            continue
        mark = _fingerprint(entry.path)
        if mark is None:
            continue
        mtime = getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000))
        found[os.path.relpath(entry.path, base)] = (mark[0], mtime, mark[1])
    return found


class MigrateResult:
    """搬家结果。status 为 ok 才表示备份里已核对的文件都已删除。"""

    def __init__(self, src, dest, status="ok", backup="", remaining=()):
        self.src = src
        self.dest = dest
        self.status = status
        self.backup = backup or ""
        self.remaining = tuple(remaining)
        if status == "ok":
            self.warning = ""
        else:
            lines = ["部分完成，未校验的内容仍留在备份里。", f"备份位置：{self.backup}"]
            lines.extend(self.remaining)
            self.warning = "\n".join(lines)

    @property
    def ok(self):
        return self.status == "ok"

    def __iter__(self):
        yield self.src
        yield self.dest


def _is_stray_name(name: str) -> bool:
    return (name.startswith(".c-drive-cleaner-delete-")
            or name.endswith(".migrate-bak"))


def _mounted_drive_roots():
    """返回可扫描的本地固定/可移动盘根目录，不包含网络盘。"""
    if os.name != "nt":
        return []
    try:
        kernel = ctypes.windll.kernel32
        mask = int(kernel.GetLogicalDrives())
        roots = []
        for index in range(26):
            if not mask & (1 << index):
                continue
            root = f"{chr(ord('A') + index)}:\\"
            if kernel.GetDriveTypeW(root) in (2, 3):
                roots.append(root)
        return roots
    except Exception:
        return []


def known_locations(environ=None):
    """返回本地卷与常见应用/用户目录，供只读残留扫描使用。"""
    env = os.environ if environ is None else environ
    candidates = list(_mounted_drive_roots())
    for key in ("USERPROFILE", "HOME", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP",
                "ProgramData", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        value = env.get(key)
        if value:
            candidates.append(value)
    roots = []
    markers = []
    for value in candidates:
        if not value:
            continue
        path = os.path.abspath(value)
        marker = os.path.normcase(path).rstrip("\\/")
        if not marker or any(marker == root or marker.startswith(root.rstrip("\\/") + os.sep)
                             for root in markers):
            continue
        roots.append(path)
        markers.append(marker)
    return roots


def find_stray_dirs(roots, max_depth=3):
    """列出隔离目录、目录/文件 .migrate-bak。只查找，不删除。"""
    found = []
    seen = set()
    for root in roots or []:
        if (not root or not os.path.isdir(root) or os.path.islink(root)
                or safepath.is_reparse_point(root)):
            continue
        base = os.path.abspath(root)
        base_depth = base.rstrip(os.sep).count(os.sep)
        for dirpath, dirnames, _filenames in os.walk(base):
            depth = dirpath.rstrip(os.sep).count(os.sep) - base_depth
            if max_depth is not None and depth >= max_depth:
                dirnames[:] = []
                continue
            kept = []
            for name in dirnames:
                path = os.path.join(dirpath, name)
                if _is_stray_name(name):
                    marker = os.path.abspath(path)
                    if marker not in seen:
                        seen.add(marker)
                        found.append(path)
                elif not os.path.islink(path) and not safepath.is_reparse_point(path):
                    kept.append(name)
            dirnames[:] = kept
            for name in _filenames:
                if not _is_stray_name(name):
                    continue
                path = os.path.join(dirpath, name)
                marker = os.path.abspath(path)
                if marker not in seen:
                    seen.add(marker)
                    found.append(path)
    return found


def partial_report(backup="", remaining=(), quarantine=(), errors=()):
    """把未完成的结果写成可读说明。"""
    lines = []
    if backup:
        lines.append("备份位置：")
        lines.append(str(backup))
    if remaining:
        lines.append("遗留路径：")
        lines.extend(str(item) for item in remaining)
    if quarantine:
        lines.append("隔离目录（不会自动删除）：")
        lines.extend(str(item) for item in quarantine)
    if errors:
        lines.append("未能安全删除：")
        lines.extend(str(item) for item in errors)
    return "\n".join(lines)


def open_folder(path: str) -> bool:
    """在资源管理器中打开目录；传入文件时定位到该文件。"""
    if not path:
        return False
    folder = path if os.path.isdir(path) else os.path.dirname(path)
    if not folder or not os.path.isdir(folder):
        return False
    if os.name == "nt" and hasattr(os, "startfile"):
        if os.path.isfile(path):
            subprocess.Popen(["explorer.exe", "/select,", os.path.normpath(path)],
                             creationflags=CREATE_NO_WINDOW)
        else:
            os.startfile(folder)  # noqa: windows-only
        return True
    return False


def _hash_fd(fd) -> str:
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        block = os.read(fd, 1024 * 1024)
        if not block:
            break
        digest.update(block)
    _note_full_read(os.fstat(fd))
    return digest.hexdigest()


def _fd_content_holds(fd, snap, expected_hash: str) -> bool:
    """句柄上的快照没变就不再读一遍。变了才重算摘要。"""
    latest = os.fstat(fd)
    if _identity_tuple(latest) == snap:
        return True
    if _hash_fd(fd) != expected_hash:
        return False
    return _identity_tuple(os.fstat(fd)) == _identity_tuple(latest)


def _open_parent_dirfd(parent: str):
    """从根目录逐级 O_NOFOLLOW 打开父目录，返回 dirfd。调用方负责关闭。"""
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    absolute = os.path.abspath(parent)
    parts = [part for part in absolute.split(os.sep) if part]
    dirfd = os.open(os.sep, flags)
    try:
        for part in parts:
            nxt = os.open(part, flags, dir_fd=dirfd)
            os.close(dirfd)
            dirfd = nxt
            if not stat.S_ISDIR(os.fstat(dirfd).st_mode):
                raise OSError("父目录不是普通目录")
        owned = dirfd
        dirfd = None
        return owned
    finally:
        if dirfd is not None:
            os.close(dirfd)


def _read_fd(fd) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks = []
    while True:
        block = os.read(fd, 1024 * 1024)
        if not block:
            break
        chunks.append(block)
    _note_full_read(os.fstat(fd))
    return b"".join(chunks)


def _write_exclusive(path: str, data: bytes) -> str:
    """用 O_CREAT|O_EXCL 把内容写回。原名被占用时改用 .migrate-recovered。"""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    for candidate in (path, path + ".migrate-recovered"):
        try:
            out = os.open(candidate, flags, 0o600)
        except FileExistsError:
            continue
        except OSError:
            continue
        try:
            view = memoryview(data)
            while view:
                try:
                    written = os.write(out, view)
                except InterruptedError:
                    continue
                if written <= 0 or written > len(view):
                    raise OSError("恢复文件写入不完整")
                view = view[written:]
            if os.fstat(out).st_size != len(data):
                raise OSError("恢复文件长度不符")
            os.fsync(out)
            return candidate
        except OSError:
            if os.name == "nt":
                try:
                    safepath.unlink_regular(
                        candidate, [os.path.dirname(candidate) or "."])
                except OSError:
                    pass
            else:
                parent_fd = None
                try:
                    parent_fd = _open_parent_dirfd(os.path.dirname(candidate) or ".")
                    safepath._unlink_name_if_inode(
                        os.path.basename(candidate), parent_fd, os.fstat(out), candidate)
                except OSError:
                    # A failed cleanup is still not a successful restoration.
                    pass
                finally:
                    if parent_fd is not None:
                        os.close(parent_fd)
        finally:
            os.close(out)
    return ""


def _verified_unlink(path: str, expected_size: int, expected_hash: str,
                     survivor_check=None, expected_snap=None):
    """打开后核对，再删除。返回 (是否干净删除, 说明)。
    POSIX 上先把目录项移入隔离目录并保留保护硬链接；最终校验通过后才
    删除保护链接。校验失败时把原 inode 放回，不依赖可能短写的内容重建。
    """
    if os.name == "nt":
        return _verified_unlink_windows(
            path, expected_size, expected_hash, survivor_check), ""
    parent = os.path.dirname(path) or "."
    name = os.path.basename(path)
    try:
        dirfd = _open_parent_dirfd(parent)
    except OSError:
        return False, ""
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        try:
            fd = os.open(name, flags, dir_fd=dirfd)
        except OSError:
            return False, ""
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                return False, ""
            if getattr(info, "st_file_attributes", 0) & safepath.FILE_ATTRIBUTE_REPARSE_POINT:
                return False, ""
            if info.st_size != expected_size:
                return False, ""
            if expected_snap is not None:
                # 迁移源已在复制后与目标摘要复核；保留最终哈希作为第二次读取。
                if _identity_tuple(info) != expected_snap:
                    return False, ""
                again = info
            else:
                digest = _hash_fd(fd)
                again = os.fstat(fd)
                if (_identity_tuple(again) != _identity_tuple(info)
                        or digest != expected_hash):
                    return False, ""
            try:
                named = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
            except OSError:
                return False, ""
            if (again.st_dev != info.st_dev or again.st_ino != info.st_ino
                    or again.st_size != expected_size
                    or named.st_dev != info.st_dev or named.st_ino != info.st_ino):
                return False, ""
            fd_snap = _identity_tuple(again)
            if survivor_check is not None:
                try:
                    if not survivor_check():
                        return False, path
                except Exception:
                    return False, path

            final_state = {}

            def validate_captured_file():
                latest = os.fstat(fd)
                latest_mtime = getattr(latest, "st_mtime_ns", latest.st_mtime)
                again_mtime = getattr(again, "st_mtime_ns", again.st_mtime)
                backup_changed = (
                    latest.st_size != expected_size
                    or latest_mtime != again_mtime
                )
                survivor_ok = True
                if survivor_check is not None:
                    try:
                        survivor_ok = bool(survivor_check())
                    except Exception:
                        survivor_ok = False
                final_state["backup_changed"] = backup_changed
                final_state["survivor_ok"] = survivor_ok
                return not backup_changed and survivor_ok

            try:
                safepath._unlink_name_if_inode(
                    name, dirfd, again, os.path.abspath(path),
                    validate=validate_captured_file)
            except OSError as exc:
                detail = str(exc)
                if final_state.get("backup_changed"):
                    detail += "；备份内容在删除窗口发生变化，已保留"
                if final_state.get("survivor_ok") is False:
                    detail += "；目标副本在删除窗口发生变化，备份已保留"
                return False, detail
            post = os.fstat(fd)
            swapped = post.st_nlink != 0
            if expected_snap is not None:
                digest = _hash_fd(fd)
                after_hash = os.fstat(fd)
                changed = (digest != expected_hash
                           or _identity_tuple(after_hash) != _identity_tuple(post))
            else:
                changed = not _fd_content_holds(fd, fd_snap, expected_hash)
            survivor_ok = True
            if survivor_check is not None:
                try:
                    survivor_ok = bool(survivor_check())
                except Exception:
                    survivor_ok = False
            if not swapped and not changed and survivor_ok:
                return True, ""
            recovered = (_write_exclusive(path, _read_fd(fd))
                         if changed or not survivor_ok else "")
            detail = recovered
            if swapped:
                note = "删除后链接数不为 0，可能删到了别的目录项"
                detail = (detail + "；" + note) if detail else note
            if not survivor_ok:
                note = "目标副本在删除核验期间发生变化，备份已保留"
                detail = (detail + "；" + note) if detail else note
            return False, detail or path
        finally:
            os.close(fd)
    finally:
        os.close(dirfd)


def _verified_unlink_windows(path: str, expected_size: int, expected_hash: str,
                             survivor_check=None) -> bool:
    """不共享写权限地打开，核对句柄后用 FILE_DISPOSITION_INFO 删除。"""
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.restype = ctypes.c_void_p
    kernel.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    kernel.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel.ReadFile.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
    ]
    kernel.ReadFile.restype = wintypes.BOOL
    kernel.SetFilePointerEx.argtypes = [
        wintypes.HANDLE, ctypes.c_longlong, ctypes.c_void_p, wintypes.DWORD,
    ]
    kernel.SetFilePointerEx.restype = wintypes.BOOL
    kernel.SetFileInformationByHandle.argtypes = [
        wintypes.HANDLE, ctypes.c_uint, ctypes.c_void_p, wintypes.DWORD,
    ]
    kernel.SetFileInformationByHandle.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    delete_access = 0x00010000
    generic_read = 0x80000000
    share_read = 0x1  # 不包含 FILE_SHARE_WRITE，哈希到删除期间拒绝别人写入
    open_existing = 3
    flag = 0x00200000  # FILE_FLAG_OPEN_REPARSE_POINT
    handle = kernel.CreateFileW(
        str(path), delete_access | generic_read, share_read, None,
        open_existing, flag, None)
    invalid = ctypes.c_void_p(-1).value
    if not handle or handle in (invalid, -1):
        return False

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

    def _identity(info):
        size = (info.nFileSizeHigh << 32) | info.nFileSizeLow
        file_id = (info.nFileIndexHigh << 32) | info.nFileIndexLow
        return info.dwFileAttributes, info.dwVolumeSerialNumber, file_id, size

    try:
        info = _ByHandle()
        if not kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
            return False
        attributes, volume, file_id, size = _identity(info)
        if attributes & safepath.FILE_ATTRIBUTE_REPARSE_POINT or size != expected_size:
            return False
        if not kernel.SetFilePointerEx(handle, 0, None, 0):
            return False
        digest = hashlib.sha256()
        if size:
            buf = ctypes.create_string_buffer(1024 * 1024)
            pending = size
            got = wintypes.DWORD(0)
            while pending > 0:
                chunk = min(len(buf), pending)
                if not kernel.ReadFile(handle, buf, chunk, ctypes.byref(got), None) or not got.value:
                    return False
                digest.update(buf.raw[:got.value])
                pending -= got.value
        _note_full_read(info)
        if digest.hexdigest() != expected_hash:
            return False
        again = _ByHandle()
        if not kernel.GetFileInformationByHandle(handle, ctypes.byref(again)):
            return False
        attributes2, volume2, file_id2, size2 = _identity(again)
        if (attributes2 & safepath.FILE_ATTRIBUTE_REPARSE_POINT
                or volume2 != volume or file_id2 != file_id or size2 != expected_size):
            return False
        if survivor_check is not None:
            try:
                if not survivor_check():
                    return False
            except Exception:
                return False
        mark = _Disposition(True)
        if not kernel.SetFileInformationByHandle(handle, 4, ctypes.byref(mark), ctypes.sizeof(mark)):
            return False
        return True
    finally:
        kernel.CloseHandle(handle)


def _rmdir_if_empty(path: str) -> bool:
    """只对空目录调用 rmdir，不递归删除里面的文件。"""
    if os.path.islink(path) or safepath.is_reparse_point(path):
        return False
    try:
        os.rmdir(path)
        return True
    except OSError:
        return False


def _directories_deepest_first(root: str):
    dirs = []
    stack = [root]
    while stack:
        current = stack.pop()
        dirs.append(current)
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                    except OSError:
                        continue
        except OSError:
            continue
    dirs.sort(key=len, reverse=True)
    return dirs


def _list_remaining(root: str):
    if not root or not os.path.lexists(root):
        return []
    if os.path.islink(root) or not os.path.isdir(root):
        return [root]
    found = []
    stack = [os.path.abspath(root)]
    while stack:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                    found.append(entry.path)
                else:
                    stack.append(entry.path)
            except OSError:
                found.append(entry.path)
    return found


def _release_manifest(backup: str, manifest: dict, survivor=None,
                      survivor_snaps=None, survivor_marks=None,
                      backup_snaps=None):
    """只删除清单里、且句柄核对通过的文件。其余留下。"""
    notes = []
    for rel, mark in (manifest or {}).items():
        size, _mtime, digest = mark
        survivor_check = None
        if survivor:
            survivor_path = os.path.join(survivor, rel)
            expected = (survivor_marks or {}).get(rel, (size, digest))
            snap = (survivor_snaps or {}).get(rel)
            survivor_check = lambda p=survivor_path, s=snap, e=expected: _survivor_still(p, s, e)
        clean, detail = _verified_unlink(
            os.path.join(backup, rel), size, digest,
            survivor_check=survivor_check,
            expected_snap=(backup_snaps or {}).get(rel))
        if not clean and detail:
            notes.append(detail)
    if os.path.isdir(backup) and not os.path.islink(backup):
        for directory in _directories_deepest_first(backup):
            _rmdir_if_empty(directory)
    remaining = _list_remaining(backup)
    for note in notes:
        if note not in remaining:
            remaining.append(note)
    return remaining


def file_inventory(root: str) -> dict:
    """root 下普通文件的相对路径指纹。不进入链接。"""
    found, snaps = _inventory_verified(root)
    file_inventory.snaps = snaps
    file_inventory.snaps_root = os.path.abspath(root) if root else ""
    return found


def inventory_covers(have: dict, need: dict) -> bool:
    """have 是否包含 need 里的每一份，且大小和摘要都相同。"""
    for rel, mark in (need or {}).items():
        if not mark or have.get(rel) != mark:
            return False
    return True


def _drop_covered(root: str, survivor: str):
    """只删除 root 里、且 survivor 仍有相同内容的文件。返回留下的路径。

    备份文件不按路径再哈希，只在打开的句柄上读一次。存活副本用核对时的快照。
    """
    if not root or os.path.islink(root) or safepath.is_reparse_point(root) or not os.path.isdir(root):
        return _list_remaining(root)
    have = file_inventory(survivor)
    snaps = {}
    if getattr(file_inventory, "snaps_root", None) == os.path.abspath(survivor):
        snaps = dict(getattr(file_inventory, "snaps", {}) or {})
    covered = {}
    base = os.path.abspath(root)
    for entry in utils.walk_files(base):
        rel = os.path.relpath(entry.path, base)
        expected = have.get(rel)
        if not expected:
            continue
        try:
            info = os.lstat(entry.path)
        except OSError:
            continue
        size, digest = expected
        if info.st_size != size or not stat.S_ISREG(info.st_mode):
            continue
        mtime = getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000))
        covered[rel] = (size, mtime, digest)
    return _release_manifest(root, covered, survivor=survivor,
                             survivor_snaps=snaps, survivor_marks=have)


def _unlink_link_only(path: str) -> bool:
    """只在目录项仍是符号链接时删除链接本身。"""
    parent = os.path.dirname(path) or "."
    name = os.path.basename(path)
    if os.name != "nt":
        try:
            dirfd = _open_parent_dirfd(parent)
        except OSError:
            return False
        try:
            try:
                info = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
            except OSError:
                return False
            if not stat.S_ISLNK(info.st_mode):
                return False
            try:
                safepath._unlink_name_if_inode(
                    name, dirfd, info, os.path.abspath(path), expected_kind="symlink")
                return True
            except OSError:
                return False
        finally:
            os.close(dirfd)
    try:
        dirfd = _open_parent_dirfd(parent)
    except OSError:
        return False
    try:
        try:
            info = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
        except OSError:
            return False
        if not stat.S_ISLNK(info.st_mode):
            return False
        os.unlink(name, dir_fd=dirfd)
        return True
    finally:
        os.close(dirfd)


def _rollback_to_source(src: str, dest: str):
    """把目标副本拷回源位置。只删除源里已经核对过的那一份。"""
    if safepath.is_reparse_point(src):
        try:
            os.rmdir(src)
        except OSError as exc:
            raise MigrateError(f"无法移除联接，目标副本已保留：{exc}")
    os.makedirs(src, exist_ok=True)
    needed = file_inventory(dest)
    _robocopy(dest, src, move=False)
    if not inventory_covers(file_inventory(src), needed):
        raise MigrateError("还原校验失败，目标位置的副本已保留，没有删除唯一的一份")
    remaining = _drop_covered(dest, src) if os.path.isdir(dest) else _list_remaining(dest)
    if remaining:
        return MigrateResult(src, dest, status="partial", backup=dest, remaining=remaining)
    return MigrateResult(src, dest, status="ok")


def migrate(src: str, dest_root: str, log=lambda _message: None):
    """把 src 迁移到 dest_root 下并建立联接。返回 MigrateResult。"""
    src, dest = validate(src, dest_root)

    log(f"复制 {src}")
    log(f"  → {dest}")
    source_sizes, src_snaps = _inventory_metadata(src)
    rc = _robocopy(src, dest, move=False)
    dest_marks, dest_snaps = _inventory_verified(dest)
    if rc >= 8 or not _inventory_covers_sizes(dest_marks, source_sizes):
        remaining = []
        if os.path.isdir(dest) and not os.path.islink(dest):
            remaining = _drop_covered(dest, src)
        if remaining:
            return MigrateResult(src, dest, status="partial", backup=dest, remaining=remaining)
        raise MigrateError(f"复制校验失败（robocopy 返回 {rc}），源目录保持原样")

    if (not _tree_metadata_still(src, source_sizes, src_snaps)
            or not _tree_still_verified(src, dest_marks, src_snaps)):
        raise MigrateError("源目录在复制后发生变化，源文件和目标副本都已保留")
    fresh_manifest = {}
    for rel, size in source_sizes.items():
        snap = src_snaps.get(rel) or ()
        mtime = snap[3] if len(snap) > 3 else 0
        fresh_manifest[rel] = (size, mtime, dest_marks[rel][1])

    backup = src.rstrip("\\/") + ".migrate-bak"
    if os.path.lexists(backup):
        raise MigrateError(f"备份位置已存在，已停止：{backup}")
    os.rename(src, backup)
    try:
        create_junction(src, dest)
        if not junction_works(src, dest):
            raise MigrateError("联接校验失败")
    except Exception as exc:
        log("建立联接失败，正在把源目录还原…")
        blocked = _restore_renamed_source(src, backup)
        if blocked:
            return MigrateResult(src, dest, status="partial", backup=backup, remaining=blocked)
        dest_left = []
        if os.path.isdir(dest) and not os.path.islink(dest):
            dest_left = _drop_covered(dest, src)
        if dest_left:
            return MigrateResult(src, dest, status="partial", backup=dest, remaining=dest_left)
        raise MigrateError(
            "建立联接失败，源目录已还原，数据未丢失") from exc
    remaining = _release_manifest(
        backup, fresh_manifest, survivor=dest,
        survivor_snaps=dest_snaps, survivor_marks=dest_marks,
        backup_snaps=src_snaps)
    if remaining:
        log(f"备份里还有未删除的内容：{backup}")
        return MigrateResult(src, dest, status="partial", backup=backup, remaining=remaining)
    log(f"已建立联接：{src} → {dest}")
    return MigrateResult(src, dest, status="ok")


def _restore_renamed_source(src: str, backup: str):
    """联接失败时把改名的源目录放回原路径。腾不出原路径时返回留下的文件。"""
    if not os.path.lexists(backup):
        raise MigrateError(f"找不到备份，无法还原：{backup}")
    if os.path.lexists(src):
        if os.path.islink(src):
            if not _unlink_link_only(src):
                return _list_remaining(src) or [src]
        elif os.path.isdir(src):
            if _list_remaining(src):
                return _list_remaining(src)
            if not _rmdir_if_empty(src):
                return _list_remaining(src) or [src]
        else:
            return [src]
    os.rename(backup, src)
    return []


def undo(src: str, log=lambda _message: None):
    """撤销迁移：删除联接并把数据搬回原位置。"""
    src = os.path.abspath(src)
    if not is_junction(src):
        raise MigrateError("该目录不是联接，无法撤销")
    target = junction_target(src)
    if not target or not os.path.isdir(target):
        raise MigrateError("找不到联接指向的目录，无法撤销")

    log(f"移除联接 {src}")
    try:
        os.rmdir(src)
    except OSError as exc:
        raise MigrateError(f"移除联接失败：{exc}")

    log(f"搬回 {target}")
    log(f"  → {src}")
    needed = file_inventory(target)
    rc = _robocopy(target, src, move=False)
    if rc >= 8 or not inventory_covers(file_inventory(src), needed):
        raise MigrateError(
            "搬回校验失败，目标副本已保留，没有删除唯一的一份。"
            f"请检查原位置 {src} 和目标 {target}")

    remaining = _drop_covered(target, src)
    if remaining:
        log(f"目标里还有未删除的内容：{target}")
        return MigrateResult(src, target, status="partial", backup=target, remaining=remaining)
    log(f"已还原：{src}")
    return MigrateResult(src, target, status="ok")


_UNINSTALL_KEYS = (
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
)


def _open_registry():
    try:
        import winreg
    except ImportError:
        return None
    return winreg


def _enum_values(reg, key):
    values = {}
    index = 0
    while True:
        try:
            name, data, _typ = reg.EnumValue(key, index)
        except OSError:
            break
        values[name] = data
        index += 1
    return values


def _first_exe(text):
    text = str(text or "").strip()
    if not text:
        return ""
    if text.startswith('"'):
        end = text.find('"', 1)
        if end > 1:
            return text[1:end]
    return text.split(" ")[0].strip('"')


def _location_from_values(values, exists):
    location = str(values.get("InstallLocation") or "").strip().strip('"')
    if location and exists(location):
        return location
    icon = str(values.get("DisplayIcon") or "").strip().strip('"')
    if icon:
        icon = icon.split(",")[0].strip().strip('"')
        folder = os.path.dirname(icon)
        if folder and exists(folder):
            return folder
    exe = _first_exe(values.get("UninstallString"))
    folder = os.path.dirname(exe) if exe else ""
    if folder and exists(folder):
        return folder
    return ""


def discover_installed(reg=None, environ=None, exists=None):
    """从卸载注册表发现已安装软件。不提供文档、桌面、下载和系统目录。"""
    environ = os.environ if environ is None else environ
    exists = os.path.isdir if exists is None else exists
    if reg is None:
        reg = _open_registry()
    if reg is None:
        return []
    hives = {
        "HKLM": reg.HKEY_LOCAL_MACHINE,
        "HKCU": reg.HKEY_CURRENT_USER,
    }
    seen = set()
    found = []
    for hive_name, subpath in _UNINSTALL_KEYS:
        try:
            root = reg.OpenKey(hives[hive_name], subpath)
        except OSError:
            continue
        index = 0
        while True:
            try:
                name = reg.EnumKey(root, index)
            except OSError:
                break
            index += 1
            try:
                sub = reg.OpenKey(root, name)
            except OSError:
                continue
            values = _enum_values(reg, sub)
            closer = getattr(sub, "Close", None)
            if closer:
                closer()
            display = str(values.get("DisplayName") or "").strip()
            if not display:
                continue
            if str(values.get("SystemComponent") or "") in ("1", "0x1"):
                continue
            try:
                if int(values.get("SystemComponent") or 0) == 1:
                    continue
            except (TypeError, ValueError):
                pass
            if values.get("ReleaseType") or values.get("ParentKeyName"):
                continue
            location = _location_from_values(values, exists)
            if not location:
                continue
            if safepath.migration_forbidden(location, environ):
                continue
            marker = safepath.normalize(location).lower()
            if marker in seen:
                continue
            seen.add(marker)
            try:
                size = int(values.get("EstimatedSize") or 0) * 1024
            except (TypeError, ValueError):
                size = 0
            found.append({
                "name": display,
                "path": location,
                "size": max(size, 0),
                "publisher": str(values.get("Publisher") or ""),
            })
        closer = getattr(root, "Close", None)
        if closer:
            closer()
    found.sort(key=lambda item: item["size"], reverse=True)
    return found


def candidate_folders():
    """软件搬家候选：只来自卸载注册表，不含文档/桌面/下载。"""
    return [item["path"] for item in discover_installed()]


def _same_file_size(src: str, dest: str) -> bool:
    try:
        return os.path.getsize(src) == os.path.getsize(dest)
    except OSError:
        return False


def _link_file(dest: str, src: str, linker=None):
    if linker is not None:
        linker(dest, src)
        return
    os.symlink(dest, src)


def _restore_file(dest: str, src: str) -> bool:
    """链接失败时把文件拷回原处并删掉目标副本。"""
    try:
        if os.path.lexists(src):
            os.remove(src)
        shutil.copy2(dest, src)
        if _same_file_size(dest, src):
            os.remove(dest)
            return True
    except OSError:
        return False
    return False


def migrate_file(src: str, dest_root: str, log=lambda _message: None, linker=None):
    """把单个大文件搬到其他盘，并在原路径留下符号链接。

    复制校验失败时源文件不动。链接建不起来时把文件拷回原处。
    """
    src = os.path.abspath(src)
    dest_root = os.path.abspath(dest_root)
    if safepath.is_system_path(src):
        raise MigrateError("系统文件不能搬家")
    if not os.path.isfile(src):
        raise MigrateError("源文件不存在")
    if not _drive_of(dest_root):
        raise MigrateError("目标位置需要指定盘符")
    if _drive_of(src) == _drive_of(dest_root):
        raise MigrateError("目标盘必须与源文件所在盘不同")
    os.makedirs(dest_root, exist_ok=True)
    dest = os.path.join(dest_root, os.path.basename(src))
    if os.path.exists(dest):
        raise MigrateError(f"目标已存在：{dest}")

    log(f"复制 {src}")
    log(f"  → {dest}")
    before = _fingerprint(src)
    shutil.copy2(src, dest)
    source_now = _fingerprint(src)
    copied = _fingerprint(dest)
    if source_now != before:
        raise MigrateError("源文件在复制后已变化，源文件和目标副本都已保留")
    if not _same_file_size(src, dest) or copied is None or copied != source_now:
        try:
            os.remove(dest)
        except OSError:
            pass
        raise MigrateError("复制校验失败，已取消，源文件未改动")

    again = _fingerprint(src)
    if again != copied:
        raise MigrateError("源文件在删除前已变化，源文件和目标副本都已保留")
    backup = src + ".migrate-bak"
    if os.path.lexists(backup):
        raise MigrateError(f"备份位置已存在，已停止：{backup}")
    os.rename(src, backup)
    clean, detail = _verified_unlink(backup, copied[0], copied[1])
    if not clean:
        remaining = []
        for candidate in (backup, backup + ".migrate-recovered"):
            if os.path.lexists(candidate):
                remaining.append(candidate)
        if detail and detail not in remaining:
            remaining.append(detail)
        if not remaining:
            remaining = [detail or backup]
        return MigrateResult(
            src, dest, status="partial", backup=backup, remaining=tuple(remaining))

    try:
        _link_file(dest, src, linker)
    except Exception as exc:
        if _restore_file(dest, src):
            raise MigrateError("无法在原位置建立链接，已还原源文件") from exc
        raise MigrateError(f"链接失败且无法还原，文件仍在：{dest}") from exc
    log(f"已搬家：{src} → {dest}")
    return MigrateResult(src, dest, status="ok")
