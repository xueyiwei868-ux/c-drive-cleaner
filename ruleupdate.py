"""规则云端更新：只接受 http/https，并且拒绝远程下发的命令。"""
import json
import os
import re
import shutil
import tempfile
import urllib.parse
import urllib.request

import safepath

BASE = os.path.dirname(os.path.abspath(__file__))
RULES_PATH = os.path.join(BASE, "rules.json")
CONFIG_PATH = os.path.join(BASE, "rules_update.json")

MAX_BYTES = 1_000_000
MAX_RULES = 200
_KEY_RE = re.compile(r"^[A-Za-z0-9_\-]{1,80}$")
_TIERS = {"conservative", "standard", "deep"}


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        error = validate_url(newurl)
        if error:
            raise urllib.error.URLError(error)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def load_config():
    try:
        with open(CONFIG_PATH, encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return {}


def validate_url(url) -> str:
    """合法时返回空串。远程规则只允许 https，避免被篡改。"""
    if not url or not isinstance(url, str):
        return "未配置规则更新地址（在 rules_update.json 里填写 url）"
    parsed = urllib.parse.urlparse(url.strip())
    if parsed.scheme != "https":
        return "规则地址只允许 https"
    if not parsed.netloc or any(char in parsed.netloc for char in " \t\r\n"):
        return "规则地址无效"
    return ""


_CACHE_PARTS = {
    "temp", "tmp", "cache", "caches", "log", "logs",
    "code cache", "gpucache", "gpu cache", "htmlcache",
}
_LIBRARY_PARTS = {
    "documents", "desktop", "downloads", "my documents",
    "文档", "桌面", "下载",
}


def remote_target_allowed(path: str, environ=None) -> str:
    """远程规则只能指向用户临时目录或 AppData 下的已知缓存。返回错误说明。"""
    if not isinstance(path, str) or not path.strip():
        return "路径为空"
    if len(path) > 500 or any(ord(char) < 32 for char in path):
        return "路径含有非法字符"
    syntax = safepath.path_syntax_error(path)
    if syntax:
        return syntax
    lowered = [part.lower() for part in safepath._path_parts(path)]
    if any(part in _LIBRARY_PARTS for part in lowered):
        return "远程规则不能指向文档、桌面或下载"
    if safepath.is_user_library(path, environ):
        return "远程规则不能指向文档、桌面或下载"
    name = os.path.basename(str(path).replace("/", "\\")).lower()
    if name in safepath.PASSWORD_FILENAMES or "login data" in name:
        return "远程规则不能删除浏览器密码库"
    if not safepath.under_remote_allowlist(path, environ):
        return "远程规则只能指向用户临时目录或已知缓存目录"
    return ""


def _bad_path(path) -> str:
    return remote_target_allowed(path)


def validate_remote_rule(item) -> str:
    """合法时返回空串。远程规则只能是文件清理，不能带命令。"""
    if not isinstance(item, dict):
        return "规则格式不正确"
    key = item.get("key")
    if not isinstance(key, str) or not _KEY_RE.match(key):
        return "规则 key 不合法"
    kind = item.get("kind", "files")
    if kind != "files":
        return "远程规则不允许 command 或其他可执行类型"
    command = item.get("command")
    if command:
        return "远程规则不允许携带命令"
    tier = item.get("tier", "standard")
    if tier not in _TIERS:
        return "风险档位不合法"
    for field in ("paths", "glob_dirs", "patterns"):
        value = item.get(field, [])
        if value is None:
            continue
        if not isinstance(value, list) or len(value) > 80:
            return f"{field} 格式不正确"
        for entry in value:
            if field == "patterns":
                if not isinstance(entry, str) or len(entry) > 80:
                    return "匹配模式不合法"
                continue
            reason = _bad_path(entry)
            if reason:
                return reason
    for field in ("name", "describe", "warning", "note"):
        value = item.get(field, "")
        if value and (not isinstance(value, str) or len(value) > 400):
            return f"{field} 过长或类型不对"
    return ""


def merge_remote(local, remote):
    """合并远程规则。返回 (新文档, 新增条数, 拒绝条数, 错误)。"""
    if not isinstance(remote, dict) or not isinstance(remote.get("categories"), list):
        return local, 0, 0, "远程规则格式不正确"
    categories = remote.get("categories") or []
    if len(categories) > MAX_RULES:
        return local, 0, 0, "远程规则条数过多"
    if not isinstance(local, dict):
        local = {"version": 1, "categories": []}
    local_cats = list(local.get("categories") or [])
    existing = {item.get("key") for item in local_cats if isinstance(item, dict)}
    added = 0
    rejected = 0
    for item in categories:
        reason = validate_remote_rule(item)
        if reason:
            rejected += 1
            continue
        key = item.get("key")
        if key in existing:
            continue
        cleaned = dict(item)
        cleaned["kind"] = "files"
        cleaned.pop("command", None)
        local_cats.append(cleaned)
        existing.add(key)
        added += 1
    merged = dict(local)
    merged["categories"] = local_cats
    return merged, added, rejected, ""


def _write_atomic(path, document):
    """先写入临时文件并 fsync，再替换。失败时旧文件保持不动。"""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".rules-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(document, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if os.path.exists(path):
            shutil.copy2(path, path + ".bak")
        os.replace(tmp, path)
        tmp = ""
    finally:
        if tmp and os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def update_rules(url=None, opener=None):
    """返回 (新增条数, 总条数, 错误信息或空串)。"""
    config = load_config()
    url = url or config.get("url") or ""
    error = validate_url(url)
    if error:
        return 0, 0, error
    try:
        if opener is None:
            opener = urllib.request.build_opener(_SafeRedirect)
        with opener.open(url, timeout=15) as response:
            payload = response.read(MAX_BYTES + 1)
    except Exception as exc:
        return 0, 0, f"下载失败：{exc}"
    if len(payload) > MAX_BYTES:
        return 0, 0, "远程规则过大，已拒绝"
    try:
        remote = json.loads(payload.decode("utf-8"))
    except Exception:
        return 0, 0, "远程规则不是合法的 JSON"

    try:
        with open(RULES_PATH, encoding="utf-8") as handle:
            local = json.load(handle)
    except Exception:
        local = {"version": 1, "categories": []}

    merged, added, rejected, error = merge_remote(local, remote)
    if error:
        return 0, 0, error
    if added == 0 and rejected:
        return 0, len(merged.get("categories") or []), f"没有可合并的规则，已拒绝 {rejected} 条"
    try:
        _write_atomic(RULES_PATH, merged)
    except Exception as exc:
        return 0, 0, f"写入失败：{exc}"
    message = ""
    if rejected:
        message = f"另有 {rejected} 条因含命令或路径不合法被拒绝"
    return added, len(merged.get("categories") or []), message
