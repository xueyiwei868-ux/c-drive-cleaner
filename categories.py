"""清理项定义。所有路径均为白名单，工具只会操作这里列出的位置。"""
import glob
import json
import os
from dataclasses import dataclass, field

from utils import current_user_sid, fixed_drives

CONSERVATIVE = "conservative"
STANDARD = "standard"
DEEP = "deep"

TIER_LABEL = {CONSERVATIVE: "保守", STANDARD: "标准", DEEP: "深度"}


@dataclass
class Category:
    key: str
    name: str
    tier: str
    kind: str                       # files / recyclebin / command
    describe: str
    paths: list = field(default_factory=list)
    patterns: tuple = ("*",)
    command: list = field(default_factory=list)
    note: str = ""
    warning: str = ""
    requires_confirm: bool = False
    prune_dirs: bool = False
    size_fn: object = None
    untrusted: bool = False


def _env(*parts) -> str:
    return os.path.expandvars(os.path.join(*parts))


def _existing(paths):
    seen, out = set(), []
    for path in paths:
        if not path:
            continue
        path = os.path.normpath(path)
        key = os.path.normcase(path)
        if key in seen or not os.path.exists(path):
            continue
        seen.add(key)
        out.append(path)
    return out


def _glob_dirs(pattern):
    return [p for p in glob.glob(pattern) if os.path.isdir(p)]


def _expand_rule_paths(items):
    """展开规则里的 %变量% 与通配符，返回存在的路径。"""
    out, seen = [], set()
    for raw in items or []:
        if not raw:
            continue
        expanded = os.path.expandvars(raw)
        matches = glob.glob(expanded) if ("*" in expanded or "?" in expanded) else [expanded]
        for match in matches:
            if not os.path.exists(match):
                continue
            key = os.path.normcase(os.path.normpath(match))
            if key in seen:
                continue
            seen.add(key)
            out.append(os.path.normpath(match))
    return out


def _load_external_rules():
    """从同目录的 rules.json 读取可扩展清理项（规则外置化）。"""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules.json")
    if not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except Exception:
        return []
    tiers = {"conservative": CONSERVATIVE, "standard": STANDARD, "deep": DEEP}
    cats = []
    for item in data.get("categories", []):
        key = item.get("key")
        if not key:
            continue
        paths = _expand_rule_paths(item.get("paths", []))
        for path in _expand_rule_paths(item.get("glob_dirs", [])):
            if os.path.isdir(path):
                paths.append(path)
        command = [os.path.expandvars(part) for part in item.get("command", [])]
        if not paths and not command:
            continue
        cats.append(Category(
            key=key,
            name=item.get("name", key),
            tier=tiers.get(item.get("tier", "standard"), STANDARD),
            kind=item.get("kind", "files"),
            describe=item.get("describe", ""),
            paths=paths,
            patterns=tuple(item.get("patterns", ["*"])),
            command=command,
            note=item.get("note", ""),
            warning=item.get("warning", ""),
            requires_confirm=bool(item.get("requires_confirm", False)),
            prune_dirs=bool(item.get("prune_dirs", False)),
            untrusted=True,
        ))
    return cats


def _other_recycle_bins():
    """其他账户（或旧系统）留下的回收站目录。"""
    sid = current_user_sid().upper()
    found = []
    for drive in fixed_drives():
        root = os.path.join(drive, "$Recycle.Bin")
        if not os.path.isdir(root):
            continue
        try:
            names = os.listdir(root)
        except OSError:
            continue
        for name in names:
            if name.upper() in ("S-1-5-18", sid):
                continue
            path = os.path.join(root, name)
            if os.path.isdir(path):
                found.append(path)
    return found


def _file_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


_CHROMIUM_CACHE_SUBDIRS = (
    "Cache",
    "Code Cache",
    "GPUCache",
    "DawnCache",
    "DawnGraphiteCache",
    "DawnWebGPUCache",
    os.path.join("Service Worker", "CacheStorage"),
)


def _profile_caches(user_data):
    """取 Chromium 系 User Data 下每个配置文件的缓存子目录。"""
    found = []
    if not os.path.isdir(user_data):
        return found
    for profile in glob.glob(os.path.join(user_data, "*")):
        if not os.path.isdir(profile):
            continue
        for sub in _CHROMIUM_CACHE_SUBDIRS:
            path = os.path.join(profile, sub)
            if os.path.isdir(path):
                found.append(path)
    return found


def _chromium_cache_dirs():
    base = os.environ.get("LOCALAPPDATA", "")
    if not base:
        return []
    vendors = [
        ("Google", "Chrome"),
        ("Microsoft", "Edge"),
        ("BraveSoftware", "Brave-Browser"),
        ("Chromium",),
    ]
    found = []
    for vendor in vendors:
        user_data = os.path.join(base, *vendor, "User Data")
        found.extend(_profile_caches(user_data))
        for sub in ("GrShaderCache", "ShaderCache"):
            path = os.path.join(user_data, sub)
            if os.path.isdir(path):
                found.append(path)
    return found


def _firefox_cache_dirs():
    base = os.environ.get("LOCALAPPDATA", "")
    root = os.path.join(base, "Mozilla", "Firefox", "Profiles")
    return [p for p in glob.glob(os.path.join(root, "*", "cache2")) if os.path.isdir(p)]


def _extra_browser_cache_dirs():
    """夸克、比特、360、QQ、搜狗等 Chromium 内核浏览器的缓存目录。"""
    local = os.environ.get("LOCALAPPDATA", "")
    roaming = os.environ.get("APPDATA", "")
    found = []

    quark = os.path.join(local, "Quark", "User Data")
    found.extend(_profile_caches(quark))
    for profile in glob.glob(os.path.join(quark, "*")):
        path = os.path.join(profile, "remote_resource_cache")
        if os.path.isdir(path):
            found.append(path)
    for sub in ("GrShaderCache", "ShaderCache", "GraphiteDawnCache"):
        path = os.path.join(quark, sub)
        if os.path.isdir(path):
            found.append(path)

    bit = os.path.join(roaming, "BitBrowser")
    for sub in ("Cache", "Code Cache", "GPUCache", "DawnGraphiteCache",
                "DawnWebGPUCache"):
        path = os.path.join(bit, sub)
        if os.path.isdir(path):
            found.append(path)

    for user_data in (
        os.path.join(local, "360Chrome", "Chrome", "User Data"),
        os.path.join(local, "360ChromeX", "Chrome", "User Data"),
        os.path.join(roaming, "360se6", "User Data"),
        os.path.join(local, "360se6", "User Data"),
        os.path.join(local, "Tencent", "QQBrowser", "User Data"),
        os.path.join(roaming, "Tencent", "QQBrowser", "User Data"),
        os.path.join(local, "SogouExplorer", "User Data"),
        os.path.join(roaming, "SogouExplorer", "User Data"),
        os.path.join(local, "Vivaldi", "User Data"),
        os.path.join(local, "Yandex", "YandexBrowser", "User Data"),
        os.path.join(local, "Arc", "User Data"),
    ):
        found.extend(_profile_caches(user_data))

    for opera_root in (os.path.join(roaming, "Opera Software"),
                       os.path.join(local, "Opera Software")):
        opera = os.path.join(opera_root, "Opera Stable")
        for sub in ("Cache", "Code Cache", "GPUCache"):
            path = os.path.join(opera, sub)
            if os.path.isdir(path):
                found.append(path)

    return found


def _dev_cache_dirs():
    local = os.environ.get("LOCALAPPDATA", "")
    user = os.environ.get("USERPROFILE", "")
    return [
        os.path.join(local, "npm-cache"),
        os.path.join(local, "pip", "Cache"),
        os.path.join(local, "Yarn", "Cache"),
        os.path.join(local, "NuGet", "Cache"),
        os.path.join(local, "NuGet", "v3-cache"),
        os.path.join(local, "go-build"),
        os.path.join(user, ".gradle", "caches"),
        os.path.join(user, ".cargo", "registry", "cache"),
        os.path.join(user, ".cache", "puppeteer"),
    ]


def get_categories():
    local = os.environ.get("LOCALAPPDATA", "")
    roaming = os.environ.get("APPDATA", "")
    profile = os.environ.get("USERPROFILE", "")
    programdata = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
    system_drive = os.environ.get("SYSTEMDRIVE", "C:")
    windows = os.environ.get("WINDIR", os.path.join(system_drive, "Windows"))
    temp = os.environ.get("TEMP", "")
    explorer = os.path.join(local, "Microsoft", "Windows", "Explorer")

    cats = []

    cats.append(Category(
        key="user_temp",
        name="用户临时文件",
        tier=CONSERVATIVE,
        kind="files",
        describe="当前用户 Temp 目录下的临时文件",
        paths=_existing([temp, os.path.join(local, "Temp")]),
        prune_dirs=True,
    ))

    cats.append(Category(
        key="win_temp",
        name="系统临时文件",
        tier=CONSERVATIVE,
        kind="files",
        describe="Windows\\Temp 下的临时文件",
        paths=_existing([os.path.join(windows, "Temp")]),
        prune_dirs=True,
    ))

    cats.append(Category(
        key="browser_cache",
        name="浏览器缓存",
        tier=CONSERVATIVE,
        kind="files",
        describe="Chrome / Edge / Firefox / 夸克等浏览器的网页缓存，不影响书签、密码与登录状态",
        paths=_existing(_chromium_cache_dirs() + _firefox_cache_dirs()
                        + _extra_browser_cache_dirs()),
        prune_dirs=True,
    ))

    cats.append(Category(
        key="thumbnails",
        name="缩略图缓存",
        tier=CONSERVATIVE,
        kind="files",
        describe="资源管理器的缩略图与图标缓存，会按需重建",
        paths=_existing([explorer]),
        patterns=("thumbcache_*.db", "iconcache_*.db"),
        note="正被资源管理器占用的文件会自动跳过",
    ))

    cats.append(Category(
        key="wer",
        name="Windows 错误报告",
        tier=CONSERVATIVE,
        kind="files",
        describe="程序崩溃时生成的错误报告",
        paths=_existing([
            os.path.join(local, "Microsoft", "Windows", "WER"),
            os.path.join(programdata, "Microsoft", "Windows", "WER"),
        ]),
        prune_dirs=True,
    ))

    cats.append(Category(
        key="crash_dumps",
        name="崩溃转储文件",
        tier=CONSERVATIVE,
        kind="files",
        describe="程序与系统崩溃时保存的内存转储",
        paths=_existing([
            os.path.join(local, "CrashDumps"),
            os.path.join(windows, "Minidump"),
            os.path.join(windows, "MEMORY.DMP"),
            os.path.join(windows, "LiveKernelReports"),
        ]),
        patterns=("*.dmp", "*.mdmp"),
    ))

    cats.append(Category(
        key="recycle_bin",
        name="回收站",
        tier=STANDARD,
        kind="recyclebin",
        describe="清空所有本地磁盘的回收站",
        paths=fixed_drives(),
    ))

    cats.append(Category(
        key="win_logs",
        name="Windows 日志",
        tier=STANDARD,
        kind="files",
        describe="Windows\\Logs 下的历史日志文件",
        paths=_existing([os.path.join(windows, "Logs")]),
    ))

    cats.append(Category(
        key="wu_cache",
        name="旧更新缓存",
        tier=STANDARD,
        kind="files",
        describe="已下载完成的 Windows 更新安装包缓存",
        paths=_existing([os.path.join(windows, "SoftwareDistribution", "Download")]),
        prune_dirs=True,
    ))

    cats.append(Category(
        key="prefetch",
        name="预读取文件",
        tier=STANDARD,
        kind="files",
        describe="Windows 预读取缓存，删除后程序首次启动会稍慢",
        paths=_existing([os.path.join(windows, "Prefetch")]),
    ))

    cats.append(Category(
        key="delivery_opt",
        name="传递优化缓存",
        tier=STANDARD,
        kind="files",
        describe="Windows 更新的分发缓存",
        paths=_existing([
            os.path.join(windows, "ServiceProfiles", "NetworkService", "AppData",
                         "Local", "Microsoft", "Windows", "DeliveryOptimization"),
            os.path.join(programdata, "Microsoft", "Windows", "DeliveryOptimization"),
        ]),
        prune_dirs=True,
    ))

    dev_paths = _existing(_dev_cache_dirs())
    if dev_paths:
        cats.append(Category(
            key="dev_cache",
            name="开发工具缓存",
            tier=STANDARD,
            kind="files",
            describe="npm / pip / yarn / Gradle / NuGet / Go 的下载缓存",
            paths=dev_paths,
            prune_dirs=True,
        ))

    def add_app(key, name, describe, paths, note=""):
        existing = _existing(paths)
        if existing:
            cats.append(Category(
                key=key,
                name=name,
                tier=STANDARD,
                kind="files",
                describe=describe,
                paths=existing,
                note=note,
            ))

    add_app(
        "app_wechat",
        "微信缓存",
        "微信的临时缓存文件，不含聊天记录",
        _glob_dirs(os.path.join(profile, "Documents", "xwechat_files", "*", "cache"))
        + _glob_dirs(os.path.join(profile, "Documents", "xwechat_files", "*", "temp"))
        + _glob_dirs(os.path.join(profile, "Documents", "WeChat Files", "*",
                                  "FileStorage", "Cache")),
        note="聊天记录和接收的文件在 msg / db_storage 目录，不会被删除",
    )

    add_app(
        "app_qq",
        "QQ 缓存",
        "QQ 的网页与界面缓存",
        [
            os.path.join(roaming, "QQ", "Cache"),
            os.path.join(roaming, "QQ", "Code Cache"),
            os.path.join(roaming, "QQ", "GPUCache"),
            os.path.join(roaming, "QQ", "log"),
        ],
        note="不含聊天记录和接收的文件",
    )

    add_app(
        "app_wps",
        "WPS 缓存",
        "WPS 的在线文档与界面缓存",
        [
            os.path.join(roaming, "kingsoft", "office6", "cache"),
            os.path.join(roaming, "kingsoft", "office6", "log"),
        ],
        note="不含自动备份和云文档",
    )

    add_app(
        "app_netdisk",
        "网盘缓存",
        "百度网盘的网页与预览缓存",
        [
            os.path.join(roaming, "baidunetdisk", "Cache"),
            os.path.join(roaming, "baidunetdisk", "Code Cache"),
            os.path.join(roaming, "baidunetdisk", "GPUCache"),
            os.path.join(roaming, "baidunetdisk", "DawnCache"),
        ],
    )

    desktop_caches = []
    for base, subs in (
        (os.path.join(roaming, "Claude"),
         ("Cache", "Code Cache", "GPUCache", "GrShaderCache", "ShaderCache",
          "DawnGraphiteCache", "DawnWebGPUCache", "logs")),
        (os.path.join(roaming, "Code"),
         ("Cache", "CachedData", "Code Cache", "GPUCache")),
    ):
        desktop_caches.extend(os.path.join(base, sub) for sub in subs)
    add_app(
        "app_desktop",
        "桌面应用缓存",
        "Claude / VS Code 等桌面应用的界面与代码缓存",
        desktop_caches,
    )

    add_app(
        "app_gpu",
        "显卡着色器缓存",
        "显卡着色器编译缓存，删除后游戏首次加载会稍慢",
        [
            os.path.join(local, "D3DSCache"),
            os.path.join(local, "NVIDIA", "DXCache"),
            os.path.join(local, "NVIDIA", "GLCache"),
            os.path.join(local, "NVIDIA Corporation", "NV_Cache"),
            os.path.join(local, "Intel", "ShaderCache"),
            os.path.join(local, "AMD", "DxCache"),
            os.path.join(local, "AMD", "GLCache"),
        ],
    )

    add_app(
        "app_office",
        "办公软件缓存",
        "Office 文档缓存与 Adobe 媒体缓存",
        [
            os.path.join(local, "Microsoft", "Office", "16.0", "OfficeFileCache"),
            os.path.join(local, "Microsoft", "Office", "OTele"),
            os.path.join(local, "Adobe", "Common", "Media Cache"),
            os.path.join(local, "Adobe", "Common", "Media Cache Files"),
        ],
    )

    codex_old = _glob_dirs(os.path.join(profile, ".cache", "codex-runtimes",
                                        "codex-runtime-install-*")) + \
                _glob_dirs(os.path.join(profile, ".cache", "codex-runtimes",
                                        "codex-primary-runtime.previous-*"))
    codex_old = _existing(codex_old)
    if codex_old:
        cats.append(Category(
            key="codex_old",
            name="Codex 旧运行时",
            tier=STANDARD,
            kind="files",
            describe="Codex 遗留的旧安装包与旧版本运行时",
            paths=codex_old,
            prune_dirs=True,
            note="当前正在使用的运行时不会被删除",
        ))

    updater_dirs = _glob_dirs(os.path.join(local, "*-updater"))
    crx_cache = os.path.join(local, "Google", "GoogleUpdater", "crx_cache")
    if os.path.isdir(crx_cache):
        updater_dirs.append(crx_cache)
    updater_paths = _existing(updater_dirs)
    if updater_paths:
        cats.append(Category(
            key="app_updaters",
            name="软件更新残留包",
            tier=STANDARD,
            kind="files",
            describe="各桌面应用更新器下载的旧安装包缓存",
            paths=updater_paths,
            prune_dirs=True,
        ))

    opt_models = _glob_dirs(os.path.join(local, "Google", "Chrome", "User Data",
                                         "OptGuideOnDeviceModel")) + \
                 _glob_dirs(os.path.join(local, "Microsoft", "Edge", "User Data",
                                         "OptGuideOnDeviceModel"))
    opt_paths = _existing(opt_models)
    if opt_paths:
        cats.append(Category(
            key="browser_ai_model",
            name="浏览器端侧 AI 模型",
            tier=STANDARD,
            kind="files",
            describe="Chrome / Edge 下载的端侧 AI 模型，占用可达数 GB",
            paths=opt_paths,
            prune_dirs=True,
            note="删除后相关 AI 功能再次使用时会重新下载",
        ))

    other_bins = _other_recycle_bins()
    if other_bins:
        cats.append(Category(
            key="recycle_bin_other",
            name="回收站残留（其他账户）",
            tier=DEEP,
            kind="files",
            describe="其他 Windows 账户或旧系统留下的回收站内容",
            paths=other_bins,
            note="删除后不可恢复，确认这些账户已不再使用",
            requires_confirm=True,
        ))

    cats.append(Category(
        key="dism",
        name="系统组件清理 (WinSxS)",
        tier=DEEP,
        kind="command",
        describe="用 DISM 清理旧组件版本，释放 WinSxS 占用",
        command=[os.path.join(windows, "System32", "Dism.exe"),
                 "/Online", "/Cleanup-Image", "/StartComponentCleanup"],
        note="耗时较长，可能 5-20 分钟，期间请勿关闭窗口",
        requires_confirm=True,
    ))

    cats.append(Category(
        key="event_logs",
        name="系统事件日志",
        tier=DEEP,
        kind="eventlogs",
        describe="清空事件查看器中的系统、应用、安全等日志",
        paths=_existing([os.path.join(windows, "System32", "winevt", "Logs")]),
        note="会丢失历史诊断记录，不影响系统运行",
        requires_confirm=True,
    ))

    cats.append(Category(
        key="search_index",
        name="搜索索引",
        tier=DEEP,
        kind="searchindex",
        describe="删除并重建 Windows 搜索索引数据库",
        paths=_existing([os.path.join(programdata, "Microsoft", "Search", "Data",
                                      "Applications", "Windows")]),
        note="清理后一段时间内搜索会变慢，系统会自动重建",
        requires_confirm=True,
    ))

    hiberfil = os.path.join(system_drive, "hiberfil.sys")
    if os.path.isfile(hiberfil):
        cats.append(Category(
            key="hibernate",
            name="休眠文件",
            tier=DEEP,
            kind="command",
            describe="关闭休眠功能并删除 hiberfil.sys",
            command=[os.path.join(windows, "System32", "powercfg.exe"), "/h", "off"],
            note="会同时关闭“快速启动”，可用 powercfg /h on 恢复",
            requires_confirm=True,
            size_fn=lambda: _file_size(hiberfil),
        ))

    windows_old = os.path.join(system_drive, "Windows.old")
    if os.path.isdir(windows_old):
        cats.append(Category(
            key="windows_old",
            name="旧系统文件 (Windows.old)",
            tier=DEEP,
            kind="files",
            describe="系统升级前的旧版本备份，删除后无法回退旧版本",
            paths=[windows_old],
            note="需要先取得文件所有权，部分文件可能删除失败",
            requires_confirm=True,
        ))

    existing_keys = {c.key for c in cats}
    for extra in _load_external_rules():
        if extra.key not in existing_keys:
            cats.append(extra)
            existing_keys.add(extra.key)

    return cats
