"""清理日志：写入一次清理会话，并汇总成历史列表。"""
import os
import re
import time


def _fmt_time(stem):
    # 形如 20261111_133500
    if len(stem) >= 15 and stem[8] == "_":
        return (f"{stem[0:4]}-{stem[4:6]}-{stem[6:8]} "
                f"{stem[9:11]}:{stem[11:13]}:{stem[13:15]}")
    return stem


def write_log(log_dir, lines, prefix=""):
    """写入一份日志，文件名形如 20261111_133500.log，供 load_history 解析。"""
    os.makedirs(log_dir, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    name = f"{prefix}{stamp}.log" if prefix else f"{stamp}.log"
    path = os.path.join(log_dir, name)
    # 同一秒内重复写入时加序号，避免覆盖。
    index = 2
    while os.path.exists(path):
        name = f"{prefix}{stamp}_{index}.log" if prefix else f"{stamp}_{index}.log"
        path = os.path.join(log_dir, name)
        index += 1
    with open(path, "w", encoding="utf-8") as handle:
        for line in lines:
            handle.write(str(line).rstrip() + "\n")
    return path


def append_shred_history(log_dir, paths):
    os.makedirs(log_dir, exist_ok=True)
    path = os.path.join(log_dir, "shred_history.log")
    moment = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(path, "a", encoding="utf-8") as handle:
        for item in paths or []:
            if isinstance(item, str):
                status, target = "ok", item
            else:
                status = item.get("status") or "ok"
                target = item.get("path") or ""
            handle.write(f"{moment}\t{status}\t{target}\n")
        handle.flush()
        os.fsync(handle.fileno())
    return path


def load_shred_history(log_dir):
    path = os.path.join(log_dir or "", "shred_history.log")
    rows = []
    if not os.path.isfile(path):
        return rows
    try:
        with open(path, encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                line = line.rstrip("\n")
                if not line:
                    continue
                parts = line.split("\t")
                if len(parts) >= 3:
                    moment, status, item = parts[0], parts[1], parts[2]
                elif len(parts) == 2:
                    moment, item = parts
                    status = "ok"
                else:
                    moment, status, item = "", "ok", line
                rows.append({"time": moment, "status": status, "path": item})
    except OSError:
        return []
    rows.reverse()
    return rows


def load_history(log_dir):
    rows = []
    if not os.path.isdir(log_dir):
        return rows
    try:
        names = sorted(os.listdir(log_dir), reverse=True)
    except OSError:
        return rows
    for name in names:
        if not name.endswith(".log"):
            continue
        path = os.path.join(log_dir, name)
        freed = "-"
        items = 0
        try:
            with open(path, encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    if "清理结束，共释放" in line:
                        match = re.search(r"共释放\s*([\d.]+\s*[A-Z]?B)", line)
                        if match:
                            freed = match.group(1)
                    elif "清理：" in line:
                        items += 1
        except OSError:
            continue
        rows.append({
            "time": _fmt_time(name[:-4]),
            "freed": freed,
            "items": items,
            "path": path,
        })
    return rows
