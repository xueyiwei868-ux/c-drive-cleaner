"""纯逻辑安全测试。在 Linux 上用临时目录和假注册表运行，不碰真实系统。"""
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import datdecode
import cleaner
import dupes
import scanjobs
import scanner
import fragviz
import history
import imclean
import main
import migrate
import privacy
import ruleupdate
import safepath
import shredder


class ImportSafetyTests(unittest.TestCase):
    def test_main_import_does_not_require_tkinter(self):
        script = """
import builtins
real_import = builtins.__import__
def import_without_tkinter(name, *args, **kwargs):
    if name == "tkinter" or name.startswith("tkinter."):
        raise ImportError("tkinter blocked for test")
    return real_import(name, *args, **kwargs)
builtins.__import__ = import_without_tkinter
import main
assert main.tk is None
"""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        result = subprocess.run(
            [sys.executable, "-c", script], cwd=root,
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


class PathProtectionTests(unittest.TestCase):
    def test_system_and_drive_roots_are_blocked(self):
        blocked = [
            r"C:\Windows\System32\cmd.exe",
            r"C:\Windows\SysWOW64\notepad.exe",
            r"C:\Program Files\App\app.exe",
            r"C:\Program Files (x86)\App\app.exe",
            r"C:\ProgramData\Microsoft\crypto",
            r"C:\pagefile.sys",
            r"C:\hiberfil.sys",
            r"C:\\",
            r"D:\System Volume Information\tracking.log",
        ]
        for path in blocked:
            self.assertTrue(safepath.is_protected_path(path), path)

    def test_user_file_is_not_a_system_path(self):
        self.assertFalse(safepath.is_protected_path(r"C:\Users\me\Videos\big.mp4"))
        self.assertFalse(safepath.is_protected_path(r"D:\data\notes.txt"))

    def test_profile_root_blocked_children_allowed(self):
        old = os.environ.get("USERPROFILE")
        os.environ["USERPROFILE"] = r"C:\Users\me"
        try:
            self.assertTrue(safepath.is_protected_path(r"C:\Users\me"))
            self.assertFalse(safepath.is_protected_path(r"C:\Users\me\Desktop\a.txt"))
        finally:
            if old is None:
                os.environ.pop("USERPROFILE", None)
            else:
                os.environ["USERPROFILE"] = old

    def test_shredder_refuses_system_path_before_delete(self):
        with self.assertRaises(shredder.ShredError):
            shredder.shred_path(r"C:\Windows\System32\cmd.exe")

    def test_libraries_are_not_migration_candidates(self):
        env = {"USERPROFILE": r"C:\Users\me"}
        for path in (
            r"C:\Users\me\Documents",
            r"C:\Users\me\Desktop",
            r"C:\Users\me\Downloads",
            r"C:\Users\me\Downloads\Setup.exe",
            r"C:\Users\me\Documents\WeChat Files",
        ):
            self.assertTrue(safepath.is_user_library(path, env), path)
            self.assertTrue(safepath.migration_forbidden(path, env), path)
        self.assertFalse(safepath.migration_forbidden(r"C:\Program Files\Demo", env))
        self.assertTrue(safepath.migration_forbidden(r"C:\Windows\System32", env))
        self.assertTrue(safepath.migration_forbidden(r"C:\Program Files", env))

    def test_password_store_names(self):
        self.assertTrue(safepath.is_password_store(
            r"C:\Users\a\AppData\Local\Google\Chrome\User Data\Default\Login Data"))
        self.assertTrue(safepath.is_password_store(
            r"C:\Users\a\AppData\Local\Quark\User Data\Default\Login Data-journal"))
        self.assertTrue(safepath.is_password_store(
            r"C:\Users\a\AppData\Roaming\Mozilla\Firefox\Profiles\x\logins.json"))
        self.assertFalse(safepath.is_password_store(
            r"C:\Users\a\AppData\Local\Google\Chrome\User Data\Default\History"))

    def test_cleaner_skips_password_database(self):
        folder = tempfile.mkdtemp()
        try:
            secret = os.path.join(folder, "Login Data")
            normal = os.path.join(folder, "cache.tmp")
            with open(secret, "w", encoding="utf-8") as handle:
                handle.write("secret")
            with open(normal, "w", encoding="utf-8") as handle:
                handle.write("junk")
            cat = type("C", (), {"key": "t", "name": "t"})()
            result = cleaner.CleanResult(cat)
            cleaner._delete_file(secret, [folder], ("*",), result)
            self.assertTrue(os.path.exists(secret))
            self.assertEqual(result.skipped, 1)
            other = cleaner.CleanResult(cat)
            cleaner._delete_file(normal, [folder], ("*",), other)
            self.assertFalse(os.path.exists(normal))
            self.assertEqual(other.deleted, 1)
        finally:
            shutil.rmtree(folder, ignore_errors=True)


class DedupeKeepTests(unittest.TestCase):
    def _groups(self):
        return [
            {"hash": "a", "size": 10, "files": [r"C:\a", r"C:\b", r"C:\c"],
             "mtimes": {r"C:\a": 1, r"C:\b": 9, r"C:\c": 3}},
            {"hash": "d", "size": 4, "files": [r"D:\d1", r"D:\d2"],
             "mtimes": {r"D:\d1": 2, r"D:\d2": 2}},
        ]

    def test_auto_select_keeps_one_per_group(self):
        groups = self._groups()
        chosen = dupes.auto_select(groups)
        self.assertNotIn(r"C:\b", chosen)
        self.assertIn(r"C:\a", chosen)
        self.assertIn(r"C:\c", chosen)
        self.assertEqual(len([p for p in chosen if p.startswith("C:")]), 2)
        self.assertEqual(len([p for p in chosen if p.startswith("D:")]), 1)

    def test_selecting_all_still_keeps_one(self):
        groups = self._groups()
        everything = [path for group in groups for path in group["files"]]
        doomed = dupes.paths_to_delete(groups, everything)
        self.assertNotIn(r"C:\b", doomed)
        self.assertNotIn(r"D:\d2", doomed)
        self.assertEqual(len(doomed), 3)
        for group in groups:
            left = [path for path in group["files"] if path not in doomed]
            self.assertEqual(len(left), 1)

    def test_partial_selection_is_respected(self):
        groups = self._groups()
        doomed = dupes.paths_to_delete(groups, [r"C:\a"])
        self.assertEqual(doomed, [r"C:\a"])
        self.assertEqual(dupes.paths_to_delete(groups, []), [])


class ImcleanTests(unittest.TestCase):
    def test_dat_and_extensionless_follow_media_directories(self):
        cases = {
            r"D:\xwechat_files\wxid\msg\video\2e7269d.t.dat": ("video", ""),
            r"D:\xwechat_files\wxid\msg\video\abc": ("video", ""),
            r"D:\xwechat_files\wxid\msg\attach\pic.dat": ("image", ""),
            r"D:\xwechat_files\wxid\msg\file\report.docx": ("file", "doc"),
            r"D:\xwechat_files\wxid\msg\file\clip.mp4": ("file", "video"),
            r"D:\xwechat_files\wxid\msg\file\pack.zip": ("file", "archive"),
            r"D:\xwechat_files\wxid\cache\foo.dat": ("cache", ""),
            r"D:\xwechat_files\wxid\msg\voice\a.silk": ("audio", ""),
            r"D:\WeChat Files\wxid\FileStorage\Image\2024-11\a.jpg": ("image", ""),
        }
        for path, expected in cases.items():
            self.assertEqual(imclean.classify(path), expected, path)

    def test_databases_and_loose_dat_are_skipped(self):
        skipped = [
            r"D:\xwechat_files\wxid\config.dat",
            r"D:\xwechat_files\wxid\db_storage\message\msg.db",
            r"D:\xwechat_files\wxid\db_storage\message\extra.dat",
            r"D:\xwechat_files\wxid\config\config.json",
            r"D:\xwechat_files\wxid\msg\video\index.db",
            r"D:\Tencent Files\1\nt_qq\database\a.dat",
        ]
        for path in skipped:
            kind, _sub = imclean.classify(path)
            self.assertIsNone(kind, path)

    def test_clean_only_removes_classified_media(self):
        root = tempfile.mkdtemp()
        try:
            video = os.path.join(root, "msg", "video")
            db = os.path.join(root, "db_storage")
            os.makedirs(video)
            os.makedirs(db)
            dat = os.path.join(video, "clip.dat")
            database = os.path.join(db, "msg.db")
            loose = os.path.join(root, "config.dat")
            for path in (dat, database, loose):
                with open(path, "wb") as handle:
                    handle.write(b"1234")

            def remover(paths):
                for path in paths:
                    os.remove(path)
                return []

            freed, deleted = imclean.clean(
                [root], {"video", "image", "file", "cache"},
                paths=[dat, database, loose], remover=remover)
            self.assertFalse(os.path.exists(dat))
            self.assertTrue(os.path.exists(database))
            self.assertTrue(os.path.exists(loose))
            self.assertEqual(deleted, 1)
            self.assertGreater(freed, 0)
        finally:
            shutil.rmtree(root, ignore_errors=True)


class RuleValidationTests(unittest.TestCase):
    def test_url_and_command_rules(self):
        self.assertEqual(ruleupdate.validate_url("https://example.com/rules.json"), "")
        self.assertIn("https", ruleupdate.validate_url("http://example.com/rules.json"))
        self.assertNotEqual(ruleupdate.validate_url("http://example.com/rules.json"), "")
        self.assertTrue(ruleupdate.validate_url("file:///tmp/rules.json"))
        self.assertTrue(ruleupdate.validate_url("javascript:alert(1)"))
        command = {"key": "evil", "kind": "command", "command": ["cmd.exe", "/c", "calc"]}
        self.assertIn("command", ruleupdate.validate_remote_rule(command))
        login = {"key": "pw", "kind": "files",
                 "paths": [r"%LOCALAPPDATA%\Google\Chrome\User Data\*\Login Data"]}
        self.assertIn("密码", ruleupdate.validate_remote_rule(login))
        traversal = {"key": "up", "kind": "files", "paths": [r"%TEMP%\..\Windows\System32"]}
        self.assertTrue(ruleupdate.validate_remote_rule(traversal))
        ok = {"key": "app_demo", "kind": "files", "tier": "standard",
              "paths": [r"%TEMP%\Demo\Cache"]}
        self.assertEqual(ruleupdate.validate_remote_rule(ok), "")
        documents = {"key": "docs", "kind": "files",
                     "paths": [r"%USERPROFILE%\Documents"]}
        self.assertIn("文档", ruleupdate.validate_remote_rule(documents))
        loose = {"key": "video", "kind": "files", "paths": [r"D:\Videos\holiday.mp4"]}
        self.assertIn("临时", ruleupdate.validate_remote_rule(loose))

    def test_merge_keeps_local_command_and_drops_remote_command(self):
        local = {"version": 1, "categories": [
            {"key": "defrag", "kind": "command", "command": ["defrag.exe", "C:", "/O"]},
        ]}
        remote = {"categories": [
            {"key": "evil", "kind": "command", "command": ["powershell.exe"]},
            {"key": "app_demo", "name": "示例缓存", "kind": "files",
             "paths": [r"%TEMP%\Demo\Cache"]},
            {"key": "defrag", "kind": "command", "command": ["calc.exe"]},
        ]}
        merged, added, rejected, error = ruleupdate.merge_remote(local, remote)
        self.assertEqual(error, "")
        self.assertEqual(added, 1)
        self.assertEqual(rejected, 2)
        keys = {item["key"]: item for item in merged["categories"]}
        self.assertEqual(keys["defrag"]["kind"], "command")
        self.assertNotIn("evil", keys)
        self.assertEqual(keys["app_demo"]["kind"], "files")
        self.assertNotIn("command", keys["app_demo"])

    def test_update_rules_rejects_bad_url_without_writing(self):
        added, _total, err = ruleupdate.update_rules("file:///tmp/rules.json")
        self.assertEqual(added, 0)
        self.assertIn("http", err)

    def test_shipped_rules_do_not_delete_login_data(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "rules.json"), encoding="utf-8") as handle:
            text = handle.read()
        self.assertNotIn("\\\\Login Data", text)
        self.assertNotIn("logins.json", text.lower())


class MigrateRollbackTests(unittest.TestCase):
    def test_junction_failure_restores_source(self):
        src = tempfile.mkdtemp()
        dest_root = tempfile.mkdtemp()
        try:
            with open(os.path.join(src, "a.txt"), "w", encoding="utf-8") as handle:
                handle.write("hello-data")

            def drive(path):
                full = os.path.abspath(path)
                dest = os.path.abspath(dest_root)
                if full == dest or full.startswith(dest + os.sep):
                    return "D:"
                return "C:"

            def robocopy(source, dest, move):
                os.makedirs(dest, exist_ok=True)
                for name in list(os.listdir(source)):
                    sp = os.path.join(source, name)
                    dp = os.path.join(dest, name)
                    if os.path.isfile(sp):
                        shutil.copy2(sp, dp)
                        if move:
                            os.remove(sp)
                return 1

            with mock.patch.object(migrate, "_drive_of", side_effect=drive), \
                    mock.patch.object(migrate, "_robocopy", side_effect=robocopy), \
                    mock.patch.object(migrate, "create_junction",
                                      side_effect=lambda link, target: os.makedirs(link, exist_ok=True)), \
                    mock.patch.object(migrate, "junction_works", return_value=False), \
                    mock.patch.object(migrate, "is_junction", return_value=False):
                with self.assertRaises(migrate.MigrateError):
                    migrate.migrate(src, dest_root)
            with open(os.path.join(src, "a.txt"), encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "hello-data")
            self.assertFalse(os.path.isdir(os.path.join(dest_root, os.path.basename(src))))
        finally:
            shutil.rmtree(src, ignore_errors=True)
            shutil.rmtree(dest_root, ignore_errors=True)

    def test_copy_failure_does_not_remove_source(self):
        src = tempfile.mkdtemp()
        dest_root = tempfile.mkdtemp()
        try:
            with open(os.path.join(src, "a.txt"), "w", encoding="utf-8") as handle:
                handle.write("keep")

            def drive(path):
                full = os.path.abspath(path)
                dest = os.path.abspath(dest_root)
                if full == dest or full.startswith(dest + os.sep):
                    return "D:"
                return "C:"

            def robocopy(source, dest, move):
                os.makedirs(dest, exist_ok=True)
                with open(os.path.join(dest, "partial.txt"), "w", encoding="utf-8") as handle:
                    handle.write("x")
                return 16

            with mock.patch.object(migrate, "_drive_of", side_effect=drive), \
                    mock.patch.object(migrate, "_robocopy", side_effect=robocopy), \
                    mock.patch.object(migrate, "is_junction", return_value=False):
                result = migrate.migrate(src, dest_root)
            self.assertTrue(os.path.isfile(os.path.join(src, "a.txt")))
            partial = os.path.join(dest_root, os.path.basename(src), "partial.txt")
            self.assertTrue(os.path.isfile(partial))
            self.assertFalse(result.ok)
            self.assertIn("partial.txt", result.warning)
        finally:
            shutil.rmtree(src, ignore_errors=True)
            shutil.rmtree(dest_root, ignore_errors=True)

    def test_file_link_failure_rolls_back(self):
        folder = tempfile.mkdtemp()
        dest_root = tempfile.mkdtemp(prefix="dest-")
        try:
            src = os.path.join(folder, "movie.mp4")
            with open(src, "wb") as handle:
                handle.write(b"0123456789")

            def drive(path):
                full = os.path.abspath(path)
                dest = os.path.abspath(dest_root)
                if full == dest or full.startswith(dest + os.sep):
                    return "D:"
                return "C:"

            def linker(_dest, _src):
                raise OSError("symlink denied")

            with mock.patch.object(migrate, "_drive_of", side_effect=drive):
                with self.assertRaises(migrate.MigrateError) as caught:
                    migrate.migrate_file(src, dest_root, linker=linker)
            self.assertIn("还原", str(caught.exception))
            with open(src, "rb") as handle:
                self.assertEqual(handle.read(), b"0123456789")
            self.assertFalse(os.path.exists(os.path.join(dest_root, "movie.mp4")))
        finally:
            shutil.rmtree(folder, ignore_errors=True)
            shutil.rmtree(dest_root, ignore_errors=True)

    def test_file_size_mismatch_keeps_source(self):
        folder = tempfile.mkdtemp()
        dest_root = tempfile.mkdtemp(prefix="dest-")
        try:
            src = os.path.join(folder, "movie.mp4")
            with open(src, "wb") as handle:
                handle.write(b"0123456789")

            def drive(path):
                full = os.path.abspath(path)
                dest = os.path.abspath(dest_root)
                if full == dest or full.startswith(dest + os.sep):
                    return "D:"
                return "C:"

            with mock.patch.object(migrate, "_drive_of", side_effect=drive), \
                    mock.patch.object(migrate, "_same_file_size", return_value=False):
                with self.assertRaises(migrate.MigrateError):
                    migrate.migrate_file(src, dest_root)
            self.assertTrue(os.path.isfile(src))
            self.assertFalse(os.path.exists(os.path.join(dest_root, "movie.mp4")))
        finally:
            shutil.rmtree(folder, ignore_errors=True)
            shutil.rmtree(dest_root, ignore_errors=True)

    def test_discover_skips_documents_desktop_downloads(self):
        class Key:
            def __init__(self, subs=None, values=None):
                self.subs = subs or {}
                self.values = values or {}

            def Close(self):
                return None

        class FakeReg:
            HKEY_LOCAL_MACHINE = "HKLM"
            HKEY_CURRENT_USER = "HKCU"

            def __init__(self, tree):
                self.tree = tree

            def OpenKey(self, root, path):
                if isinstance(root, Key):
                    key = root.subs.get(path)
                else:
                    key = self.tree.get((root, path))
                if key is None:
                    raise OSError(path)
                return key

            def EnumKey(self, key, index):
                names = list(key.subs)
                if index >= len(names):
                    raise OSError("end")
                return names[index]

            def EnumValue(self, key, index):
                names = list(key.values)
                if index >= len(names):
                    raise OSError("end")
                name = names[index]
                return name, key.values[name], 1

        uninstall = Key(subs={
            "demo": Key(values={
                "DisplayName": "演示软件",
                "InstallLocation": r"C:\Program Files\Demo",
                "EstimatedSize": 12,
            }),
            "docs": Key(values={
                "DisplayName": "文档",
                "InstallLocation": r"C:\Users\me\Documents",
                "EstimatedSize": 99,
            }),
            "desk": Key(values={
                "DisplayName": "桌面",
                "InstallLocation": r"C:\Users\me\Desktop",
            }),
            "down": Key(values={
                "DisplayName": "下载",
                "InstallLocation": r"C:\Users\me\Downloads\Portable",
            }),
            "patch": Key(values={
                "DisplayName": "更新",
                "InstallLocation": r"C:\Program Files\Demo",
                "ReleaseType": "Update",
            }),
        })
        reg = FakeReg({
            ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"): uninstall,
        })
        rows = migrate.discover_installed(
            reg=reg,
            environ={"USERPROFILE": r"C:\Users\me"},
            exists=lambda _path: True,
        )
        paths = [row["path"] for row in rows]
        self.assertEqual(paths, [r"C:\Program Files\Demo"])
        self.assertEqual(rows[0]["size"], 12 * 1024)


class PrivacyAndHistoryTests(unittest.TestCase):
    def test_trace_list_has_no_password_files(self):
        names = {name.lower() for name in privacy.TRACE_FILENAMES}
        self.assertNotIn("login data", names)
        self.assertNotIn("logins.json", names)

    def test_history_sql_keeps_unrelated_rows(self):
        folder = tempfile.mkdtemp()
        try:
            profile = os.path.join(folder, "Default")
            os.makedirs(profile)
            history_db = os.path.join(profile, "History")
            login = os.path.join(profile, "Login Data")
            with open(login, "w", encoding="utf-8") as handle:
                handle.write("passwords")
            conn = sqlite3.connect(history_db)
            conn.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT)")
            conn.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER)")
            conn.execute("CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT)")
            conn.execute("CREATE TABLE downloads_url_chains (id INTEGER, chain_id INTEGER)")
            conn.execute("INSERT INTO urls (url) VALUES ('https://example.com/a')")
            conn.execute("INSERT INTO urls (url) VALUES ('https://item.taobao.com/1')")
            conn.execute("INSERT INTO visits (url) VALUES (1)")
            conn.execute("INSERT INTO visits (url) VALUES (2)")
            conn.execute("INSERT INTO downloads (target_path) VALUES ('a.zip')")
            conn.commit()
            conn.close()

            picked = privacy.collect_chromium_files(profile)
            self.assertIn(history_db, picked)
            self.assertNotIn(login, picked)
            stats = privacy.history_stats(history_db)
            self.assertEqual(stats["urls"], 2)
            self.assertEqual(stats["downloads"], 1)
            self.assertEqual(stats["shop"], 1)

            self.assertTrue(privacy.apply_sql(history_db, privacy._download_sql(history_db)))
            stats = privacy.history_stats(history_db)
            self.assertEqual(stats["downloads"], 0)
            self.assertEqual(stats["urls"], 2)

            self.assertTrue(privacy.apply_sql(history_db, privacy._shop_sql()))
            stats = privacy.history_stats(history_db)
            self.assertEqual(stats["shop"], 0)
            self.assertEqual(stats["urls"], 1)
            self.assertFalse(privacy.apply_sql(login, ["DELETE FROM urls"]))
            with open(login, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "passwords")

            records = [{
                "id": "hist_chrome", "section": "history", "browser": "chrome",
                "action": "files", "files": [history_db, login],
            }]
            plan = privacy.clean_plan(records, ["hist_chrome"])
            self.assertIn(history_db, plan["files"])
            self.assertNotIn(login, plan["files"])
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_history_log_roundtrip(self):
        folder = tempfile.mkdtemp()
        try:
            history.write_log(folder, [
                "开始清理",
                "清理：临时文件",
                "清理结束，共释放 1.5 MB",
            ])
            rows = history.load_history(folder)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["freed"], "1.5 MB")
            self.assertEqual(rows[0]["items"], 1)
        finally:
            shutil.rmtree(folder, ignore_errors=True)


class DatDecodeTests(unittest.TestCase):
    def test_xor_roundtrip_jpeg_png_gif(self):
        import io
        from PIL import Image
        samples = {}
        for fmt, color in (("JPEG", (200, 10, 10)), ("PNG", (10, 180, 40)), ("GIF", (10, 40, 200))):
            image = Image.new("RGB", (6, 6), color)
            buffer = io.BytesIO()
            image.save(buffer, format=fmt)
            samples[fmt] = buffer.getvalue()
        for fmt, raw in samples.items():
            encoded = bytes(byte ^ 0x5A for byte in raw)
            self.assertEqual(datdecode.xor_key(encoded), 0x5A)
            decoded = datdecode.decode_dat(encoded)
            self.assertTrue(decoded.startswith(raw[:4]))
            self.assertEqual(Image.open(io.BytesIO(decoded)).size, (6, 6))

    def test_plain_text_is_not_decoded(self):
        self.assertIsNone(datdecode.xor_key(b"hello world!!"))
        self.assertIsNone(datdecode.decode_dat(b"\x00\x01\x02\x03\x04"))


class ReviewFixTests(unittest.TestCase):
    def test_rollback_keeps_the_only_copy_when_copy_back_fails(self):
        src = tempfile.mkdtemp()
        dest = tempfile.mkdtemp()
        try:
            with open(os.path.join(dest, "only.txt"), "w", encoding="utf-8") as handle:
                handle.write("only-copy")

            def robocopy(_source, _dest, move):
                self.assertFalse(move)
                return 1

            with mock.patch.object(migrate, "_robocopy", side_effect=robocopy):
                with self.assertRaises(migrate.MigrateError):
                    migrate._rollback_to_source(src, dest)
            with open(os.path.join(dest, "only.txt"), encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "only-copy")
        finally:
            shutil.rmtree(src, ignore_errors=True)
            shutil.rmtree(dest, ignore_errors=True)

    def test_incomplete_copy_does_not_delete_source(self):
        src = tempfile.mkdtemp()
        dest_root = tempfile.mkdtemp()
        try:
            with open(os.path.join(src, "keep.txt"), "w", encoding="utf-8") as handle:
                handle.write("stay")

            def drive(path):
                full = os.path.abspath(path)
                root = os.path.abspath(dest_root)
                if full == root or full.startswith(root + os.sep):
                    return "D:"
                return "C:"

            def robocopy(_source, dest, move):
                os.makedirs(dest, exist_ok=True)
                return 1

            with mock.patch.object(migrate, "_drive_of", side_effect=drive), \
                    mock.patch.object(migrate, "_robocopy", side_effect=robocopy), \
                    mock.patch.object(migrate, "is_junction", return_value=False):
                with self.assertRaises(migrate.MigrateError):
                    migrate.migrate(src, dest_root)
            with open(os.path.join(src, "keep.txt"), encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "stay")
        finally:
            shutil.rmtree(src, ignore_errors=True)
            shutil.rmtree(dest_root, ignore_errors=True)

    def test_cleaner_refuses_documents_at_execution(self):
        root = tempfile.mkdtemp()
        old = os.environ.get("USERPROFILE")
        os.environ["USERPROFILE"] = root
        try:
            docs = os.path.join(root, "Documents")
            os.makedirs(docs)
            secret = os.path.join(docs, "secret.txt")
            with open(secret, "w", encoding="utf-8") as handle:
                handle.write("keep-me")
            cat = type("C", (), {"key": "t", "name": "t"})()
            result = cleaner.CleanResult(cat)
            cleaner._delete_file(secret, [docs], ("*",), result)
            self.assertTrue(os.path.exists(secret))
            self.assertEqual(result.skipped, 1)
            with open(secret, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "keep-me")
        finally:
            if old is None:
                os.environ.pop("USERPROFILE", None)
            else:
                os.environ["USERPROFILE"] = old
            shutil.rmtree(root, ignore_errors=True)

    def test_shred_symlink_does_not_follow(self):
        folder = tempfile.mkdtemp()
        try:
            target = os.path.join(folder, "secret.txt")
            with open(target, "w", encoding="utf-8") as handle:
                handle.write("safe")
            link = os.path.join(folder, "link.txt")
            os.symlink(target, link)
            with self.assertRaises(shredder.ShredError):
                shredder.shred_path(link)
            with open(target, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "safe")
            nested = os.path.join(folder, "real")
            os.makedirs(nested)
            inside = os.path.join(nested, "data.txt")
            with open(inside, "w", encoding="utf-8") as handle:
                handle.write("dir")
            linkdir = os.path.join(folder, "linkdir")
            os.symlink(nested, linkdir, target_is_directory=True)
            with self.assertRaises(shredder.ShredError):
                shredder.shred_path(linkdir)
            with open(inside, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "dir")
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_shred_rejects_mocked_junction_root(self):
        folder = tempfile.mkdtemp()
        try:
            target = os.path.join(folder, "data.txt")
            with open(target, "w", encoding="utf-8") as handle:
                handle.write("junction")
            with mock.patch.object(safepath, "is_reparse_point", return_value=True):
                with self.assertRaises(shredder.ShredError):
                    shredder.shred_path(target)
            with open(target, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "junction")
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_hidden_duplicate_selection_is_not_deleted(self):
        groups = [
            {"hash": "v", "size": 10, "files": [r"C:\a.mp4", r"C:\b.mp4"],
             "mtimes": {r"C:\a.mp4": 2, r"C:\b.mp4": 1}},
            {"hash": "z", "size": 8, "files": [r"D:\a.zip", r"D:\b.zip"],
             "mtimes": {r"D:\a.zip": 2, r"D:\b.zip": 1}},
        ]
        selected = dupes.auto_select(groups)
        self.assertIn(r"D:\b.zip", selected)
        visible = dupes.paths_for_cleanup(groups, selected, {"video"})
        self.assertNotIn(r"D:\b.zip", visible)
        self.assertNotIn(r"D:\a.zip", visible)
        self.assertTrue(all(path.endswith(".mp4") for path in visible))

    def test_stale_scan_generation_is_dropped(self):
        jobs = scanjobs.ScanJobs()
        first = jobs.start("big")
        second = jobs.start("big")
        self.assertFalse(jobs.accept("big", first))
        self.assertTrue(jobs.accept("big", second))
        self.assertTrue(jobs.accept("dup", jobs.start("dup")))
        self.assertFalse(jobs.accept("im-wechat", 1))

    def test_large_list_is_not_truncated_and_disk_filter_hides_rows(self):
        rows = [(rf"C:\f{i}.mp4", i, 0) for i in range(10)] + [(r"D:\a.zip", 3, 0)]
        self.assertEqual(len(scanner.visible_large_paths(rows, "all", "全部")), 11)
        only_c = scanner.visible_large_paths(rows, "video", "C:")
        self.assertEqual(len(only_c), 10)
        self.assertTrue(all(path.startswith("C:") for path in only_c))
        self.assertEqual(scanner.visible_large_paths(rows, "archive", "全部"), [r"D:\a.zip"])


class ThirdReviewTests(unittest.TestCase):
    def test_windows_temp_secrets_rejected_at_validate_and_execute(self):
        env = {
            "TEMP": r"C:\Users\me\AppData\Local\Temp",
            "TMP": r"C:\Users\me\AppData\Local\Temp",
            "LOCALAPPDATA": r"C:\Users\me\AppData\Local",
            "APPDATA": r"C:\Users\me\AppData\Roaming",
            "USERPROFILE": r"C:\Users\me",
            "SystemRoot": r"C:\Windows",
        }
        self.assertNotEqual(
            ruleupdate.remote_target_allowed(r"C:\Windows\Temp\secrets", env), "")
        self.assertNotEqual(
            ruleupdate.remote_target_allowed(r"%SystemRoot%\Temp\secrets", env), "")
        self.assertNotEqual(
            ruleupdate.remote_target_allowed(r"%TEMP%\..\Windows\Temp\secrets", env), "")
        self.assertNotEqual(
            ruleupdate.remote_target_allowed(r"\\server\share\Temp\secrets", env), "")
        self.assertNotEqual(
            ruleupdate.remote_target_allowed(r"C:\Users\me\AppData\Local\Temp\note.txt:secret", env), "")
        self.assertEqual(
            ruleupdate.remote_target_allowed(r"%TEMP%\Demo\Cache", env), "")

        root = tempfile.mkdtemp()
        old = {key: os.environ.get(key) for key in ("TEMP", "TMP", "LOCALAPPDATA", "SystemRoot", "USERPROFILE")}
        try:
            windows = os.path.join(root, "Windows")
            os.makedirs(os.path.join(windows, "Temp", "secrets"))
            secret = os.path.join(windows, "Temp", "secrets", "keep.txt")
            with open(secret, "w", encoding="utf-8") as handle:
                handle.write("keep")
            user_temp = os.path.join(root, "user-temp")
            os.makedirs(user_temp)
            os.environ["SystemRoot"] = windows
            os.environ["TEMP"] = user_temp
            os.environ["TMP"] = user_temp
            os.environ["LOCALAPPDATA"] = os.path.join(root, "Local")
            os.environ["USERPROFILE"] = os.path.join(root, "profile")
            cat = type("C", (), {
                "key": "remote", "name": "remote", "paths": [os.path.dirname(secret)],
                "kind": "files", "patterns": ("*",), "prune_dirs": False, "untrusted": True,
            })()
            result = cleaner.clean_category(cat)
            self.assertTrue(os.path.exists(secret))
            self.assertEqual(result.deleted, 0)
            with open(secret, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "keep")
        finally:
            for key, value in old.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
            shutil.rmtree(root, ignore_errors=True)

    def test_clean_root_symlink_is_not_followed(self):
        folder = tempfile.mkdtemp()
        try:
            real = os.path.join(folder, "real")
            os.makedirs(real)
            secret = os.path.join(real, "secret.txt")
            with open(secret, "w", encoding="utf-8") as handle:
                handle.write("alive")
            link = os.path.join(folder, "link")
            os.symlink(real, link, target_is_directory=True)
            cat = type("C", (), {
                "key": "t", "name": "t", "paths": [link],
                "kind": "files", "patterns": ("*",), "prune_dirs": False, "untrusted": False,
            })()
            cleaner.clean_category(cat)
            self.assertTrue(os.path.exists(secret))
            with open(secret, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "alive")
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_directory_migrate_keeps_source_if_it_changes_after_copy(self):
        src = tempfile.mkdtemp()
        dest_root = tempfile.mkdtemp()
        try:
            original = os.path.join(src, "a.txt")
            with open(original, "w", encoding="utf-8") as handle:
                handle.write("old-content")

            def drive(path):
                full = os.path.abspath(path)
                root = os.path.abspath(dest_root)
                if full == root or full.startswith(root + os.sep):
                    return "D:"
                return "C:"

            def robocopy(source, dest, move):
                os.makedirs(dest, exist_ok=True)
                for name in list(os.listdir(source)):
                    sp = os.path.join(source, name)
                    if os.path.isfile(sp) and not os.path.islink(sp):
                        shutil.copy2(sp, os.path.join(dest, name))
                with open(os.path.join(source, "a.txt"), "w", encoding="utf-8") as handle:
                    handle.write("new-content")
                return 0

            with mock.patch.object(migrate, "_drive_of", side_effect=drive), \
                    mock.patch.object(migrate, "_robocopy", side_effect=robocopy), \
                    mock.patch.object(migrate, "is_junction", return_value=False):
                with self.assertRaises(migrate.MigrateError):
                    migrate.migrate(src, dest_root)
            with open(original, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "new-content")
            copied = os.path.join(dest_root, os.path.basename(src), "a.txt")
            with open(copied, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "old-content")
        finally:
            shutil.rmtree(src, ignore_errors=True)
            shutil.rmtree(dest_root, ignore_errors=True)

    def test_single_file_migrate_detects_same_size_content_change(self):
        folder = tempfile.mkdtemp()
        dest_root = tempfile.mkdtemp(prefix="dest-")
        try:
            src = os.path.join(folder, "movie.bin")
            with open(src, "wb") as handle:
                handle.write(b"0123456789")

            def drive(path):
                full = os.path.abspath(path)
                root = os.path.abspath(dest_root)
                if full == root or full.startswith(root + os.sep):
                    return "D:"
                return "C:"

            real_copy = shutil.copy2

            def copy2(source, dest, *args, **kwargs):
                real_copy(source, dest, *args, **kwargs)
                with open(source, "wb") as handle:
                    handle.write(b"ABCDEFGHIJ")

            with mock.patch.object(migrate, "_drive_of", side_effect=drive), \
                    mock.patch("migrate.shutil.copy2", side_effect=copy2):
                with self.assertRaises(migrate.MigrateError):
                    migrate.migrate_file(src, dest_root)
            with open(src, "rb") as handle:
                self.assertEqual(handle.read(), b"ABCDEFGHIJ")
            with open(os.path.join(dest_root, "movie.bin"), "rb") as handle:
                self.assertEqual(handle.read(), b"0123456789")
        finally:
            shutil.rmtree(folder, ignore_errors=True)
            shutil.rmtree(dest_root, ignore_errors=True)

    def test_shred_failure_is_recorded_as_failed(self):
        folder = tempfile.mkdtemp()
        try:
            records = shredder.run_batch(
                [os.path.join(folder, "missing.bin")],
                shred_fn=lambda path: (_ for _ in ()).throw(shredder.ShredError("失败")),
            )
            self.assertEqual(records[0]["status"], "failed")
            history.append_shred_history(folder, records)
            rows = history.load_shred_history(folder)
            self.assertEqual(rows[0]["status"], "failed")
            self.assertNotEqual(rows[0]["status"], "ok")
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_rules_write_crash_keeps_previous_file(self):
        folder = tempfile.mkdtemp()
        path = os.path.join(folder, "rules.json")
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write('{"version": 1, "categories": [{"key": "old", "kind": "files"}]}\n')
            with mock.patch.object(ruleupdate, "RULES_PATH", path), \
                    mock.patch("ruleupdate.os.replace", side_effect=OSError("crash")):
                added, _total, err = ruleupdate.update_rules(
                    "https://example.com/rules.json",
                    opener=_OkOpener(b'{"categories": [{"key": "app_demo", "kind": "files", "paths": ["%TEMP%\\\\Cache"]}]}'),
                )
            self.assertNotEqual(added, 1)
            with open(path, encoding="utf-8") as handle:
                self.assertIn("old", handle.read())
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_privacy_count_without_action_is_not_selectable(self):
        record = {"id": "risk_money", "action": "files", "count": 4, "files": []}
        self.assertFalse(privacy.is_selectable(record))
        shop = {"id": "shop", "action": "sql", "count": 2, "files": [], "sql_jobs": [{"path": "h"}]}
        self.assertTrue(privacy.is_selectable(shop))


class _OkOpener:
    def __init__(self, payload):
        self.payload = payload

    def open(self, url, timeout=15):
        payload = self.payload

        class Resp:
            def read(self, n):
                return payload

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        return Resp()


class FourthReviewTests(unittest.TestCase):
    def _drive(self, dest_root):
        def drive(path):
            full = os.path.abspath(path)
            root = os.path.abspath(dest_root)
            if full == root or full.startswith(root + os.sep):
                return "D:"
            return "C:"
        return drive

    def test_large_file_middle_byte_blocks_directory_migrate(self):
        src = tempfile.mkdtemp()
        dest_root = tempfile.mkdtemp()
        try:
            payload = bytearray(b"A" * (9 * 1024 * 1024))
            original = os.path.join(src, "big.bin")
            with open(original, "wb") as handle:
                handle.write(payload)

            def robocopy(source, dest, move):
                os.makedirs(dest, exist_ok=True)
                for name in list(os.listdir(source)):
                    sp = os.path.join(source, name)
                    if os.path.isfile(sp) and not os.path.islink(sp):
                        shutil.copy2(sp, os.path.join(dest, name))
                with open(os.path.join(source, "big.bin"), "r+b") as handle:
                    handle.seek(4 * 1024 * 1024)
                    handle.write(b"B")
                return 0

            with mock.patch.object(migrate, "_drive_of", side_effect=self._drive(dest_root)), \
                    mock.patch.object(migrate, "_robocopy", side_effect=robocopy), \
                    mock.patch.object(migrate, "is_junction", return_value=False):
                with self.assertRaises(migrate.MigrateError):
                    migrate.migrate(src, dest_root)
            with open(original, "rb") as handle:
                handle.seek(4 * 1024 * 1024)
                self.assertEqual(handle.read(1), b"B")
            copied = os.path.join(dest_root, os.path.basename(src), "big.bin")
            with open(copied, "rb") as handle:
                handle.seek(4 * 1024 * 1024)
                self.assertEqual(handle.read(1), b"A")
        finally:
            shutil.rmtree(src, ignore_errors=True)
            shutil.rmtree(dest_root, ignore_errors=True)

    def test_large_file_middle_byte_blocks_single_file_migrate(self):
        folder = tempfile.mkdtemp()
        dest_root = tempfile.mkdtemp(prefix="dest-")
        try:
            src = os.path.join(folder, "big.bin")
            payload = bytearray(b"C" * (9 * 1024 * 1024))
            with open(src, "wb") as handle:
                handle.write(payload)
            real_copy = shutil.copy2

            def copy2(source, dest, *args, **kwargs):
                real_copy(source, dest, *args, **kwargs)
                with open(source, "r+b") as handle:
                    handle.seek(4 * 1024 * 1024)
                    handle.write(b"D")

            with mock.patch.object(migrate, "_drive_of", side_effect=self._drive(dest_root)), \
                    mock.patch("migrate.shutil.copy2", side_effect=copy2):
                with self.assertRaises(migrate.MigrateError):
                    migrate.migrate_file(src, dest_root)
            with open(src, "rb") as handle:
                handle.seek(4 * 1024 * 1024)
                self.assertEqual(handle.read(1), b"D")
            with open(os.path.join(dest_root, "big.bin"), "rb") as handle:
                handle.seek(4 * 1024 * 1024)
                self.assertEqual(handle.read(1), b"C")
        finally:
            shutil.rmtree(folder, ignore_errors=True)
            shutil.rmtree(dest_root, ignore_errors=True)

    def test_junction_create_failure_restores_source(self):
        src = tempfile.mkdtemp()
        dest_root = tempfile.mkdtemp()
        try:
            with open(os.path.join(src, "keep.txt"), "w", encoding="utf-8") as handle:
                handle.write("intact")

            def robocopy(source, dest, move):
                os.makedirs(dest, exist_ok=True)
                for name in list(os.listdir(source)):
                    sp = os.path.join(source, name)
                    if os.path.isfile(sp) and not os.path.islink(sp):
                        shutil.copy2(sp, os.path.join(dest, name))
                return 0

            with mock.patch.object(migrate, "_drive_of", side_effect=self._drive(dest_root)), \
                    mock.patch.object(migrate, "_robocopy", side_effect=robocopy), \
                    mock.patch.object(migrate, "is_junction", return_value=False), \
                    mock.patch.object(migrate, "create_junction",
                                      side_effect=migrate.MigrateError("联接失败")):
                with self.assertRaises(migrate.MigrateError):
                    migrate.migrate(src, dest_root)
            with open(os.path.join(src, "keep.txt"), encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "intact")
        finally:
            shutil.rmtree(src, ignore_errors=True)
            shutil.rmtree(dest_root, ignore_errors=True)

    def test_delete_refuses_parent_swapped_to_symlink(self):
        folder = tempfile.mkdtemp()
        try:
            allowed = os.path.join(folder, "allowed")
            outside = os.path.join(folder, "outside")
            os.makedirs(allowed)
            os.makedirs(outside)
            secret = os.path.join(outside, "victim.txt")
            with open(secret, "w", encoding="utf-8") as handle:
                handle.write("keep-outside")
            link = os.path.join(folder, "link")
            os.symlink(outside, link)
            cat = type("C", (), {
                "key": "t", "name": "t", "kind": "files",
                "paths": [link], "patterns": ("*",), "prune_dirs": False,
                "untrusted": False,
            })()
            cleaner.clean_category(cat)
            self.assertTrue(os.path.exists(secret))
            with open(secret, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "keep-outside")
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_unlink_rechecks_parent_immediately_before_delete(self):
        folder = tempfile.mkdtemp()
        try:
            allowed = os.path.join(folder, "allowed")
            outside = os.path.join(folder, "outside")
            os.makedirs(allowed)
            os.makedirs(outside)
            victim = os.path.join(allowed, "victim.txt")
            secret = os.path.join(outside, "victim.txt")
            with open(victim, "w", encoding="utf-8") as handle:
                handle.write("local")
            with open(secret, "w", encoding="utf-8") as handle:
                handle.write("secret")
            real_open = os.open

            def raced_open(path, flags, *args, **kwargs):
                fd = real_open(path, flags, *args, **kwargs)
                # 挂在 unlink_regular 真正打开文件的那一步，而不是 os.remove。
                if (os.path.basename(str(path)) == "victim.txt"
                        and kwargs.get("dir_fd") is not None
                        and not os.path.islink(allowed)):
                    os.rename(allowed, allowed + ".moved")
                    os.symlink(outside, allowed, target_is_directory=True)
                return fd

            cat = type("C", (), {"key": "t", "name": "t"})()
            result = cleaner.CleanResult(cat)
            with mock.patch("safepath.os.open", side_effect=raced_open):
                cleaner._delete_file(victim, [allowed], ("*",), result)
            moved = os.path.join(allowed + ".moved", "victim.txt")
            self.assertEqual(result.deleted, 0)
            self.assertTrue(os.path.isfile(moved))
            with open(moved, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "local")
            with open(secret, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "secret")
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_fastscan_rejects_symlink_root(self):
        import fastscan
        folder = tempfile.mkdtemp()
        try:
            real = os.path.join(folder, "real")
            os.makedirs(real)
            with open(os.path.join(real, "secret.txt"), "w", encoding="utf-8") as handle:
                handle.write("x")
            link = os.path.join(folder, "link")
            os.symlink(real, link, target_is_directory=True)
            found = fastscan.iter_files(link, min_size=0)
            self.assertEqual(found, [])
        finally:
            shutil.rmtree(folder, ignore_errors=True)


class FifthReviewTests(unittest.TestCase):
    def _drive(self, dest_root):
        def drive(path):
            full = os.path.abspath(path)
            root = os.path.abspath(dest_root)
            if full == root or full.startswith(root + os.sep):
                return "D:"
            return "C:"
        return drive

    def test_directory_backup_added_file_is_not_deleted(self):
        src = tempfile.mkdtemp()
        dest_root = tempfile.mkdtemp()
        try:
            with open(os.path.join(src, "keep.txt"), "w", encoding="utf-8") as handle:
                handle.write("original")

            def robocopy(source, dest, move):
                os.makedirs(dest, exist_ok=True)
                for name in list(os.listdir(source)):
                    sp = os.path.join(source, name)
                    if os.path.isfile(sp) and not os.path.islink(sp):
                        shutil.copy2(sp, os.path.join(dest, name))
                return 0

            def plant_and_link(link, target):
                backup = link.rstrip("\\/") + ".migrate-bak"
                with open(os.path.join(backup, "extra.txt"), "w", encoding="utf-8") as handle:
                    handle.write("added-during-window")
                os.symlink(target, link, target_is_directory=True)

            with mock.patch.object(migrate, "_drive_of", side_effect=self._drive(dest_root)), \
                    mock.patch.object(migrate, "_robocopy", side_effect=robocopy), \
                    mock.patch.object(migrate, "is_junction", return_value=False), \
                    mock.patch.object(migrate, "create_junction", side_effect=plant_and_link):
                result = migrate.migrate(src, dest_root)
            backup = src.rstrip("\\/") + ".migrate-bak"
            extra = os.path.join(backup, "extra.txt")
            self.assertTrue(os.path.isfile(extra))
            with open(extra, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "added-during-window")
            self.assertFalse(self._succeeded(result))
            self.assertIn(".migrate-bak", getattr(result, "backup", ""))
        finally:
            shutil.rmtree(src, ignore_errors=True)
            shutil.rmtree(dest_root, ignore_errors=True)
            shutil.rmtree(src.rstrip("\\/") + ".migrate-bak", ignore_errors=True)

    def test_single_file_change_before_delete_keeps_backup(self):
        folder = tempfile.mkdtemp()
        dest_root = tempfile.mkdtemp(prefix="dest-")
        try:
            src = os.path.join(folder, "movie.bin")
            with open(src, "wb") as handle:
                handle.write(b"0123456789")
            hits = {"n": 0}
            real = migrate._fingerprint

            def fingerprint(path):
                mark = real(path)
                if os.path.abspath(path) == os.path.abspath(src):
                    hits["n"] += 1
                    if hits["n"] == 3:
                        with open(path, "ab") as handle:
                            handle.write(b"X")
                return mark

            with mock.patch.object(migrate, "_drive_of", side_effect=self._drive(dest_root)), \
                    mock.patch.object(migrate, "_fingerprint", side_effect=fingerprint):
                result = migrate.migrate_file(src, dest_root)
            self.assertFalse(self._succeeded(result))
            backup = src + ".migrate-bak"
            self.assertTrue(os.path.isfile(backup))
            with open(backup, "rb") as handle:
                self.assertEqual(handle.read(), b"0123456789X")
            with open(os.path.join(dest_root, "movie.bin"), "rb") as handle:
                self.assertEqual(handle.read(), b"0123456789")
        finally:
            shutil.rmtree(folder, ignore_errors=True)
            shutil.rmtree(dest_root, ignore_errors=True)

    def _succeeded(self, result):
        if isinstance(result, tuple):
            return True
        return bool(getattr(result, "ok", False))

    def test_file_added_before_rmdir_survives_and_is_not_success(self):
        src = tempfile.mkdtemp()
        dest_root = tempfile.mkdtemp()
        try:
            with open(os.path.join(src, "keep.txt"), "w", encoding="utf-8") as handle:
                handle.write("original")

            def robocopy(source, dest, move):
                os.makedirs(dest, exist_ok=True)
                for name in list(os.listdir(source)):
                    sp = os.path.join(source, name)
                    if os.path.isfile(sp) and not os.path.islink(sp):
                        shutil.copy2(sp, os.path.join(dest, name))
                return 0

            def link(link_path, target):
                os.symlink(target, link_path, target_is_directory=True)

            real_rmdir = os.rmdir

            def rmdir(path, *args, **kwargs):
                if str(path).rstrip("\\/").endswith(".migrate-bak"):
                    extra = os.path.join(path, "extra.txt")
                    if not os.path.exists(extra):
                        with open(extra, "w", encoding="utf-8") as handle:
                            handle.write("added-before-rmdir")
                return real_rmdir(path, *args, **kwargs)

            with mock.patch.object(migrate, "_drive_of", side_effect=self._drive(dest_root)), \
                    mock.patch.object(migrate, "_robocopy", side_effect=robocopy), \
                    mock.patch.object(migrate, "is_junction", return_value=False), \
                    mock.patch.object(migrate, "create_junction", side_effect=link), \
                    mock.patch("migrate.os.rmdir", side_effect=rmdir):
                result = migrate.migrate(src, dest_root)
            extra = os.path.join(src.rstrip("\\/") + ".migrate-bak", "extra.txt")
            self.assertTrue(os.path.isfile(extra))
            with open(extra, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "added-before-rmdir")
            self.assertFalse(self._succeeded(result))
            self.assertIn("extra.txt", " ".join(getattr(result, "remaining", ())))
            self.assertIn(".migrate-bak", getattr(result, "backup", ""))
        finally:
            shutil.rmtree(src, ignore_errors=True)
            shutil.rmtree(dest_root, ignore_errors=True)
            shutil.rmtree(src.rstrip("\\/") + ".migrate-bak", ignore_errors=True)

    def test_append_at_delete_survives_and_is_not_success(self):
        folder = tempfile.mkdtemp()
        dest_root = tempfile.mkdtemp(prefix="dest-")
        try:
            src = os.path.join(folder, "movie.bin")
            with open(src, "wb") as handle:
                handle.write(b"0123456789")
            backup = src + ".migrate-bak"
            real_open = os.open
            did = {"n": 0}

            def hooked_open(path, flags, *args, **kwargs):
                name = os.path.basename(str(path))
                directory = bool(flags & getattr(os, "O_DIRECTORY", 0))
                if name == os.path.basename(backup) and not directory and not did["n"]:
                    did["n"] = 1
                    with open(backup, "ab") as handle:
                        handle.write(b"APPENDED")
                return real_open(path, flags, *args, **kwargs)

            with mock.patch.object(migrate, "_drive_of", side_effect=self._drive(dest_root)), \
                    mock.patch("safepath.os.open", side_effect=hooked_open), \
                    mock.patch("migrate.os.open", side_effect=hooked_open):
                result = migrate.migrate_file(src, dest_root)
            self.assertTrue(os.path.isfile(backup))
            with open(backup, "rb") as handle:
                self.assertEqual(handle.read(), b"0123456789APPENDED")
            with open(os.path.join(dest_root, "movie.bin"), "rb") as handle:
                self.assertEqual(handle.read(), b"0123456789")
            self.assertFalse(self._succeeded(result))
            self.assertIn(backup, getattr(result, "remaining", ()))
        finally:
            shutil.rmtree(folder, ignore_errors=True)
            shutil.rmtree(dest_root, ignore_errors=True)

    def test_shred_swap_before_open_leaves_external_file(self):
        folder = tempfile.mkdtemp()
        try:
            local = os.path.join(folder, "local.txt")
            external = os.path.join(folder, "external.txt")
            with open(local, "w", encoding="utf-8") as handle:
                handle.write("LOCALDATA")
            with open(external, "w", encoding="utf-8") as handle:
                handle.write("EXTERNAL")
            swapped = {"done": False}
            real_lstat = os.lstat

            def lstat(path, *args, **kwargs):
                info = real_lstat(path, *args, **kwargs)
                if (not swapped["done"] and os.path.abspath(path) == os.path.abspath(local)
                        and not stat.S_ISLNK(info.st_mode)):
                    swapped["done"] = True
                    os.rename(local, local + ".real")
                    os.symlink(external, local)
                return info

            with mock.patch("os.lstat", side_effect=lstat):
                with self.assertRaises(Exception):
                    shredder.shred_file(local)
            with open(external, "rb") as handle:
                self.assertEqual(handle.read(), b"EXTERNAL")
            with open(local + ".real", "rb") as handle:
                self.assertEqual(handle.read(), b"LOCALDATA")
        finally:
            shutil.rmtree(folder, ignore_errors=True)


class SixthReviewTests(unittest.TestCase):
    def _drive(self, dest_root):
        def drive(path):
            full = os.path.abspath(path)
            root = os.path.abspath(dest_root)
            if full == root or full.startswith(root + os.sep):
                return "D:"
            return "C:"
        return drive

    def _plain_success(self, result):
        if result is None or isinstance(result, (tuple, str)):
            return True
        if isinstance(result, migrate.MigrateResult):
            return result.ok
        return False

    def _listed(self, result):
        if isinstance(result, migrate.MigrateResult):
            return result.warning + "\n" + "\n".join(result.remaining)
        return str(result)

    def _assert_sneaky_kept(self, victim_dir, result):
        sneaky = os.path.join(victim_dir, "sneaky.txt")
        self.assertTrue(os.path.isfile(sneaky))
        with open(sneaky, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "sneaky-data")
        self.assertFalse(self._plain_success(result))
        self.assertIn("sneaky.txt", self._listed(result))

    def test_copy_failure_added_file_survives_and_is_not_success(self):
        src = tempfile.mkdtemp()
        dest_root = tempfile.mkdtemp()
        try:
            with open(os.path.join(src, "a.txt"), "w", encoding="utf-8") as handle:
                handle.write("keep")

            def robocopy(source, dest, move):
                os.makedirs(dest, exist_ok=True)
                for name in os.listdir(source):
                    sp = os.path.join(source, name)
                    if os.path.isfile(sp) and not os.path.islink(sp):
                        shutil.copy2(sp, os.path.join(dest, name))
                return 16

            victim = None

            def robocopy_capture(source, dest, move):
                nonlocal victim
                victim = dest
                return robocopy(source, dest, move)

            with mock.patch.object(migrate, "_drive_of", side_effect=self._drive(dest_root)), \
                    mock.patch.object(migrate, "_robocopy", side_effect=robocopy_capture), \
                    mock.patch.object(migrate, "is_junction", return_value=False):
                # Hooks are bound after robocopy creates dest; plant uses the dest path.
                real_remove = os.remove
                real_open = os.open
                planted = {"done": False}

                def plant():
                    if planted["done"] or not victim:
                        return
                    planted["done"] = True
                    with open(os.path.join(victim, "sneaky.txt"), "w", encoding="utf-8") as handle:
                        handle.write("sneaky-data")

                def remove(path, *args, **kwargs):
                    if victim and str(path).startswith(victim):
                        plant()
                    return real_remove(path, *args, **kwargs)

                def hooked_open(path, flags, *args, **kwargs):
                    directory = bool(flags & getattr(os, "O_DIRECTORY", 0))
                    if victim and not directory and os.path.basename(str(path)) == "a.txt":
                        plant()
                    return real_open(path, flags, *args, **kwargs)

                with mock.patch("migrate.os.remove", side_effect=remove), \
                        mock.patch("migrate.os.open", side_effect=hooked_open):
                    try:
                        result = migrate.migrate(src, dest_root)
                    except migrate.MigrateError as exc:
                        result = exc
            self._assert_sneaky_kept(victim, result)
        finally:
            shutil.rmtree(src, ignore_errors=True)
            shutil.rmtree(dest_root, ignore_errors=True)

    def test_junction_failure_added_file_survives_and_is_not_success(self):
        src = tempfile.mkdtemp()
        dest_root = tempfile.mkdtemp()
        try:
            with open(os.path.join(src, "a.txt"), "w", encoding="utf-8") as handle:
                handle.write("keep")

            def robocopy(source, dest, move):
                os.makedirs(dest, exist_ok=True)
                for name in os.listdir(source):
                    sp = os.path.join(source, name)
                    if os.path.isfile(sp) and not os.path.islink(sp):
                        shutil.copy2(sp, os.path.join(dest, name))
                return 1

            victim = {"path": ""}

            def capture_robocopy(source, dest, move):
                victim["path"] = dest
                return robocopy(source, dest, move)

            real_remove = os.remove
            real_open = os.open
            planted = {"done": False}

            def plant():
                if planted["done"] or not victim["path"]:
                    return
                planted["done"] = True
                with open(os.path.join(victim["path"], "sneaky.txt"), "w", encoding="utf-8") as handle:
                    handle.write("sneaky-data")

            def remove(path, *args, **kwargs):
                if victim["path"] and str(path).startswith(victim["path"]):
                    plant()
                return real_remove(path, *args, **kwargs)

            def hooked_open(path, flags, *args, **kwargs):
                directory = bool(flags & getattr(os, "O_DIRECTORY", 0))
                if (victim["path"] and not directory and kwargs.get("dir_fd") is not None
                        and os.path.basename(str(path)) == "a.txt"):
                    plant()
                return real_open(path, flags, *args, **kwargs)

            with mock.patch.object(migrate, "_drive_of", side_effect=self._drive(dest_root)), \
                    mock.patch.object(migrate, "_robocopy", side_effect=capture_robocopy), \
                    mock.patch.object(migrate, "create_junction",
                                      side_effect=lambda link, target: os.makedirs(link, exist_ok=True)), \
                    mock.patch.object(migrate, "junction_works", return_value=False), \
                    mock.patch.object(migrate, "is_junction", return_value=False), \
                    mock.patch("migrate.os.remove", side_effect=remove), \
                    mock.patch("migrate.os.open", side_effect=hooked_open):
                try:
                    result = migrate.migrate(src, dest_root)
                except migrate.MigrateError as exc:
                    result = exc
            self._assert_sneaky_kept(victim["path"], result)
        finally:
            shutil.rmtree(src, ignore_errors=True)
            shutil.rmtree(dest_root, ignore_errors=True)

    def test_rollback_added_file_survives_and_is_not_success(self):
        src = tempfile.mkdtemp()
        dest = tempfile.mkdtemp()
        try:
            with open(os.path.join(dest, "a.txt"), "w", encoding="utf-8") as handle:
                handle.write("copied")

            def robocopy(source, target, move):
                os.makedirs(target, exist_ok=True)
                for name in os.listdir(source):
                    sp = os.path.join(source, name)
                    if os.path.isfile(sp) and not os.path.islink(sp):
                        shutil.copy2(sp, os.path.join(target, name))
                return 1

            real_unlink_name = safepath._unlink_name_if_inode
            planted = {"done": False}

            def plant():
                if planted["done"]:
                    return
                planted["done"] = True
                with open(os.path.join(dest, "sneaky.txt"), "w", encoding="utf-8") as handle:
                    handle.write("sneaky-data")

            def hooked_unlink_name(name, dirfd, expected, path="", **kwargs):
                if os.path.abspath(path).startswith(os.path.abspath(dest) + os.sep):
                    plant()
                return real_unlink_name(name, dirfd, expected, path, **kwargs)

            with mock.patch.object(migrate, "_robocopy", side_effect=robocopy), \
                    mock.patch("migrate.safepath._unlink_name_if_inode",
                               side_effect=hooked_unlink_name):
                try:
                    result = migrate._rollback_to_source(src, dest)
                except migrate.MigrateError as exc:
                    result = exc
            self._assert_sneaky_kept(dest, result)
        finally:
            shutil.rmtree(src, ignore_errors=True)
            shutil.rmtree(dest, ignore_errors=True)

    def test_undo_added_file_survives_and_is_not_success(self):
        src = tempfile.mkdtemp()
        target = tempfile.mkdtemp()
        try:
            with open(os.path.join(target, "a.txt"), "w", encoding="utf-8") as handle:
                handle.write("moved")

            def robocopy(source, dest, move):
                os.makedirs(dest, exist_ok=True)
                for name in os.listdir(source):
                    sp = os.path.join(source, name)
                    if os.path.isfile(sp) and not os.path.islink(sp) and name != "sneaky.txt":
                        shutil.copy2(sp, os.path.join(dest, name))
                return 1

            real_remove = os.remove
            real_open = os.open
            planted = {"done": False}

            def plant():
                if planted["done"]:
                    return
                planted["done"] = True
                with open(os.path.join(target, "sneaky.txt"), "w", encoding="utf-8") as handle:
                    handle.write("sneaky-data")

            def remove(path, *args, **kwargs):
                if str(path).startswith(target):
                    plant()
                return real_remove(path, *args, **kwargs)

            def hooked_open(path, flags, *args, **kwargs):
                directory = bool(flags & getattr(os, "O_DIRECTORY", 0))
                if not directory and os.path.basename(str(path)) == "a.txt":
                    plant()
                return real_open(path, flags, *args, **kwargs)

            def is_junction(path):
                return os.path.abspath(path) == os.path.abspath(src)

            with mock.patch.object(migrate, "is_junction", side_effect=is_junction), \
                    mock.patch.object(migrate, "junction_target", return_value=target), \
                    mock.patch.object(migrate, "_robocopy", side_effect=robocopy), \
                    mock.patch("migrate.os.remove", side_effect=remove), \
                    mock.patch("migrate.os.open", side_effect=hooked_open):
                try:
                    result = migrate.undo(src)
                except migrate.MigrateError as exc:
                    result = exc
            self._assert_sneaky_kept(target, result)
        finally:
            shutil.rmtree(src, ignore_errors=True)
            shutil.rmtree(target, ignore_errors=True)

    def test_restore_renamed_source_added_file_survives_and_is_not_success(self):
        src = tempfile.mkdtemp()
        dest_root = tempfile.mkdtemp()
        try:
            with open(os.path.join(src, "a.txt"), "w", encoding="utf-8") as handle:
                handle.write("keep")

            def robocopy(source, dest, move):
                os.makedirs(dest, exist_ok=True)
                for name in os.listdir(source):
                    sp = os.path.join(source, name)
                    if os.path.isfile(sp) and not os.path.islink(sp):
                        shutil.copy2(sp, os.path.join(dest, name))
                return 1

            real_rmdir = os.rmdir
            planted = {"done": False}

            def rmdir(path, *args, **kwargs):
                if os.path.abspath(path) == os.path.abspath(src) and not planted["done"]:
                    planted["done"] = True
                    with open(os.path.join(path, "sneaky.txt"), "w", encoding="utf-8") as handle:
                        handle.write("sneaky-data")
                return real_rmdir(path, *args, **kwargs)

            with mock.patch.object(migrate, "_drive_of", side_effect=self._drive(dest_root)), \
                    mock.patch.object(migrate, "_robocopy", side_effect=robocopy), \
                    mock.patch.object(migrate, "create_junction",
                                      side_effect=lambda link, target: os.makedirs(link, exist_ok=True)), \
                    mock.patch.object(migrate, "junction_works", return_value=False), \
                    mock.patch.object(migrate, "is_junction", return_value=False), \
                    mock.patch("migrate.os.rmdir", side_effect=rmdir):
                try:
                    result = migrate.migrate(src, dest_root)
                except Exception as exc:
                    result = exc
            self._assert_sneaky_kept(src, result)
            backup = src.rstrip("\\/") + ".migrate-bak"
            self.assertTrue(os.path.isfile(os.path.join(backup, "a.txt")))
        finally:
            shutil.rmtree(src, ignore_errors=True)
            shutil.rmtree(dest_root, ignore_errors=True)
            shutil.rmtree(src.rstrip("\\/") + ".migrate-bak", ignore_errors=True)


class SeventhReviewTests(unittest.TestCase):
    def _drive(self, dest_root):
        def drive(path):
            full = os.path.abspath(path)
            root = os.path.abspath(dest_root)
            if full == root or full.startswith(root + os.sep):
                return "D:"
            return "C:"
        return drive

    def _not_success(self, result):
        if isinstance(result, migrate.MigrateResult):
            return not result.ok
        return False

    def test_single_file_append_before_unlink_is_preserved(self):
        folder = tempfile.mkdtemp()
        dest_root = tempfile.mkdtemp(prefix="dest-")
        try:
            src = os.path.join(folder, "movie.bin")
            with open(src, "wb") as handle:
                handle.write(b"0123456789")
            backup = src + ".migrate-bak"
            real_unlink_name = safepath._unlink_name_if_inode
            did = {"n": 0}

            def hooked_unlink_name(name, dirfd, expected, path="", **kwargs):
                if os.path.abspath(path) == os.path.abspath(backup) and not did["n"]:
                    did["n"] = 1
                    with open(backup, "ab") as handle:
                        handle.write(b"APPENDED")
                return real_unlink_name(name, dirfd, expected, path, **kwargs)

            with mock.patch.object(migrate, "_drive_of", side_effect=self._drive(dest_root)), \
                    mock.patch("migrate.safepath._unlink_name_if_inode",
                               side_effect=hooked_unlink_name):
                result = migrate.migrate_file(src, dest_root)
            preserved = b""
            for path in (backup, backup + ".migrate-recovered"):
                if os.path.isfile(path):
                    with open(path, "rb") as handle:
                        preserved = handle.read()
                    break
            self.assertEqual(preserved, b"0123456789APPENDED")
            with open(os.path.join(dest_root, "movie.bin"), "rb") as handle:
                self.assertEqual(handle.read(), b"0123456789")
            self.assertTrue(self._not_success(result))
            self.assertIn(b"APPENDED", self._listed_bytes(result))
        finally:
            shutil.rmtree(folder, ignore_errors=True)
            shutil.rmtree(dest_root, ignore_errors=True)

    def _listed_bytes(self, result):
        if not isinstance(result, migrate.MigrateResult):
            return b""
        blob = result.warning.encode("utf-8", "replace")
        for path in result.remaining:
            if os.path.isfile(path):
                with open(path, "rb") as handle:
                    blob += handle.read()
        return blob

    def test_directory_append_before_unlink_is_preserved(self):
        src = tempfile.mkdtemp()
        dest_root = tempfile.mkdtemp()
        try:
            with open(os.path.join(src, "keep.txt"), "wb") as handle:
                handle.write(b"original")

            def robocopy(source, dest, move):
                os.makedirs(dest, exist_ok=True)
                for name in os.listdir(source):
                    sp = os.path.join(source, name)
                    if os.path.isfile(sp) and not os.path.islink(sp):
                        shutil.copy2(sp, os.path.join(dest, name))
                return 0

            def link(link_path, target):
                os.symlink(target, link_path, target_is_directory=True)

            backup = src.rstrip("\\/") + ".migrate-bak"
            target = os.path.join(backup, "keep.txt")
            real_unlink_name = safepath._unlink_name_if_inode
            did = {"n": 0}

            def hooked_unlink_name(name, dirfd, expected, path="", **kwargs):
                if os.path.abspath(path) == os.path.abspath(target) and not did["n"]:
                    did["n"] = 1
                    with open(target, "ab") as handle:
                        handle.write(b"APPENDED")
                return real_unlink_name(name, dirfd, expected, path, **kwargs)

            with mock.patch.object(migrate, "_drive_of", side_effect=self._drive(dest_root)), \
                    mock.patch.object(migrate, "_robocopy", side_effect=robocopy), \
                    mock.patch.object(migrate, "is_junction", return_value=False), \
                    mock.patch.object(migrate, "create_junction", side_effect=link), \
                    mock.patch("migrate.safepath._unlink_name_if_inode",
                               side_effect=hooked_unlink_name):
                result = migrate.migrate(src, dest_root)
            preserved = b""
            for path in (target, target + ".migrate-recovered"):
                if os.path.isfile(path):
                    with open(path, "rb") as handle:
                        preserved = handle.read()
                    break
            self.assertEqual(preserved, b"originalAPPENDED")
            self.assertTrue(self._not_success(result))
            self.assertIn("keep.txt", result.warning)
        finally:
            shutil.rmtree(src, ignore_errors=True)
            shutil.rmtree(dest_root, ignore_errors=True)
            shutil.rmtree(backup, ignore_errors=True)


class SafetyRaceRegressionTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX dir-fd deletion path")
    def test_cleaner_does_not_delete_leaf_replacement(self):
        folder = tempfile.mkdtemp()
        try:
            allowed = os.path.join(folder, "allowed")
            os.makedirs(allowed)
            victim = os.path.join(allowed, "victim.txt")
            replacement = os.path.join(allowed, "replacement.txt")
            with open(victim, "wb") as handle:
                handle.write(b"opened original")
            with open(replacement, "wb") as handle:
                handle.write(b"replacement data")

            cat = type("C", (), {"key": "race", "name": "race"})()
            result = cleaner.CleanResult(cat)
            real_rename = os.rename
            raced = {"done": False}

            def swap_before_capture(src, dst, *args, **kwargs):
                if (str(src) == "victim.txt" and kwargs.get("src_dir_fd") is not None
                        and not raced["done"]):
                    raced["done"] = True
                    real_rename(victim, victim + ".opened-original")
                    real_rename(replacement, victim)
                return real_rename(src, dst, *args, **kwargs)

            with mock.patch("safepath.os.rename", side_effect=swap_before_capture):
                cleaner._delete_file(victim, [allowed], ("*",), result)

            self.assertEqual(result.deleted, 0)
            self.assertEqual(result.skipped, 1)
            self.assertEqual(result.pending, 0)
            with open(victim, "rb") as handle:
                self.assertEqual(handle.read(), b"replacement data")
            with open(victim + ".opened-original", "rb") as handle:
                self.assertEqual(handle.read(), b"opened original")
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    @unittest.skipIf(os.name == "nt", "POSIX dir-fd deletion path")
    def test_rollback_link_delete_does_not_remove_replacement_file(self):
        folder = tempfile.mkdtemp()
        try:
            target = os.path.join(folder, "target.txt")
            link = os.path.join(folder, "link")
            with open(target, "wb") as handle:
                handle.write(b"target stays")
            os.symlink(target, link)
            real_rename = os.rename
            raced = {"done": False}

            def replace_link_before_capture(src, dst, *args, **kwargs):
                if (str(src) == "link" and kwargs.get("src_dir_fd") is not None
                        and not raced["done"]):
                    raced["done"] = True
                    real_rename(link, link + ".opened-link")
                    with open(link, "wb") as handle:
                        handle.write(b"replacement file")
                return real_rename(src, dst, *args, **kwargs)

            with mock.patch("migrate.os.rename", side_effect=replace_link_before_capture):
                self.assertFalse(migrate._unlink_link_only(link))

            with open(link, "rb") as handle:
                self.assertEqual(handle.read(), b"replacement file")
            self.assertTrue(os.path.islink(link + ".opened-link"))
            with open(target, "rb") as handle:
                self.assertEqual(handle.read(), b"target stays")
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    @unittest.skipIf(os.name == "nt", "POSIX backup recovery path")
    def test_drop_covered_rechecks_survivor_after_inventory_snapshot(self):
        backup = tempfile.mkdtemp()
        survivor = tempfile.mkdtemp()
        try:
            backup_file = os.path.join(backup, "data.bin")
            survivor_file = os.path.join(survivor, "data.bin")
            for path in (backup_file, survivor_file):
                with open(path, "wb") as handle:
                    handle.write(b"known-good")

            real_inventory = migrate.file_inventory
            changed = {"done": False}

            def stale_snapshot_then_change(root):
                inventory = real_inventory(root)
                if os.path.abspath(root) == os.path.abspath(survivor) and not changed["done"]:
                    changed["done"] = True
                    with open(survivor_file, "wb") as handle:
                        handle.write(b"changed after scan")
                return inventory

            with mock.patch.object(migrate, "file_inventory",
                                   side_effect=stale_snapshot_then_change):
                remaining = migrate._drop_covered(backup, survivor)

            self.assertTrue(os.path.isfile(backup_file))
            with open(backup_file, "rb") as handle:
                self.assertEqual(handle.read(), b"known-good")
            self.assertIn(backup_file, remaining)
        finally:
            shutil.rmtree(backup, ignore_errors=True)
            shutil.rmtree(survivor, ignore_errors=True)

    @unittest.skipIf(os.name == "nt", "POSIX backup recovery path")
    def test_drop_covered_restores_backup_if_survivor_changes_during_delete(self):
        backup = tempfile.mkdtemp()
        survivor = tempfile.mkdtemp()
        try:
            backup_file = os.path.join(backup, "data.bin")
            survivor_file = os.path.join(survivor, "data.bin")
            for path in (backup_file, survivor_file):
                with open(path, "wb") as handle:
                    handle.write(b"known-good")

            real_unlink_name = safepath._unlink_name_if_inode
            changed = {"done": False}

            def delete_then_change_survivor(name, dirfd, expected, path="", **kwargs):
                result = real_unlink_name(name, dirfd, expected, path, **kwargs)
                if os.path.abspath(path) == os.path.abspath(backup_file) and not changed["done"]:
                    changed["done"] = True
                    with open(survivor_file, "wb") as handle:
                        handle.write(b"changed during deletion")
                return result

            with mock.patch("migrate.safepath._unlink_name_if_inode",
                            side_effect=delete_then_change_survivor):
                remaining = migrate._drop_covered(backup, survivor)

            self.assertTrue(os.path.isfile(backup_file))
            with open(backup_file, "rb") as handle:
                self.assertEqual(handle.read(), b"known-good")
            with open(survivor_file, "rb") as handle:
                self.assertEqual(handle.read(), b"changed during deletion")
            self.assertIn(backup_file, remaining)
        finally:
            shutil.rmtree(backup, ignore_errors=True)
            shutil.rmtree(survivor, ignore_errors=True)

    def test_write_exclusive_rejects_zero_and_incomplete_short_writes(self):
        folder = tempfile.mkdtemp()
        try:
            payload = b"complete recovery payload"
            path = os.path.join(folder, "recovered.bin")
            with mock.patch("migrate.os.write", return_value=0):
                self.assertEqual(migrate._write_exclusive(path, payload), "")
            self.assertFalse(os.path.lexists(path))
            self.assertFalse(os.path.lexists(path + ".migrate-recovered"))

            real_write = os.write
            calls = {"n": 0}

            def partial_then_zero(fd, view):
                calls["n"] += 1
                if calls["n"] % 2:
                    return real_write(fd, view[:min(3, len(view))])
                return 0

            with mock.patch("migrate.os.write", side_effect=partial_then_zero):
                self.assertEqual(migrate._write_exclusive(path, payload), "")
            self.assertFalse(os.path.lexists(path))
            self.assertFalse(os.path.lexists(path + ".migrate-recovered"))
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_write_exclusive_completes_valid_short_writes(self):
        folder = tempfile.mkdtemp()
        try:
            path = os.path.join(folder, "recovered.bin")
            payload = b"all short writes must finish"
            real_write = os.write

            def short_write(fd, view):
                return real_write(fd, view[:min(2, len(view))])

            with mock.patch("migrate.os.write", side_effect=short_write):
                written_path = migrate._write_exclusive(path, payload)
            self.assertEqual(written_path, path)
            with open(path, "rb") as handle:
                self.assertEqual(handle.read(), payload)
        finally:
            shutil.rmtree(folder, ignore_errors=True)


@unittest.skipIf(os.name == "nt", "该回归覆盖 POSIX 源文件快照优化路径")
class PosixSourceSnapshotTests(unittest.TestCase):
    def test_directory_migrate_rechecks_content_when_source_snapshot_matches(self):
        src = tempfile.mkdtemp()
        dest_root = tempfile.mkdtemp()
        source_file = os.path.join(src, "item.bin")
        dest_file = os.path.join(dest_root, os.path.basename(src), "item.bin")
        backup = src.rstrip("\\/") + ".migrate-bak"
        try:
            with open(source_file, "wb") as handle:
                handle.write(b"known-good")
            stable_snapshot = migrate._identity_tuple(os.lstat(source_file))

            def drive(path):
                full = os.path.abspath(path)
                root = os.path.abspath(dest_root)
                return "D:" if full == root or full.startswith(root + os.sep) else "C:"

            def robocopy(source, dest, move):
                os.makedirs(dest, exist_ok=True)
                shutil.copy2(source_file, os.path.join(dest, "item.bin"))
                before = os.stat(source_file)
                with open(source_file, "wb") as handle:
                    handle.write(b"changed!!!")
                os.utime(source_file, ns=(before.st_atime_ns, before.st_mtime_ns))
                return 0

            def link(link_path, target):
                os.symlink(target, link_path, target_is_directory=True)

            with mock.patch.object(migrate, "_drive_of", side_effect=drive), \
                    mock.patch.object(migrate, "_robocopy", side_effect=robocopy), \
                    mock.patch.object(migrate, "is_junction", return_value=False), \
                    mock.patch.object(migrate, "create_junction", side_effect=link), \
                    mock.patch.object(migrate, "_tree_metadata_still", return_value=True), \
                    mock.patch.object(migrate, "_identity_tuple", return_value=stable_snapshot):
                with self.assertRaisesRegex(migrate.MigrateError, "源目录在复制后发生变化"):
                    migrate.migrate(src, dest_root)

            with open(source_file, "rb") as handle:
                self.assertEqual(handle.read(), b"changed!!!")
            with open(dest_file, "rb") as handle:
                self.assertEqual(handle.read(), b"known-good")
        finally:
            if os.path.islink(src):
                os.unlink(src)
            else:
                shutil.rmtree(src, ignore_errors=True)
            shutil.rmtree(dest_root, ignore_errors=True)
            shutil.rmtree(backup, ignore_errors=True)


class HashBudgetTests(unittest.TestCase):
    def test_directory_migrate_reads_each_file_at_most_twice(self):
        src = tempfile.mkdtemp()
        dest_root = tempfile.mkdtemp()
        try:
            with open(os.path.join(src, "keep.txt"), "wb") as handle:
                handle.write(b"hash-budget")
            source_info = os.stat(os.path.join(src, "keep.txt"))

            def drive(path):
                full = os.path.abspath(path)
                root = os.path.abspath(dest_root)
                if full == root or full.startswith(root + os.sep):
                    return "D:"
                return "C:"

            def robocopy(source, dest, move):
                os.makedirs(dest, exist_ok=True)
                for name in os.listdir(source):
                    sp = os.path.join(source, name)
                    if os.path.isfile(sp) and not os.path.islink(sp):
                        shutil.copy2(sp, os.path.join(dest, name))
                return 0

            def link(link_path, target):
                os.symlink(target, link_path, target_is_directory=True)

            migrate._full_read_counts.clear()
            with mock.patch.object(migrate, "_drive_of", side_effect=drive), \
                    mock.patch.object(migrate, "_robocopy", side_effect=robocopy), \
                    mock.patch.object(migrate, "is_junction", return_value=False), \
                    mock.patch.object(migrate, "create_junction", side_effect=link):
                result = migrate.migrate(src, dest_root)
            self.assertTrue(result.ok)
            self.assertTrue(migrate._full_read_counts)
            self.assertLessEqual(max(migrate._full_read_counts.values()), 2)
            self.assertEqual(
                migrate._full_read_counts.get((source_info.st_dev, source_info.st_ino)), 2)
        finally:
            shutil.rmtree(src, ignore_errors=True)
            shutil.rmtree(dest_root, ignore_errors=True)


class WindowsSnapshotTests(unittest.TestCase):
    def test_directory_migrate_rejects_same_size_source_change_with_restored_mtime(self):
        src = tempfile.mkdtemp()
        dest_root = tempfile.mkdtemp()
        source_file = os.path.join(src, "item.bin")
        dest_file = os.path.join(dest_root, os.path.basename(src), "item.bin")
        backup = src.rstrip("\\/") + ".migrate-bak"
        try:
            with open(source_file, "wb") as handle:
                handle.write(b"known-good")

            def drive(path):
                full = os.path.abspath(path)
                root = os.path.abspath(dest_root)
                return "D:" if full == root or full.startswith(root + os.sep) else "C:"

            def robocopy(source, dest, move):
                os.makedirs(dest, exist_ok=True)
                shutil.copy2(os.path.join(source, "item.bin"),
                             os.path.join(dest, "item.bin"))
                before = os.stat(source_file)
                with open(source_file, "wb") as handle:
                    handle.write(b"changed!!!")
                os.utime(source_file, ns=(before.st_atime_ns, before.st_mtime_ns))
                return 0

            def link(link_path, target):
                os.symlink(target, link_path, target_is_directory=True)

            with mock.patch.object(migrate.os, "name", "nt"), \
                    mock.patch.object(migrate, "_drive_of", side_effect=drive), \
                    mock.patch.object(migrate, "_robocopy", side_effect=robocopy), \
                    mock.patch.object(migrate, "is_junction", return_value=False), \
                    mock.patch.object(migrate, "create_junction", side_effect=link), \
                    mock.patch.object(migrate.safepath, "is_reparse_point", return_value=False):
                with self.assertRaisesRegex(migrate.MigrateError, "源目录在复制后发生变化"):
                    migrate.migrate(src, dest_root)

            with open(source_file, "rb") as handle:
                self.assertEqual(handle.read(), b"changed!!!")
            with open(dest_file, "rb") as handle:
                self.assertEqual(handle.read(), b"known-good")
            self.assertFalse(os.path.lexists(backup))
        finally:
            if os.path.islink(src):
                os.unlink(src)
            else:
                shutil.rmtree(src, ignore_errors=True)
            shutil.rmtree(dest_root, ignore_errors=True)
            shutil.rmtree(backup, ignore_errors=True)

    def test_same_size_content_change_with_restored_mtime_rehashes_survivor(self):
        folder = tempfile.mkdtemp()
        try:
            path = os.path.join(folder, "survivor.bin")
            with open(path, "wb") as handle:
                handle.write(b"known-good")
            with mock.patch.object(migrate.os, "name", "nt"), \
                    mock.patch.object(migrate.safepath, "is_reparse_point", return_value=False):
                marked = migrate._fingerprint_with_snap(path)
                before = os.stat(path)
                with open(path, "wb") as handle:
                    handle.write(b"changed!!!")
                os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))

                self.assertEqual(migrate._identity_tuple(os.lstat(path)), marked[2])
                self.assertFalse(migrate._survivor_still(
                    path, marked[2], (marked[0], marked[1])))
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_same_size_windows_survivor_change_keeps_correct_backup(self):
        folder = tempfile.mkdtemp()
        try:
            backup_root = os.path.join(folder, "source.migrate-bak")
            survivor_root = os.path.join(folder, "target")
            os.makedirs(backup_root)
            os.makedirs(survivor_root)
            backup = os.path.join(backup_root, "item")
            survivor = os.path.join(survivor_root, "item")
            with open(backup, "wb") as handle:
                handle.write(b"known-good")
            with open(survivor, "wb") as handle:
                handle.write(b"known-good")

            with mock.patch.object(migrate.os, "name", "nt"), \
                    mock.patch.object(migrate.safepath, "is_reparse_point", return_value=False):
                marked = migrate._fingerprint_with_snap(survivor)
                backup_mark = migrate._fingerprint_with_snap(backup)
                before = os.stat(survivor)
                with open(survivor, "wb") as handle:
                    handle.write(b"changed!!!")
                os.utime(survivor, ns=(before.st_atime_ns, before.st_mtime_ns))
                snap = marked[2]
                manifest = {"item": (backup_mark[0], backup_mark[2][3], backup_mark[1])}

                def unlink_if_survivor_matches(path, _size, _digest, survivor_check=None):
                    if survivor_check is None or not survivor_check():
                        return False
                    os.remove(path)
                    return True

                with mock.patch.object(migrate, "_verified_unlink_windows",
                                       side_effect=unlink_if_survivor_matches):
                    remaining = migrate._release_manifest(
                        backup_root, manifest, survivor=survivor_root,
                        survivor_snaps={"item": snap},
                        survivor_marks={"item": (marked[0], marked[1])})

            self.assertTrue(os.path.isfile(backup))
            with open(backup, "rb") as handle:
                self.assertEqual(handle.read(), b"known-good")
            self.assertIn(backup, remaining)
        finally:
            shutil.rmtree(folder, ignore_errors=True)


class StrayAndWarningTests(unittest.TestCase):
    def test_find_stray_dirs_lists_without_deleting(self):
        root = tempfile.mkdtemp()
        try:
            quarantine = os.path.join(root, "work", ".c-drive-cleaner-delete-abc")
            backup = os.path.join(root, "moved.migrate-bak")
            os.makedirs(quarantine)
            os.makedirs(backup)
            kept = os.path.join(quarantine, "captured")
            with open(kept, "w", encoding="utf-8") as handle:
                handle.write("keep")
            found = migrate.find_stray_dirs([root])
            self.assertIn(quarantine, found)
            self.assertIn(backup, found)
            self.assertTrue(os.path.isdir(quarantine))
            self.assertTrue(os.path.isdir(backup))
            with open(kept, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "keep")
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_find_stray_dirs_finds_deep_directories_and_single_file_backups(self):
        root = tempfile.mkdtemp()
        try:
            deep = os.path.join(root, "one", "two", "three", "four")
            os.makedirs(deep)
            backup_dir = os.path.join(deep, "folder.migrate-bak")
            os.makedirs(backup_dir)
            backup_file = os.path.join(deep, "movie.bin.migrate-bak")
            with open(backup_file, "wb") as handle:
                handle.write(b"keep")

            found = migrate.find_stray_dirs([root], max_depth=None)
            self.assertIn(backup_dir, found)
            self.assertIn(backup_file, found)
            self.assertTrue(os.path.isdir(backup_dir))
            with open(backup_file, "rb") as handle:
                self.assertEqual(handle.read(), b"keep")
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_known_locations_includes_local_volumes_and_app_roots(self):
        volume = tempfile.mkdtemp()
        profile = tempfile.mkdtemp()
        appdata = tempfile.mkdtemp()
        program_files = tempfile.mkdtemp()
        try:
            with mock.patch.object(migrate, "_mounted_drive_roots", return_value=[volume]):
                roots = migrate.known_locations({
                    "USERPROFILE": profile,
                    "APPDATA": appdata,
                    "ProgramFiles": program_files,
                })
            self.assertIn(volume, roots)
            self.assertIn(profile, roots)
            self.assertIn(appdata, roots)
            self.assertIn(program_files, roots)
        finally:
            for path in (volume, profile, appdata, program_files):
                shutil.rmtree(path, ignore_errors=True)

    def test_partial_report_lists_backup_leftovers_and_errors(self):
        text = migrate.partial_report(
            backup=r"D:\data.migrate-bak",
            remaining=[r"D:\data.migrate-bak\extra.txt"],
            quarantine=[r"D:\data\.c-drive-cleaner-delete-1"],
            errors=["目录项已变化，未删除：C:\\Temp\\a.tmp"],
        )
        self.assertIn(r"D:\data.migrate-bak", text)
        self.assertIn("extra.txt", text)
        self.assertIn(".c-drive-cleaner-delete-1", text)
        self.assertIn("未能安全删除", text)
        self.assertIn("目录项已变化", text)

    def test_open_folder_uses_startfile_on_windows(self):
        folder = tempfile.mkdtemp()
        try:
            with mock.patch.object(migrate.os, "name", "nt"), \
                    mock.patch.object(migrate.os, "startfile", create=True) as start:
                self.assertTrue(migrate.open_folder(folder))
            start.assert_called_once_with(folder)
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_open_folder_selects_single_file_backup_on_windows(self):
        folder = tempfile.mkdtemp()
        try:
            backup = os.path.join(folder, "movie.bin.migrate-bak")
            with open(backup, "wb") as handle:
                handle.write(b"keep")
            with mock.patch.object(migrate.os, "name", "nt"), \
                    mock.patch.object(migrate.os, "startfile", create=True), \
                    mock.patch.object(migrate.subprocess, "Popen") as launch:
                self.assertTrue(migrate.open_folder(backup))
            launch.assert_called_once_with(
                ["explorer.exe", "/select,", os.path.normpath(backup)],
                creationflags=migrate.CREATE_NO_WINDOW)
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_bigmove_warning_uses_actual_backup_not_destination(self):
        destination = tempfile.mkdtemp()
        try:
            backup = os.path.join(destination, "source.bin.migrate-bak")
            with open(backup, "wb") as handle:
                handle.write(b"recover me")
            app = main.App.__new__(main.App)
            app._show_warning_panel = mock.Mock()
            app.start_bigmove_scan = mock.Mock()
            with mock.patch.object(main.migrate, "find_stray_dirs", return_value=[]):
                app._handle_bigmove_done((
                    "bigmove_done", [], ["source.bin：未完成"], destination, [backup]))

            args = app._show_warning_panel.call_args.args
            self.assertEqual(args[2], backup)
            self.assertNotEqual(args[2], destination)
            self.assertIn(backup, migrate.partial_report(args[2], args[3], args[4]))
            app.start_bigmove_scan.assert_called_once_with()
        finally:
            shutil.rmtree(destination, ignore_errors=True)


class FragVizTests(unittest.TestCase):
    def test_grid_follows_real_percentage(self):
        text = """
        可用空间                 = 56.00 GB
        碎片总计                 = 33%
        碎片文件                 = 18.99 GB
        碎片数                   = 135895
        """
        parsed = fragviz.parse_defrag_report(text)
        self.assertEqual(parsed["percent"], 33.0)
        self.assertEqual(parsed["space_gb"], 18.99)
        self.assertEqual(parsed["count"], 135895)
        self.assertIsNone(fragviz.cells_from_analysis(None, 4, 8))
        cells = fragviz.cells_from_analysis(50, 2, 10)
        self.assertEqual(cells.count("hot"), 10)
        self.assertEqual(fragviz.cells_from_analysis(0, 3, 4).count("hot"), 0)
        self.assertEqual(len(fragviz.cells_from_analysis(33, 11, 32)), 11 * 32)


if __name__ == "__main__":
    unittest.main()
