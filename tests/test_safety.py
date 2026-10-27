import contextlib
import io
import json
import os
import struct
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from pathlib import Path
from unittest import mock

from core import (
    ai_assistant,
    apps,
    browser_cleaner,
    dependencies,
    diagnostics,
    duplicates,
    health,
    history,
    junk,
    large_files,
    memory,
    progress,
    security_audit,
    self_test,
    settings,
    silicon,
    startup,
    uninstaller,
    usage,
    utils,
)


class PathPolicyTests(unittest.TestCase):
    def test_system_and_sensitive_paths_are_blocked(self):
        blocked = [
            "/System/Library/CoreServices/Finder.app",
            "/usr/bin/python3",
            "/Library/Preferences/com.apple.loginwindow.plist",
            os.path.expanduser("~/Library/Mobile Documents/com~apple~CloudDocs/file.txt"),
            os.path.expanduser("~/Documents/important.db"),
        ]
        for path in blocked:
            with self.subTest(path=path):
                self.assertFalse(utils.is_safe_to_delete(path))

    def test_app_intent_only_allows_complete_top_level_bundles(self):
        self.assertTrue(utils.is_safe_to_delete("/Applications/ThirdParty.app", intent="app_bundle"))
        self.assertTrue(
            utils.is_safe_to_delete(
                os.path.expanduser("~/Applications/ThirdParty.app"), intent="app_bundle"
            )
        )
        self.assertFalse(utils.is_safe_to_delete("/Applications", intent="app_bundle"))
        self.assertFalse(
            utils.is_safe_to_delete(
                "/Applications/Host.app/Contents/Helpers/Child.app", intent="app_bundle"
            )
        )

    def test_collection_roots_and_document_packages_are_blocked(self):
        home = os.path.expanduser("~")
        for path in (
            os.path.join(home, "Documents"),
            os.path.join(home, "Pictures"),
            os.path.join(home, "Library", "Containers"),
            os.path.join(home, "Pictures", "Photos Library.photoslibrary", "originals", "photo.jpg"),
            os.path.join(home, "Documents", "Quarterly Report.pages", "Data", "image.png"),
        ):
            with self.subTest(path=path):
                self.assertFalse(utils.is_safe_to_delete(path))

    def test_symlink_components_are_blocked(self):
        with tempfile.TemporaryDirectory(dir=os.path.expanduser("~/Downloads")) as temp_dir:
            target = Path(temp_dir, "target")
            target.mkdir()
            link = Path(temp_dir, "link")
            link.symlink_to(target, target_is_directory=True)
            self.assertFalse(utils.is_safe_to_delete(str(link / "file.txt")))

    def test_authorized_command_is_passed_as_argv(self):
        command = "mv '/tmp/a$b`c' '/tmp/d'"
        with mock.patch.object(utils, "run_command", return_value=(0, "", "")) as runner:
            utils.run_authorized_command(command)
        argv = runner.call_args.args[0]
        self.assertEqual(argv[-1], command)
        self.assertNotIn(command, argv[2])

    def test_cache_identity_allows_content_updates_but_rejects_replacement(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir, "cache.bin")
            path.write_bytes(b"before")
            identity = utils.snapshot_path_identity(str(path))
            path.write_bytes(b"updated cache contents")

            self.assertFalse(utils.path_identity_matches(str(path), identity))
            self.assertTrue(
                utils.path_identity_matches(
                    str(path), identity, allow_content_changes=True
                )
            )

            path.unlink()
            path.write_bytes(b"replacement")
            self.assertFalse(
                utils.path_identity_matches(
                    str(path), identity, allow_content_changes=True
                )
            )

    def test_automatic_cache_scan_can_require_current_user_ownership(self):
        with tempfile.TemporaryDirectory() as temp_dir, mock.patch.object(
            utils, "is_user_owned_path", return_value=False
        ):
            self.assertFalse(
                utils.is_safe_scan_candidate(temp_dir, require_user_owned=True)
            )

    def test_application_scripts_children_are_allowed_but_root_is_protected(self):
        root = os.path.expanduser("~/Library/Application Scripts")
        self.assertFalse(utils.is_safe_to_delete(root))
        self.assertTrue(
            utils.is_safe_to_delete(os.path.join(root, "com.example.thirdparty"))
        )


class ScannerSafetyTests(unittest.TestCase):
    def test_junk_scan_has_no_system_or_trash_targets(self):
        cleanable_roots = {
            root
            for target in junk.JUNK_TARGETS.values()
            if target.get("cleanable")
            for root in target["roots"]
        }
        self.assertNotIn("/Library/Caches", cleanable_roots)
        self.assertNotIn("/Library/Logs", cleanable_roots)
        self.assertNotIn("/private/var/log", cleanable_roots)
        self.assertNotIn("~/.Trash", cleanable_roots)
        self.assertNotIn(os.path.expanduser("~/.Trash"), cleanable_roots)

        # System locations may be measured, never cleaned.
        for key in ("system_caches", "system_logs"):
            self.assertFalse(junk.JUNK_TARGETS[key]["cleanable"])
            self.assertFalse(junk.JUNK_TARGETS[key]["user_owned"])

    def test_expected_system_inventory_denial_is_not_a_junk_error(self):
        with tempfile.TemporaryDirectory() as temp_dir, mock.patch.object(
            junk, "get_dir_size", return_value=(0, 0)
        ) as measure:
            junk._scan_target_items(
                {
                    "roots": [temp_dir],
                    "cleanable": False,
                    "user_owned": False,
                }
            )
        measure.assert_called_once_with(
            temp_dir,
            feature="junk",
            report_issues=False,
        )

    def test_junk_never_registers_browser_caches_for_auto_cleaning(self):
        """The browser panel owns those paths; it refuses to clean a live browser."""
        browser_roots = junk._browser_managed_roots()
        self.assertTrue(browser_roots)
        for root in browser_roots:
            self.assertTrue(junk._is_browser_managed(root, browser_roots))
            self.assertTrue(
                junk._is_browser_managed(os.path.join(root, "child"), browser_roots)
            )

        cache_root = os.path.expanduser("~/Library/Caches")
        safari_cache = os.path.realpath(os.path.join(cache_root, "com.apple.Safari"))
        self.assertTrue(junk._is_browser_managed(safari_cache, browser_roots))
        self.assertFalse(
            junk._is_browser_managed(
                os.path.join(cache_root, "com.example.unrelated"), browser_roots
            )
        )

    def test_junk_clean_refuses_browser_cache_even_if_registered(self):
        browser_root = sorted(junk._browser_managed_roots())[0]
        with mock.patch.dict(
            junk._LAST_SCAN_ITEMS, {"user_cache": {browser_root: (0, 0, 0, 0, 0)}}, clear=True
        ):
            with mock.patch.object(junk, "move_to_trash") as trash:
                result = junk.clean_target("user_cache")
        trash.assert_not_called()
        self.assertEqual(result["moved"], 0)
        self.assertEqual(result["failed"], 1)
        self.assertIn("Navegadores", result["errors"][0])

    def test_cookies_are_never_deletable(self):
        """~/Library/HTTPStorages mixes HTTP caches with live session cookies."""
        cookie = os.path.expanduser(
            "~/Library/HTTPStorages/com.example.client.binarycookies"
        )
        self.assertFalse(utils.is_safe_to_delete(cookie))
        # The sibling cache directory stays eligible.
        self.assertTrue(
            utils.is_safe_to_delete(
                os.path.expanduser("~/Library/HTTPStorages/com.example.client")
            )
        )

    def test_leftover_delete_requires_latest_scan_membership(self):
        with apps._SCAN_LOCK:
            apps._LAST_LEFTOVER_PATHS.clear()
        ok, message = apps.delete_leftover(os.path.expanduser("~/Documents/report.txt"))
        self.assertFalse(ok)
        self.assertIn("varredura", message)

    def test_large_file_delete_revalidates_scan_identity(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir, "large.bin")
            path.write_bytes(b"x" * 4096)
            results = large_files.scan_large_files(
                min_size_mb=0.001, scan_paths=[os.path.realpath(temp_dir)]
            )
            self.assertEqual(len(results), 1)

            path.write_bytes(b"changed")
            with mock.patch.object(large_files, "move_to_trash") as trash:
                ok, message = large_files.delete_large_file(str(path))
            self.assertFalse(ok)
            self.assertIn("alterado", message)
            trash.assert_not_called()

    def test_junk_cleaner_uses_latest_snapshot_only(self):
        with tempfile.TemporaryDirectory(dir=os.path.expanduser("~/Downloads")) as temp_dir:
            first = Path(temp_dir, "scanned.cache")
            late = Path(temp_dir, "created-after-scan.cache")
            first.write_text("scanned", encoding="utf-8")
            target = {"name": "Teste", "description": "Teste", "roots": [temp_dir], "cleanable": True}
            with mock.patch.dict(junk.JUNK_TARGETS, {"test": target}, clear=True):
                junk.scan_junk()
                first.write_text("cache updated after scan", encoding="utf-8")
                late.write_text("late", encoding="utf-8")
                with mock.patch.object(junk, "move_to_trash", return_value=(True, "ok")) as trash:
                    result = junk.clean_target("test")
            self.assertEqual(result["moved"], 1)
            self.assertEqual(trash.call_count, 1)
            self.assertEqual(trash.call_args.args[0], str(first))
            self.assertTrue(trash.call_args.kwargs["allow_content_changes"])

    def test_junk_scan_rejects_candidate_with_document_package_descendant(self):
        cache_parent = os.path.expanduser("~/Library/Caches")
        with tempfile.TemporaryDirectory(dir=cache_parent) as temp_dir:
            candidate = Path(temp_dir, "com.example.cache")
            package = candidate / "Important.pages"
            package.mkdir(parents=True)
            (package / "document.bin").write_bytes(b"user document")
            target = {
                "name": "Teste",
                "description": "Teste",
                "roots": [temp_dir],
                "cleanable": True,
            }

            with mock.patch.dict(junk.JUNK_TARGETS, {"test": target}, clear=True):
                result = junk.scan_junk()

            self.assertEqual(result["test"]["size_bytes"], 0)
            with junk._SCAN_LOCK:
                self.assertEqual(junk._LAST_SCAN_ITEMS["test"], {})

    def test_junk_clean_rejects_protected_content_added_after_scan(self):
        cache_parent = os.path.expanduser("~/Library/Caches")
        with tempfile.TemporaryDirectory(dir=cache_parent) as temp_dir:
            candidate = Path(temp_dir, "com.example.cache")
            candidate.mkdir()
            (candidate / "temporary.bin").write_bytes(b"temporary")
            target = {
                "name": "Teste",
                "description": "Teste",
                "roots": [temp_dir],
                "cleanable": True,
            }

            with mock.patch.dict(junk.JUNK_TARGETS, {"test": target}, clear=True):
                junk.scan_junk()
                package = candidate / "Important.pages"
                package.mkdir()
                (package / "document.bin").write_bytes(b"user document")
                with mock.patch.object(junk, "move_to_trash") as trash:
                    cleaned = junk.clean_target("test")

            self.assertEqual(cleaned["moved"], 0)
            self.assertEqual(cleaned["failed"], 1)
            trash.assert_not_called()

    def test_scanners_prune_macos_document_packages(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(os.path.realpath(temp_dir))
            package = root / "Important.pages"
            package.mkdir()
            (package / "internal.bin").write_bytes(b"x" * 4096)
            first = root / "copy-1.bin"
            second = root / "copy-2.bin"
            first.write_bytes(b"safe duplicate")
            second.write_bytes(b"safe duplicate")

            large = large_files.scan_large_files(min_size_mb=0.001, scan_paths=[str(root)])
            duplicate_groups = duplicates.scan_duplicates([str(root)])

            self.assertNotIn(str(package / "internal.bin"), {item["path"] for item in large})
            duplicate_paths = {
                item["path"] for group in duplicate_groups for item in group["files"]
            }
            self.assertNotIn(str(package / "internal.bin"), duplicate_paths)

    def test_leftover_revalidates_safety_but_allows_cache_content_changes(self):
        with tempfile.TemporaryDirectory(
            dir=os.path.expanduser("~/Library/Caches")
        ) as temp_dir:
            root = Path(temp_dir)
            caches = root / "Caches"
            saved = root / "Saved Application State"
            candidate = caches / "com.example.orphan"
            candidate.mkdir(parents=True)
            saved.mkdir()
            content = candidate / "cache.bin"
            content.write_bytes(b"before")
            real_expanduser = os.path.expanduser

            def fake_expand(path):
                if path == "~/Library/Caches":
                    return str(caches)
                if path == "~/Library/Saved Application State":
                    return str(saved)
                return real_expanduser(path)

            with mock.patch.object(apps.os.path, "expanduser", side_effect=fake_expand), mock.patch.object(
                apps, "find_installed_apps", return_value=(set(), set())
            ):
                results = apps.scan_leftovers()
                self.assertEqual(len(results), 1)
                content.write_bytes(b"changed content")
                with mock.patch.object(
                    apps, "move_to_trash", return_value=(True, "ok")
                ) as trash:
                    ok, message = apps.delete_leftover(str(candidate))

            self.assertTrue(ok, message)
            trash.assert_called_once()
            self.assertTrue(trash.call_args.kwargs["allow_content_changes"])

    def test_leftover_is_blocked_if_corresponding_app_appears_after_scan(self):
        with tempfile.TemporaryDirectory(
            dir=os.path.expanduser("~/Library/Caches")
        ) as temp_dir:
            root = Path(temp_dir)
            caches = root / "Caches"
            saved = root / "Saved Application State"
            candidate = caches / "com.example.returned"
            candidate.mkdir(parents=True)
            saved.mkdir()
            (candidate / "cache.bin").write_bytes(b"cache")
            real_expanduser = os.path.expanduser

            def fake_expand(path):
                if path == "~/Library/Caches":
                    return str(caches)
                if path == "~/Library/Saved Application State":
                    return str(saved)
                return real_expanduser(path)

            inventory = mock.Mock(
                side_effect=[
                    (set(), set()),
                    ({"com.example.returned"}, {"Returned"}),
                ]
            )
            with mock.patch.object(apps.os.path, "expanduser", side_effect=fake_expand), mock.patch.object(
                apps, "find_installed_apps", inventory
            ):
                results = apps.scan_leftovers()
                self.assertEqual(len(results), 1)
                with mock.patch.object(apps, "move_to_trash") as trash:
                    ok, message = apps.delete_leftover(str(candidate))

            self.assertFalse(ok)
            self.assertIn("está instalado", message)
            trash.assert_not_called()

    def test_vendor_cache_scan_is_deep_but_protects_installed_product(self):
        with tempfile.TemporaryDirectory(
            dir=os.path.expanduser("~/Library/Caches")
        ) as temp_dir:
            root = Path(temp_dir)
            caches = root / "Caches"
            saved = root / "Saved Application State"
            chrome = caches / "Google" / "Chrome"
            orphan = caches / "Google" / "UnusedTool"
            chrome.mkdir(parents=True)
            orphan.mkdir()
            saved.mkdir()
            (chrome / "cache.bin").write_bytes(b"active")
            (orphan / "cache.bin").write_bytes(b"orphan")
            real_expanduser = os.path.expanduser

            def fake_expand(path):
                if path == "~/Library/Caches":
                    return str(caches)
                if path == "~/Library/Saved Application State":
                    return str(saved)
                return real_expanduser(path)

            with mock.patch.object(apps.os.path, "expanduser", side_effect=fake_expand), mock.patch.object(
                apps,
                "find_installed_apps",
                return_value=({"com.google.Chrome"}, {"Google Chrome"}),
            ):
                results = apps.scan_leftovers()

            self.assertEqual([item["name"] for item in results], ["UnusedTool"])
            self.assertEqual(results[0]["confidence"], "Revisar")


class BrowserCacheSafetyTests(unittest.TestCase):
    def _target(self, cache_root: str) -> dict:
        return {
            "name": "Navegador de Teste",
            "app_paths": (),
            "process_names": ("test-browser",),
            "roots": (cache_root,),
        }

    def test_targets_exclude_browser_profiles_and_personal_data(self):
        all_roots = {
            os.path.expanduser(root)
            for target in browser_cleaner.BROWSER_CACHE_TARGETS.values()
            for root in target["roots"]
        }
        self.assertNotIn(os.path.expanduser("~/Library/Safari"), all_roots)
        self.assertFalse(any("Application Support/Firefox" in root for root in all_roots))

    def test_cleaner_uses_latest_scan_and_ignores_late_items(self):
        cache_parent = os.path.expanduser("~/Library/Caches")
        with tempfile.TemporaryDirectory(dir=cache_parent) as cache_root:
            scanned = Path(cache_root, "cache2")
            scanned.mkdir()
            (scanned / "entry.bin").write_bytes(b"temporary")
            target = self._target(cache_root)

            with mock.patch.dict(
                browser_cleaner.BROWSER_CACHE_TARGETS, {"test": target}, clear=True
            ), mock.patch.object(
                browser_cleaner, "_browser_is_running", return_value=False
            ):
                results = browser_cleaner.scan_browser_caches()
                late = Path(cache_root, "created-after-scan")
                late.mkdir()
                with mock.patch.object(
                    browser_cleaner, "move_to_trash", return_value=(True, "ok")
                ) as trash:
                    result = browser_cleaner.clean_browser_cache("test")

            self.assertGreater(results["test"]["size_bytes"], 0)
            self.assertEqual(result["moved"], 1)
            trash.assert_called_once()
            self.assertEqual(trash.call_args.args[0], os.path.realpath(scanned))
            self.assertNotEqual(trash.call_args.args[0], os.path.realpath(late))

    def test_cleaner_allows_ordinary_cache_writes_between_scan_and_clean(self):
        """
        Exercise the real Trash policy with a stub for only the native move.

        Both a changed file and a directory with newly created cache entries
        remain eligible when their device, inode and file type stay unchanged.
        """
        cache_parent = os.path.expanduser("~/Library/Caches")
        with tempfile.TemporaryDirectory(dir=cache_parent) as cache_root:
            scanned = Path(cache_root, "cache2")
            scanned.mkdir()
            content = scanned / "entry.bin"
            content.write_bytes(b"before")
            direct_file = Path(cache_root, "cache.bin")
            direct_file.write_bytes(b"before")
            target = self._target(cache_root)

            with mock.patch.dict(
                browser_cleaner.BROWSER_CACHE_TARGETS, {"test": target}, clear=True
            ), mock.patch.object(
                browser_cleaner, "_browser_is_running", return_value=False
            ):
                browser_cleaner.scan_browser_caches()
                directory_identity = utils.snapshot_path_identity(str(scanned))
                file_identity = utils.snapshot_path_identity(str(direct_file))
                content.write_bytes(b"changed content after the scan")
                (scanned / "new-entry.bin").write_bytes(b"new cache entry")
                direct_file.write_bytes(b"changed direct cache file")
                # Make the directory mtime change deterministic even on a
                # filesystem whose timestamp resolution is coarser than writes.
                os.utime(
                    scanned,
                    ns=(directory_identity[4] + 1_000_000, directory_identity[4] + 1_000_000),
                )
                self.assertFalse(utils.path_identity_matches(str(scanned), directory_identity))
                self.assertFalse(utils.path_identity_matches(str(direct_file), file_identity))

                foundation = mock.Mock()
                native_trash = (
                    foundation.NSFileManager.defaultManager.return_value
                    .trashItemAtURL_resultingItemURL_error_
                )
                native_trash.return_value = (True, None, None)
                with mock.patch.dict("sys.modules", {"Foundation": foundation}):
                    result = browser_cleaner.clean_browser_cache("test")

            self.assertEqual(result["moved"], 2)
            self.assertEqual(result["failed"], 0)
            self.assertEqual(result["files_moved"], 3)
            self.assertEqual(native_trash.call_count, 2)
            self.assertTrue(scanned.exists())
            self.assertTrue(direct_file.exists())

    def test_cleaner_rejects_symlink_planted_after_scan(self):
        """A link introduced between scan and clean must fail the item closed."""
        cache_parent = os.path.expanduser("~/Library/Caches")
        with tempfile.TemporaryDirectory(dir=cache_parent) as cache_root:
            scanned = Path(cache_root, "cache3")
            scanned.mkdir()
            (scanned / "entry.bin").write_bytes(b"before")
            target = self._target(cache_root)

            with mock.patch.dict(
                browser_cleaner.BROWSER_CACHE_TARGETS, {"test": target}, clear=True
            ), mock.patch.object(
                browser_cleaner, "_browser_is_running", return_value=False
            ):
                browser_cleaner.scan_browser_caches()
                os.symlink(
                    os.path.expanduser("~/Library/Keychains"), scanned / "escape"
                )
                with mock.patch.object(browser_cleaner, "move_to_trash") as trash:
                    result = browser_cleaner.clean_browser_cache("test")

            self.assertEqual(result["moved"], 0)
            self.assertEqual(result["failed"], 1)
            trash.assert_not_called()

    def test_cleaner_revalidates_root_identity(self):
        """Swapping the scanned directory itself must still block the move."""
        cache_parent = os.path.expanduser("~/Library/Caches")
        with tempfile.TemporaryDirectory(dir=cache_parent) as cache_root:
            scanned = Path(cache_root, "cache4")
            scanned.mkdir()
            (scanned / "entry.bin").write_bytes(b"before")
            target = self._target(cache_root)

            with mock.patch.dict(
                browser_cleaner.BROWSER_CACHE_TARGETS, {"test": target}, clear=True
            ), mock.patch.object(
                browser_cleaner, "_browser_is_running", return_value=False
            ):
                browser_cleaner.scan_browser_caches()
                with browser_cleaner._SCAN_LOCK:
                    registered = dict(browser_cleaner._LAST_SCAN_ITEMS["test"])
                self.assertEqual(len(registered), 1)
                # The identity recorded at scan time is what move_to_trash
                # receives, so a replaced directory fails the inode check.
                identity = next(iter(registered.values()))["identity"]
                self.assertEqual(
                    identity, utils.snapshot_path_identity(str(scanned))
                )
                scanned.rename(Path(cache_root, "original-cache"))
                scanned.mkdir()
                (scanned / "entry.bin").write_bytes(b"replacement cache")

                foundation = mock.Mock()
                native_trash = (
                    foundation.NSFileManager.defaultManager.return_value
                    .trashItemAtURL_resultingItemURL_error_
                )
                with mock.patch.dict("sys.modules", {"Foundation": foundation}):
                    result = browser_cleaner.clean_browser_cache("test")

            self.assertEqual(result["moved"], 0)
            self.assertEqual(result["failed"], 1)
            self.assertIn("mudou desde a varredura", result["errors"][0])
            native_trash.assert_not_called()
            self.assertTrue(scanned.exists())

    def test_cleaner_requires_browser_to_be_closed(self):
        cache_parent = os.path.expanduser("~/Library/Caches")
        with tempfile.TemporaryDirectory(dir=cache_parent) as cache_root:
            Path(cache_root, "entry.bin").write_bytes(b"cache")
            target = self._target(cache_root)
            with mock.patch.dict(
                browser_cleaner.BROWSER_CACHE_TARGETS, {"test": target}, clear=True
            ), mock.patch.object(
                browser_cleaner, "_browser_is_running", side_effect=(False, True)
            ):
                browser_cleaner.scan_browser_caches()
                with mock.patch.object(browser_cleaner, "move_to_trash") as trash:
                    result = browser_cleaner.clean_browser_cache("test")

            self.assertEqual(result["moved"], 0)
            self.assertIn("Feche completamente", result["errors"][0])
            trash.assert_not_called()


class SecurityAuditTests(unittest.TestCase):
    def test_audit_is_read_only_and_classifies_macos_protections(self):
        outputs = {
            "fdesetup": (0, "FileVault is On.", ""),
            "socketfilterfw": (0, "Firewall is enabled. (State = 1)", ""),
            "spctl": (0, "assessments enabled", ""),
            "csrutil": (0, "System Integrity Protection status: enabled.", ""),
            "softwareupdate": (0, "Automatic checking is on", ""),
            "ps": (0, "/Applications/Safari.app/Contents/MacOS/Safari\n", ""),
        }

        def fake_run(command, timeout=120):
            return outputs[os.path.basename(command[0])]

        with mock.patch.object(security_audit, "run_command", side_effect=fake_run) as runner:
            report = security_audit.run_security_audit()

        self.assertTrue(report["read_only"])
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["summary"], {"ok": 6, "attention": 0, "unknown": 0})
        self.assertEqual(
            [call.args[0][1] for call in runner.call_args_list],
            ["status", "--getglobalstate", "--status", "status", "--schedule", "-A"],
        )

    def test_remote_controlled_browser_is_flagged_only_from_main_process(self):
        ps_output = "\n".join([
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --remote-debugging-port=9222 --user-data-dir=/tmp/x",
            "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Helpers/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer) --type=renderer --remote-debugging-port=9222",
            "/Applications/Safari.app/Contents/MacOS/Safari",
            "/bin/zsh -c grep --remote-debugging-port notes.txt --type=x",
        ])
        self.assertEqual(
            security_audit.find_remote_debugging_browsers(ps_output), ["Google Chrome"]
        )
        self.assertEqual(security_audit.find_remote_debugging_browsers(""), [])

        with mock.patch.object(security_audit, "run_command", return_value=(0, ps_output, "")):
            check = security_audit._remote_debugging_check()
        self.assertEqual(check["status"], "attention")
        self.assertIn("Google Chrome", check["detail"])
        self.assertFalse(check["action_available"])

        with mock.patch.object(security_audit, "run_command", return_value=(1, "", "denied")):
            check = security_audit._remote_debugging_check()
        self.assertEqual(check["status"], "unknown")

    def test_current_softwareupdate_wording_is_recognized(self):
        with mock.patch.object(
            security_audit,
            "run_command",
            return_value=(0, "Automatic checking for updates is turned on", ""),
        ):
            enabled, _ = security_audit._run_check(
                ["/usr/sbin/softwareupdate", "--schedule"],
                ("automatic checking for updates is turned on",),
                ("automatic checking for updates is turned off",),
            )
        self.assertTrue(enabled)

    def test_settings_shortcut_uses_only_allowlisted_url(self):
        with mock.patch.object(
            security_audit, "run_command", return_value=(0, "", "")
        ) as runner:
            ok, _ = security_audit.open_security_setting("firewall")
        self.assertTrue(ok)
        runner.assert_called_once_with(
            [
                "/usr/bin/open",
                "x-apple.systempreferences:com.apple.Network-Settings.extension?Firewall",
            ],
            timeout=15,
        )

        with mock.patch.object(security_audit, "run_command") as runner:
            ok, _ = security_audit.open_security_setting("../../malicious")
        self.assertFalse(ok)
        runner.assert_not_called()

        with mock.patch.object(
            security_audit, "run_command", return_value=(0, "", "")
        ) as runner:
            ok, _ = security_audit.open_security_setting("full_disk_access")
        self.assertTrue(ok)
        runner.assert_called_once_with(
            [
                "/usr/bin/open",
                "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles",
            ],
            timeout=15,
        )


class DependencySafetyTests(unittest.TestCase):
    def tearDown(self):
        with dependencies._PACKAGE_LOCK:
            dependencies._LAST_PACKAGES.clear()

    def test_removal_requires_fresh_listing_and_supports_multiple_packages(self):
        npm_path = "/opt/homebrew/bin/npm"
        with dependencies._PACKAGE_LOCK:
            dependencies._LAST_PACKAGES["npm"] = {
                "path": os.path.realpath(npm_path),
                "removable": {"alpha": "alpha", "beta": "beta"},
            }

        with mock.patch.object(dependencies.shutil, "which", return_value=npm_path), mock.patch.object(
            dependencies, "run_command", return_value=(0, "removed", "")
        ) as runner:
            first = dependencies.remove_dependency("npm", "alpha")
            second = dependencies.remove_dependency("npm", "beta")
            unknown = dependencies.remove_dependency("npm", "gamma")

        self.assertTrue(first["success"])
        self.assertTrue(second["success"])
        self.assertFalse(unknown["success"])
        self.assertEqual(
            [call.args[0] for call in runner.call_args_list],
            [
                [npm_path, "uninstall", "--global", "alpha"],
                [npm_path, "uninstall", "--global", "beta"],
            ],
        )

    def test_pip_inventory_is_limited_to_user_packages(self):
        pip_path = "/opt/homebrew/bin/pip3"
        payload = '[{"name":"Example","version":"1.2.3"}]'
        with mock.patch.object(dependencies.shutil, "which", return_value=pip_path), mock.patch.object(
            dependencies, "run_command", return_value=(0, payload, "")
        ) as runner:
            result = dependencies.check_pip()

        runner.assert_called_once_with([pip_path, "list", "--user", "--format=json"])
        self.assertEqual(result["packages"][0]["name"], "Example")
        self.assertTrue(result["packages"][0]["removable"])

    def test_failed_removal_stays_available_for_retry(self):
        npm_path = "/opt/homebrew/bin/npm"
        with dependencies._PACKAGE_LOCK:
            dependencies._LAST_PACKAGES["npm"] = {
                "path": os.path.realpath(npm_path),
                "removable": {"example": "example"},
            }

        with mock.patch.object(
            dependencies.shutil, "which", return_value=npm_path
        ), mock.patch.object(
            dependencies, "run_command", return_value=(1, "", "falha simulada")
        ):
            result = dependencies.remove_dependency("npm", "example")

        self.assertFalse(result["success"])
        with dependencies._PACKAGE_LOCK:
            self.assertIn(
                "example",
                dependencies._LAST_PACKAGES["npm"]["removable"],
            )

    def test_gui_path_fallback_finds_homebrew(self):
        with mock.patch.object(dependencies.shutil, "which", return_value=None), mock.patch.object(
            dependencies.os.path, "isfile", side_effect=lambda path: path == "/opt/homebrew/bin/brew"
        ), mock.patch.object(dependencies.os, "access", return_value=True):
            located = dependencies._find_manager_executable("brew")

        self.assertEqual(located, "/opt/homebrew/bin/brew")


class AiSummarySafetyTests(unittest.TestCase):
    def _summarize(self, facts: str, summary: str) -> dict:
        helper_result = mock.Mock(
            stdout=json.dumps({"available": True, "summary": summary}),
            stderr="",
            returncode=0,
        )
        with mock.patch.object(ai_assistant.platform, "machine", return_value="arm64"), mock.patch.object(
            ai_assistant, "_locate_binary", return_value="/tmp/hollyoptimizer-ai"
        ), mock.patch.object(ai_assistant.subprocess, "run", return_value=helper_result):
            return ai_assistant.summarize(facts)

    def test_ai_summary_accepts_exact_numeric_facts(self):
        result = self._summarize(
            "Há 2 itens usando 1.25 GB e 0 sobras.",
            "Foram encontrados 2 itens, totalizando 1,25 GB, e 0 sobras.",
        )
        self.assertTrue(result["available"])

    def test_ai_summary_rejects_changed_or_omitted_numeric_facts(self):
        changed = self._summarize(
            "Há 2 itens usando 1.25 GB e 0 sobras.",
            "Foram encontrados 3 itens usando 1.25 GB.",
        )
        self.assertFalse(changed["available"])
        self.assertEqual(changed["reason"], "numeric_facts_changed")


class DuplicateSafetyTests(unittest.TestCase):
    def _scan_group(self, temp_dir: str, count: int = 2):
        paths = []
        for index in range(count):
            path = Path(temp_dir, f"copy-{index}.txt")
            path.write_text("same content", encoding="utf-8")
            paths.append(path)
        groups = duplicates.scan_duplicates([os.path.realpath(temp_dir)])
        self.assertEqual(len(groups), 1)
        return groups[0], paths

    def test_backend_refuses_to_remove_every_copy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            group, _ = self._scan_group(temp_dir)
            selections = [{"hash": group["hash"], "path": item["path"]} for item in group["files"]]
            with mock.patch.object(duplicates, "move_to_trash") as trash:
                result = duplicates.delete_duplicate_files(selections)
            self.assertEqual(result["deleted"], 0)
            self.assertTrue(any("preservada" in error for error in result["errors"]))
            trash.assert_not_called()

    def test_backend_allows_only_non_keeper_copy_after_revalidation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            group, _ = self._scan_group(temp_dir)
            selection = [{"hash": group["hash"], "path": group["files"][1]["path"]}]
            with mock.patch.object(duplicates, "move_to_trash", return_value=(True, "ok")) as trash:
                result = duplicates.delete_duplicate_files(selection)
            self.assertEqual(result["deleted"], 1)
            self.assertFalse(result["errors"])
            trash.assert_called_once()

    def test_concurrent_opposite_selections_preserve_one_copy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            group, paths = self._scan_group(temp_dir)
            first_move_started = threading.Event()
            second_call_started = threading.Event()
            finish_first_move = threading.Event()

            def simulate_trash(path, **kwargs):
                if path == os.path.realpath(paths[0]):
                    first_move_started.set()
                    if not finish_first_move.wait(timeout=5):
                        raise RuntimeError("A segunda chamada não foi iniciada.")
                return True, "Movimentação nativa simulada; arquivos preservados."

            def remove_copy(index):
                if index == 1:
                    second_call_started.set()
                return duplicates.delete_duplicate_files(
                    [{"hash": group["hash"], "path": str(paths[index])}]
                )

            with mock.patch.object(
                duplicates, "move_to_trash", side_effect=simulate_trash
            ) as trash, ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(remove_copy, 0)
                try:
                    self.assertTrue(first_move_started.wait(timeout=5))
                    second = pool.submit(remove_copy, 1)
                    self.assertTrue(second_call_started.wait(timeout=5))
                    with self.assertRaises(FutureTimeoutError):
                        second.result(timeout=0.05)
                finally:
                    finish_first_move.set()
                results = [first.result(timeout=5), second.result(timeout=5)]

            self.assertEqual(sum(result["deleted"] for result in results), 1)
            self.assertEqual(sum(bool(result["errors"]) for result in results), 1)
            trash.assert_called_once()
            self.assertTrue(all(path.exists() for path in paths))

    def test_keeper_changed_while_selected_copy_is_hashed_blocks_removal(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            group, paths = self._scan_group(temp_dir)
            snapshot_file = duplicates._snapshot_file

            def change_keeper_after_hash(*args):
                snapshot = snapshot_file(*args)
                paths[0].write_text("keeper changed during hashing", encoding="utf-8")
                return snapshot

            with mock.patch.object(
                duplicates, "_snapshot_file", side_effect=change_keeper_after_hash
            ), mock.patch.object(duplicates, "move_to_trash") as trash:
                result = duplicates.delete_duplicate_files(
                    [{"hash": group["hash"], "path": str(paths[1])}]
                )

            self.assertEqual(result["deleted"], 0)
            self.assertTrue(any("preservada mudou" in error for error in result["errors"]))
            trash.assert_not_called()

    def test_backend_refuses_file_changed_after_scan(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            group, paths = self._scan_group(temp_dir)
            paths[1].write_text("different content", encoding="utf-8")
            selection = [{"hash": group["hash"], "path": str(paths[1])}]
            with mock.patch.object(duplicates, "move_to_trash") as trash:
                result = duplicates.delete_duplicate_files(selection)
            self.assertEqual(result["deleted"], 0)
            self.assertTrue(result["errors"])
            trash.assert_not_called()

    def test_scan_rejects_file_changed_while_full_hash_is_read(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            first = Path(temp_dir, "first.txt")
            second = Path(temp_dir, "second.txt")
            first.write_text("same content", encoding="utf-8")
            second.write_text("same content", encoding="utf-8")
            original_hash = duplicates.get_file_full_hash
            changed = False

            def mutate_after_hash(path, operation=""):
                nonlocal changed
                result = original_hash(path, operation)
                if not changed:
                    Path(path).write_text("other content", encoding="utf-8")
                    changed = True
                return result

            with mock.patch.object(
                duplicates, "get_file_full_hash", side_effect=mutate_after_hash
            ):
                groups = duplicates.scan_duplicates([temp_dir])

            self.assertEqual(groups, [])

    def test_hash_reader_refuses_symbolic_links(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir, "target.txt")
            link = Path(temp_dir, "link.txt")
            target.write_text("content", encoding="utf-8")
            link.symlink_to(target)
            self.assertEqual(duplicates.get_file_full_hash(str(link)), "")


class LargeFileInputTests(unittest.TestCase):
    def test_size_limit_must_be_finite_and_positive(self):
        for value in (0, -1, float("nan"), float("inf"), True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                large_files.scan_large_files(value, [])


class UninstallerSafetyTests(unittest.TestCase):
    def test_icon_cache_key_cannot_escape_cache_directory(self):
        key = uninstaller._safe_cache_key("../../Desktop/overwrite", "/Applications/Test.app")
        self.assertNotIn("/", key)
        self.assertNotIn("..", key)

    def test_uninstall_requires_latest_app_listing(self):
        with uninstaller._REGISTRY_LOCK:
            uninstaller._LAST_LISTED_APPS.clear()
            uninstaller._RELATED_BY_APP.clear()
        ok, logs = uninstaller.uninstall_app("/Applications/Unknown.app", [])
        self.assertFalse(ok)
        self.assertIn("listagem", logs[0])

    def test_related_files_use_only_registered_app_name(self):
        app_path = "/Applications/Example.app"
        with tempfile.TemporaryDirectory(
            dir=os.path.expanduser("~/Library/Caches")
        ) as temp_dir:
            expected = Path(temp_dir, "Example")
            unrelated = Path(temp_dir, "Unrelated Data")
            expected.mkdir()
            unrelated.mkdir()
            (expected / "cache.bin").write_bytes(b"cache")
            (unrelated / "important.bin").write_bytes(b"keep")

            with uninstaller._REGISTRY_LOCK:
                uninstaller._LAST_LISTED_APPS.clear()
                uninstaller._RELATED_BY_APP.clear()
                uninstaller._LAST_LISTED_APPS[app_path] = {
                    "path": app_path,
                    "bundle_id": "com.example.app",
                    "name": "Example",
                }

            with mock.patch.object(
                uninstaller,
                "LIBRARY_DIRS",
                [{"dir": temp_dir, "type": "support"}],
            ):
                related = uninstaller.get_app_related_files(
                    app_path, "com.example.app"
                )

        self.assertEqual([item["name"] for item in related], ["Example"])

    def test_uninstall_retries_with_admin_after_permission_failure(self):
        app_path = "/Applications/ThirdParty.app"
        identity = (1, 2, 0o40755, 4096, 123)
        with uninstaller._REGISTRY_LOCK:
            uninstaller._LAST_LISTED_APPS.clear()
            uninstaller._RELATED_BY_APP.clear()
            uninstaller._LAST_LISTED_APPS[app_path] = {
                "path": app_path,
                "bundle_id": "com.example.thirdparty",
                "_identity": identity,
            }
            uninstaller._RELATED_BY_APP[app_path] = {}

        permission_error = (
            "Falha ao mover para a Lixeira: NSCocoaErrorDomain Code=513 "
            "afpAccessDenied: Insufficient access privileges"
        )
        with mock.patch.object(uninstaller.os.path, "exists", return_value=True), mock.patch.object(
            uninstaller, "move_to_trash", return_value=(False, permission_error)
        ) as native_trash, mock.patch.object(
            uninstaller,
            "move_app_to_trash_authorized",
            return_value=(True, "Movido com autorização"),
        ) as authorized_trash:
            ok, logs = uninstaller.uninstall_app(app_path, [])

        self.assertTrue(ok)
        self.assertIn("Movido com autorização", logs[0])
        native_trash.assert_called_once()
        authorized_trash.assert_called_once_with(app_path, expected_identity=identity)

    def test_leftover_scanner_does_not_follow_symlink_candidates(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(os.path.realpath(temp_dir))
            caches = root / "Caches"
            saved = root / "Saved Application State"
            target = root / "Documents"
            caches.mkdir()
            saved.mkdir()
            target.mkdir()
            (target / "important.txt").write_text("preserve", encoding="utf-8")
            (caches / "com.example.orphan").symlink_to(target, target_is_directory=True)

            real_expanduser = os.path.expanduser
            def fake_expand(path):
                if path == "~/Library/Caches":
                    return str(caches)
                if path == "~/Library/Saved Application State":
                    return str(saved)
                return real_expanduser(path)

            with mock.patch.object(apps.os.path, "expanduser", side_effect=fake_expand), mock.patch.object(
                apps, "find_installed_apps", return_value=(set(), set())
            ):
                results = apps.scan_leftovers()
            self.assertEqual(results, [])


class MemorySafetyTests(unittest.TestCase):
    def test_vm_page_size_and_reclaimable_memory_are_accounted_for(self):
        vm_output = """Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free: 10.
Pages speculative: 2.
Pages active: 40.
Pages inactive: 30.
Pages wired down: 10.
Pages purgeable: 8.
"""

        def fake_run(command, timeout=120):
            executable = os.path.basename(command[0])
            if executable == "sysctl" and command[-1] == "hw.memsize":
                return 0, str(100 * 16384), ""
            if executable == "sysctl":
                return 0, "1", ""
            if executable == "vm_stat":
                return 0, vm_output, ""
            raise AssertionError(command)

        with mock.patch.object(memory, "run_command", side_effect=fake_run):
            stats = memory.get_memory_stats()

        self.assertEqual(stats["free_bytes"], 12 * 16384)
        self.assertEqual(stats["available_bytes"], 50 * 16384)
        self.assertEqual(stats["used_bytes"], 50 * 16384)
        self.assertEqual(stats["percent"], 50.0)

    def test_process_kill_requires_fresh_identity_and_uses_sigterm(self):
        pid = 99999
        with memory._PROCESS_LOCK:
            memory._LAST_PROCESS_IDENTITIES.clear()
            memory._LAST_PROCESS_IDENTITIES[pid] = {
                "uid": os.getuid(),
                "start_time": "Sat Aug 8 19:00:00 2026",
                "path": "/Applications/Test.app/Contents/MacOS/Test",
            }

        with mock.patch.object(
            memory,
            "_get_process_info",
            return_value=(
                os.getuid(),
                "Sat Aug 8 19:00:00 2026",
                "/Applications/Test.app/Contents/MacOS/Test",
            ),
        ), mock.patch.object(memory, "run_command", return_value=(0, "", "")) as runner:
            ok, _ = memory.kill_process(pid)

        self.assertTrue(ok)
        runner.assert_called_once_with(["/bin/kill", "-TERM", str(pid)])


class OperationalSafetyTests(unittest.TestCase):
    def test_empty_trash_uses_finder_and_verifies_the_remaining_count(self):
        with mock.patch.object(
            utils, "run_command", return_value=(0, "3|0", "")
        ) as runner:
            ok, message, finder_unavailable = utils.empty_trash()

        self.assertTrue(ok)
        self.assertFalse(finder_unavailable)
        self.assertIn("3 itens removidos", message)
        self.assertEqual(runner.call_args.args[0][0], "/usr/bin/osascript")

    def test_empty_trash_fails_safe_when_finder_automation_is_denied(self):
        with mock.patch.object(
            utils, "run_command", return_value=(-1, "", "Automação negada")
        ), mock.patch.object(utils.os, "unlink") as unlink:
            ok, message, finder_unavailable = utils.empty_trash()

        self.assertFalse(ok)
        self.assertTrue(finder_unavailable)
        self.assertIn("Automação", message)
        unlink.assert_not_called()

    def test_empty_trash_reports_user_cancellation_without_fallback(self):
        with mock.patch.object(
            utils, "run_command", return_value=(1, "", "execution error: User canceled. (-128)")
        ):
            ok, message, finder_unavailable = utils.empty_trash()

        self.assertFalse(ok)
        self.assertFalse(finder_unavailable)
        self.assertIn("cancelada", message)

    def test_local_permanent_deletion_accounts_for_blocked_items(self):
        with mock.patch.object(
            utils.os.path, "isdir", return_value=True
        ), mock.patch.object(
            utils, "has_symlink_component", return_value=False
        ), mock.patch.object(
            utils.os, "listdir", return_value=["bloqueado"]
        ), mock.patch.object(
            utils.os.path, "isfile", return_value=True
        ), mock.patch.object(
            utils.os.path, "islink", return_value=False
        ), mock.patch.object(
            utils.os, "unlink", side_effect=PermissionError("Operation not permitted")
        ):
            ok, message, _ = utils.empty_trash_local_permanent()

        self.assertFalse(ok)
        self.assertIn("1 bloqueados", message)
        self.assertIn("Exclusão permanente local", message)

    def test_local_permanent_deletion_reports_scope(self):
        with mock.patch.object(
            utils.os.path, "isdir", return_value=True
        ), mock.patch.object(
            utils, "has_symlink_component", return_value=False
        ), mock.patch.object(
            utils.os, "listdir", return_value=["item"]
        ), mock.patch.object(
            utils.os.path, "isfile", return_value=True
        ), mock.patch.object(
            utils.os.path, "islink", return_value=False
        ), mock.patch.object(
            utils.os, "unlink"
        ), mock.patch.object(
            utils.os.path, "lexists", return_value=False
        ):
            ok, message, _ = utils.empty_trash_local_permanent()

        self.assertTrue(ok)
        self.assertIn("outros volumes não foram tocadas", message)

    def test_empty_trash_button_uses_the_defined_dialog_api(self):
        app_js = Path(__file__).resolve().parents[1] / "gui" / "app.js"
        source = app_js.read_text(encoding="utf-8")
        self.assertNotIn("showCustomConfirm(", source)
        self.assertIn("const confirmed = await showConfirm(", source)

    def test_dynamic_html_escapes_attribute_quotes_and_blocks_inline_scripts(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / "gui" / "app.js").read_text(encoding="utf-8")
        html = (root / "gui" / "index.html").read_text(encoding="utf-8")

        self.assertIn(".replace(/\"/g, '&quot;')", source)
        self.assertIn(".replace(/'/g, '&#39;')", source)
        self.assertNotIn("onclick=", source)
        self.assertNotIn("onclick=", html)
        self.assertIn("Content-Security-Policy", html)
        self.assertIn("script-src 'self'", html)

    def test_self_test_reports_missing_gui_assets_without_crashing(self):
        with tempfile.TemporaryDirectory() as resource_root, mock.patch.object(
            self_test, "configure_logging", return_value=__file__
        ), contextlib.redirect_stdout(io.StringIO()):
            result = self_test.run_self_test(resource_root)
        self.assertEqual(result, 1)

    def test_running_app_data_is_excluded_from_general_cleanup(self):
        self.assertTrue(
            junk._is_own_data(
                os.path.expanduser(
                    "~/Library/Logs/HollyOptimizer/hollyoptimizer.log"
                )
            )
        )
        self.assertTrue(
            junk._is_own_data(
                os.path.expanduser(
                    "~/Library/Caches/HollyOptimizer/Icons/icon.png"
                )
            )
        )

    def test_diagnostics_redact_file_names(self):
        secret_path = os.path.expanduser("~/Documents/private-client-name.txt")
        with mock.patch.object(diagnostics, "configure_logging"), mock.patch.object(
            diagnostics._LOGGER, "warning"
        ):
            diagnostics.record_issue("test", PermissionError(1, "Operation not permitted"), secret_path)
        report = diagnostics.consume_issues("test")
        self.assertEqual(report["total"], 1)
        self.assertEqual(report["counts"], {"tcc_denied": 1})
        self.assertNotIn("private-client-name", str(report))
        self.assertEqual(report["messages"][0], "O macOS bloqueou o acesso. Verifique Acesso Total ao Disco.")

    def test_diagnostics_classify_policy_rejection_separately_from_unexpected(self):
        """A ValueError from the safety gate itself is a correct rejection,
        not a bug, and must not be reported to the user as an unexpected failure."""
        with mock.patch.object(diagnostics, "configure_logging"), mock.patch.object(
            diagnostics._LOGGER, "warning"
        ):
            diagnostics.record_issue(
                "test", ValueError("Item fora da política segura: /tmp/x"), "/tmp/x"
            )
        report = diagnostics.consume_issues("test")
        self.assertEqual(report["counts"], {"policy_blocked": 1})
        self.assertNotIn("inesperada", report["messages"][0])

    def test_diagnostics_coalesce_repeated_permission_scope(self):
        denied = PermissionError(1, "Operation not permitted")
        with mock.patch.object(diagnostics, "configure_logging"), mock.patch.object(
            diagnostics._LOGGER, "warning"
        ) as logger:
            diagnostics.record_issue("dedupe", denied, "~/Library/Containers/one")
            diagnostics.record_issue("dedupe", denied, "~/Library/Containers/two")
        report = diagnostics.consume_issues("dedupe")
        self.assertEqual(report["total"], 1)
        logger.assert_called_once()

    def test_operation_progress_can_be_cancelled(self):
        progress.start("test", "Scanning")
        progress.update("test", 42, "42 files")
        self.assertTrue(progress.cancel("test"))
        self.assertTrue(progress.is_cancelled("test"))
        progress.finish("test", "Cancelled")
        state = progress.snapshot("test")
        self.assertFalse(state["active"])
        self.assertEqual(state["processed"], 42)

    def test_startup_toggle_blocks_when_destination_already_exists(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            active = Path(temp_dir, "com.example.agent.plist")
            disabled = Path(temp_dir, "com.example.agent.plist.disabled")
            plist_body = (
                b'<?xml version="1.0"?><plist version="1.0"><dict>'
                b'<key>Label</key><string>com.example.agent</string></dict></plist>'
            )
            active.write_bytes(plist_body)
            disabled.write_bytes(b"conteudo distinto que nao pode ser sobrescrito")
            resolved = os.path.realpath(active)
            with startup._SCAN_LOCK:
                startup._LAST_SCAN_ITEMS.clear()
                startup._LAST_SCAN_ITEMS.add(resolved)

            ok, message = startup.toggle_startup_item(str(active), True)

            self.assertFalse(ok)
            self.assertIn("Conflito", message)
            self.assertTrue(active.exists())
            self.assertEqual(active.read_bytes(), plist_body)
            self.assertEqual(
                disabled.read_bytes(), b"conteudo distinto que nao pode ser sobrescrito"
            )

    def test_startup_toggle_renames_without_clobber_when_no_conflict(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            active = Path(temp_dir, "com.example.agent.plist")
            active.write_bytes(
                b'<?xml version="1.0"?><plist version="1.0"><dict>'
                b'<key>Label</key><string>com.example.agent</string></dict></plist>'
            )
            resolved = os.path.realpath(active)
            with startup._SCAN_LOCK:
                startup._LAST_SCAN_ITEMS.clear()
                startup._LAST_SCAN_ITEMS.add(resolved)

            ok, message = startup.toggle_startup_item(str(active), True)

            self.assertTrue(ok, message)
            self.assertFalse(active.exists())
            self.assertTrue(Path(temp_dir, "com.example.agent.plist.disabled").exists())

    def test_inventory_only_junk_categories_are_never_cleaned(self):
        for key in ("docker_containers", "xcode_archives", "xcode_device_support"):
            with self.subTest(key=key):
                self.assertFalse(junk.JUNK_TARGETS[key]["cleanable"])
                with mock.patch.object(junk, "move_to_trash") as trash:
                    result = junk.clean_target(key)
                self.assertEqual(result["moved"], 0)
                self.assertEqual(result["failed"], 1)
                self.assertIn("revisão manual", result["errors"][0])
                trash.assert_not_called()

        snapshot_result = junk.clean_target("time_machine_snapshots")
        self.assertEqual(snapshot_result["moved"], 0)
        self.assertEqual(snapshot_result["failed"], 1)
        self.assertIn("inválida", snapshot_result["errors"][0])

    def test_junk_selection_excludes_disabled_inventory_rows(self):
        app_js = Path(__file__).parents[1] / "gui" / "app.js"
        source = app_js.read_text(encoding="utf-8")
        self.assertIn(".junk-checkbox:not(:disabled)", source)
        self.assertIn(".junk-checkbox:checked:not(:disabled)", source)

    def test_docker_internal_components_are_protected(self):
        internal = os.path.expanduser(
            "~/Library/Containers/com.docker.docker/Data/vms/0/data.raw"
        )
        self.assertFalse(utils.is_safe_to_delete(internal))

    def test_npm_cache_children_are_deletable_after_policy_alignment(self):
        child = os.path.expanduser("~/.npm/_cacache/content-v2")
        root = os.path.expanduser("~/.npm/_cacache")
        self.assertTrue(utils._is_under_allow_root(os.path.realpath(child)))
        self.assertFalse(utils._is_under_allow_root(os.path.realpath(root)))

    def test_cargo_and_gradle_cache_children_are_deletable_but_roots_are_not(self):
        for root, child in (
            ("~/.cargo/registry/cache", "~/.cargo/registry/cache/index.crates.io-abc"),
            ("~/.cargo/registry/src", "~/.cargo/registry/src/index.crates.io-abc"),
            ("~/.gradle/caches", "~/.gradle/caches/modules-2"),
        ):
            with self.subTest(root=root):
                self.assertTrue(
                    utils._is_under_allow_root(os.path.realpath(os.path.expanduser(child)))
                )
                self.assertFalse(
                    utils._is_under_allow_root(os.path.realpath(os.path.expanduser(root)))
                )
        self.assertTrue(junk.JUNK_TARGETS["cargo_cache"]["cleanable"])
        self.assertTrue(junk.JUNK_TARGETS["gradle_cache"]["cleanable"])

    def test_apple_startup_items_cannot_be_toggled(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir, "com.apple.protected.plist")
            path.write_bytes(
                b'<?xml version="1.0"?><plist version="1.0"><dict>'
                b'<key>Label</key><string>com.apple.protected</string></dict></plist>'
            )
            resolved = os.path.realpath(path)
            with startup._SCAN_LOCK:
                startup._LAST_SCAN_ITEMS.clear()
                startup._LAST_SCAN_ITEMS.add(resolved)
            ok, message = startup.toggle_startup_item(str(path), True)
            self.assertFalse(ok)
            self.assertIn("Apple", message)


class AppleSiliconAuditTests(unittest.TestCase):
    """The architecture audit must stay read-only and classify honestly."""

    def _write_macho(self, path: Path, cputype: int) -> None:
        # Cabeçalho Mach-O 64 bits little-endian: magic seguido de cputype.
        path.write_bytes(
            struct.pack("<Ii", silicon.MH_MAGIC_64, cputype) + b"\x00" * 24
        )

    def _write_fat(self, path: Path, cputypes: list) -> None:
        blob = struct.pack(">II", silicon.FAT_MAGIC, len(cputypes))
        for cputype in cputypes:
            blob += struct.pack(">iiIII", cputype, 0, 4096, 1024, 12)
        path.write_bytes(blob)

    def test_thin_arm64_binary_is_native(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            binary = Path(temp_dir, "app")
            self._write_macho(binary, silicon.CPU_TYPE_ARM64)
            self.assertEqual(silicon._read_architectures(str(binary)), ["arm64"])
            self.assertEqual(
                silicon.classify_architectures(["arm64"])[0], "native"
            )

    def test_intel_only_binary_is_flagged_as_rosetta(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            binary = Path(temp_dir, "app")
            self._write_macho(binary, silicon.CPU_TYPE_X86_64)
            self.assertEqual(silicon._read_architectures(str(binary)), ["x86_64"])
            category, label = silicon.classify_architectures(["x86_64"])
            self.assertEqual(category, "intel")
            self.assertIn("Rosetta", label)

    def test_fat_binary_with_both_slices_is_universal(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            binary = Path(temp_dir, "app")
            self._write_fat(binary, [silicon.CPU_TYPE_X86_64, silicon.CPU_TYPE_ARM64])
            architectures = silicon._read_architectures(str(binary))
            self.assertCountEqual(architectures, ["x86_64", "arm64"])
            self.assertEqual(
                silicon.classify_architectures(architectures)[0], "universal"
            )

    def test_corrupt_and_absent_binaries_never_raise(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            garbage = Path(temp_dir, "garbage")
            garbage.write_bytes(b"\x00\x01\x02")
            self.assertEqual(silicon._read_architectures(str(garbage)), [])
            self.assertEqual(
                silicon._read_architectures(os.path.join(temp_dir, "missing")), []
            )

    def test_absurd_fat_arch_count_is_rejected(self):
        """A corrupt header must not drive an unbounded read."""
        with tempfile.TemporaryDirectory() as temp_dir:
            binary = Path(temp_dir, "app")
            binary.write_bytes(struct.pack(">II", silicon.FAT_MAGIC, 4_000_000_000))
            self.assertEqual(silicon._read_architectures(str(binary)), [])

    def test_web_app_shim_is_not_reported_as_unknown_architecture(self):
        """Chrome/Safari dock shortcuts have no Contents/MacOS at all."""
        with tempfile.TemporaryDirectory() as temp_dir:
            bundle = Path(temp_dir, "Gmail.app", "Contents")
            bundle.mkdir(parents=True)
            Path(bundle, "Info.plist").write_bytes(
                b'<?xml version="1.0"?><plist version="1.0"><dict></dict></plist>'
            )
            executable, web_app = silicon._bundle_executable(str(bundle.parent))
            self.assertEqual(executable, "")
            self.assertTrue(web_app)
            self.assertEqual(
                silicon.classify_architectures([], web_app=True)[0], "webapp"
            )

    def test_script_launcher_is_distinguished_from_unknown(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            script = Path(temp_dir, "launcher.sh")
            script.write_bytes(b"#!/bin/bash\nexec java -jar app.jar\n")
            self.assertTrue(silicon._is_script_launcher(str(script)))
            self.assertEqual(
                silicon.classify_architectures([], script=True)[0], "script"
            )

    def test_audit_declares_itself_read_only_and_touches_nothing(self):
        with mock.patch.object(utils, "move_to_trash") as trash:
            report = silicon.scan_app_architectures()
        trash.assert_not_called()
        self.assertTrue(report["read_only"])
        self.assertEqual(report["scanned"], len(report["apps"]))
        self.assertEqual(sum(report["totals"].values()), report["scanned"])
        # O módulo não expõe nenhuma operação de escrita.
        for name in dir(silicon):
            self.assertNotIn(
                name, ("delete", "clean", "remove", "thin_binary", "strip_architecture")
            )


class SwapReportingTests(unittest.TestCase):
    def test_swap_values_are_parsed_with_units(self):
        self.assertEqual(memory._parse_swap_value("1024.00M"), 1024 * 1024 ** 2)
        self.assertEqual(memory._parse_swap_value("2.00G"), 2 * 1024 ** 3)
        self.assertEqual(memory._parse_swap_value("0.00"), 0)
        self.assertEqual(memory._parse_swap_value("lixo"), 0)

    def test_swap_levels_escalate_with_usage(self):
        cases = [
            ("total = 1024.00M  used = 0.00M  free = 1024.00M", "normal"),
            ("total = 4096.00M  used = 2048.00M  free = 2048.00M", "warning"),
            ("total = 8192.00M  used = 6144.00M  free = 2048.00M", "critical"),
        ]
        for output, expected in cases:
            with self.subTest(output=output), mock.patch.object(
                memory, "run_command", return_value=(0, output, "")
            ):
                self.assertEqual(memory.get_swap_stats()["swap_level"], expected)

    def test_swap_failure_degrades_without_raising(self):
        with mock.patch.object(memory, "run_command", return_value=(1, "", "erro")):
            stats = memory.get_swap_stats()
        self.assertEqual(stats["swap_used_bytes"], 0)
        self.assertEqual(stats["swap_level"], "unknown")


def _usage_snapshot(**overrides):
    base = {
        "apps": [],
        "app_names": set(),
        "bundle_ids": set(),
        "bundle_tails": set(),
        "executables": set(),
        "commands": [],
    }
    base.update(overrides)
    return base


class SettingsTests(unittest.TestCase):
    def test_free_space_goal_is_validated_and_persisted(self):
        with tempfile.TemporaryDirectory() as temp_dir, mock.patch.object(
            settings, "data_dir", return_value=temp_dir
        ):
            self.assertEqual(settings.load_settings()["free_space_goal_gb"], 20)
            self.assertEqual(settings.set_free_space_goal("50")["free_space_goal_gb"], 50)
            self.assertEqual(settings.load_settings()["free_space_goal_gb"], 50)
            for invalid in (0, -5, "abc", None, True, 10**9):
                with self.subTest(value=invalid), self.assertRaises(ValueError):
                    settings.set_free_space_goal(invalid)
            self.assertEqual(settings.load_settings()["free_space_goal_gb"], 50)
            Path(temp_dir, "settings.json").write_text("{not json", encoding="utf-8")
            self.assertEqual(settings.load_settings()["free_space_goal_gb"], 20)
        self.assertEqual(settings.coerce_free_space_goal("nope"), 20)
        self.assertEqual(settings.coerce_free_space_goal(30.9), 30)


class UsageDetectionTests(unittest.TestCase):
    def test_running_match_checks_process_app_bundle_and_command_marker(self):
        snap = _usage_snapshot(
            executables={"node"},
            app_names={"xcode"},
            bundle_ids={"com.docker.docker"},
            bundle_tails={"docker"},
            commands=["/opt/homebrew/library/homebrew/brew.rb install wget"],
        )
        self.assertEqual(usage.running_match(process_names=("node",), snapshot=snap), "node")
        self.assertEqual(usage.running_match(app_names=("Xcode",), snapshot=snap), "Xcode")
        self.assertEqual(
            usage.running_match(bundle_ids=("com.docker.docker",), snapshot=snap),
            "com.docker.docker",
        )
        self.assertEqual(
            usage.running_match(command_markers=("Library/Homebrew",), snapshot=snap),
            "Library/Homebrew",
        )
        self.assertEqual(
            usage.running_match(process_names=("cargo",), app_names=("Slack",), snapshot=snap),
            "",
        )

    def test_app_folder_is_running_by_lock_file_or_running_app_name(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            folder = Path(temp_dir, "Slack")
            folder.mkdir()
            self.assertEqual(usage.app_folder_running(str(folder), _usage_snapshot()), "")
            (folder / "SingletonLock").symlink_to("host-123")
            self.assertEqual(usage.app_folder_running(str(folder), _usage_snapshot()), "Slack")

            other = Path(temp_dir, "discord")
            other.mkdir()
            self.assertEqual(
                usage.app_folder_running(str(other), _usage_snapshot(app_names={"discord"})),
                "discord",
            )
            self.assertEqual(
                usage.app_folder_running(
                    str(Path(temp_dir, "com.spotify.client")),
                    _usage_snapshot(bundle_ids={"com.spotify.client"}),
                ),
                "com.spotify.client",
            )

    def test_usage_labels(self):
        self.assertEqual(usage.describe("Xcode", 3)["state"], "running")
        self.assertEqual(usage.describe("", 0)["label"], "usado hoje")
        self.assertEqual(usage.describe("", 1)["label"], "usado ontem")
        idle = usage.describe("", 12)
        self.assertEqual(idle["state"], "idle")
        self.assertIn("12 dias", idle["label"])
        self.assertEqual(usage.describe("", None)["state"], "unknown")

    def test_last_activity_reads_root_and_direct_children(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            old = time.time() - 10 * 86400
            os.utime(temp_dir, (old, old))
            self.assertEqual(usage.last_activity_days([temp_dir]), 10)
            Path(temp_dir, "fresh").write_text("x", encoding="utf-8")
            os.utime(temp_dir, (old, old))
            self.assertEqual(usage.last_activity_days([temp_dir]), 0)
            self.assertIsNone(usage.last_activity_days([os.path.join(temp_dir, "missing")]))


class JunkUsageAndDelegationTests(unittest.TestCase):
    def test_nested_category_root_is_delegated_instead_of_double_counted(self):
        with tempfile.TemporaryDirectory(dir=os.path.expanduser("~/Downloads")) as temp_dir:
            parent = Path(temp_dir, "Caches")
            pip = parent / "pip"
            pip.mkdir(parents=True)
            (pip / "wheel.whl").write_bytes(b"x" * 100)
            (parent / "other").mkdir()
            (parent / "other" / "f.bin").write_bytes(b"y" * 50)
            targets = {
                "parent": {"name": "P", "description": "", "roots": [str(parent)], "cleanable": True},
                "pip": {"name": "pip", "description": "", "roots": [str(pip)], "cleanable": True},
            }
            with mock.patch.dict(junk.JUNK_TARGETS, targets, clear=True):
                results = junk.scan_junk()
                with junk._SCAN_LOCK:
                    registered = dict(junk._LAST_SCAN_ITEMS["parent"])
            self.assertEqual(results["pip"]["size_bytes"], 100)
            self.assertEqual(results["parent"]["size_bytes"], 50)
            self.assertEqual(results["parent"]["delegated"], 1)
            self.assertNotIn(os.path.realpath(pip), registered)

    def test_category_is_blocked_while_its_tool_runs_and_rechecked_at_clean_time(self):
        with tempfile.TemporaryDirectory(dir=os.path.expanduser("~/Downloads")) as temp_dir:
            Path(temp_dir, "build.cache").write_text("x", encoding="utf-8")
            target = {
                "name": "Xcode DerivedData", "description": "", "roots": [temp_dir],
                "cleanable": True, "usage": {"app_names": ("Xcode",)},
                "block_when_running": True,
            }
            running = _usage_snapshot(app_names={"xcode"})
            with mock.patch.dict(junk.JUNK_TARGETS, {"xcode": target}, clear=True):
                with mock.patch.object(junk.usage_detector, "get_snapshot", return_value=running):
                    results = junk.scan_junk()
                    self.assertTrue(results["xcode"]["blocked"])
                    self.assertEqual(results["xcode"]["usage"]["state"], "running")
                    self.assertIn("Xcode", results["xcode"]["blocked_hint"])
                    with mock.patch.object(junk, "move_to_trash") as trash:
                        result = junk.clean_target("xcode")
                    trash.assert_not_called()
                    self.assertEqual(result["failed"], 1)
                    self.assertIn("Xcode", result["errors"][0])

                with mock.patch.object(junk.usage_detector, "get_snapshot", return_value=_usage_snapshot()):
                    results = junk.scan_junk()
                    self.assertFalse(results["xcode"]["blocked"])
                    with mock.patch.object(junk, "move_to_trash", return_value=(True, "ok")) as trash:
                        result = junk.clean_target("xcode")
                    self.assertEqual(result["moved"], 1)
                    self.assertEqual(trash.call_args.kwargs["feature"], "junk")
                    self.assertEqual(trash.call_args.kwargs["size_bytes"], 1)

    def test_electron_cache_of_an_open_app_is_deferred_and_refused_later(self):
        with tempfile.TemporaryDirectory(dir=os.path.expanduser("~/Downloads")) as temp_dir:
            support = Path(temp_dir)
            open_cache = support / "Slack" / "Cache"
            open_cache.mkdir(parents=True)
            (open_cache / "data_0").write_bytes(b"a" * 10)
            (support / "Slack" / "SingletonLock").symlink_to("host-1")
            closed_cache = support / "Notion" / "Cache"
            closed_cache.mkdir(parents=True)
            (closed_cache / "data_0").write_bytes(b"b" * 20)
            target = {
                "name": "Electron", "description": "",
                "roots": [str(support / "*" / "Cache")],
                "cleanable": True, "item_running_check": "app_folder",
            }
            with mock.patch.dict(junk.JUNK_TARGETS, {"electron": target}, clear=True), \
                 mock.patch.object(junk.usage_detector, "get_snapshot", return_value=_usage_snapshot()):
                results = junk.scan_junk()
                self.assertEqual(results["electron"]["size_bytes"], 20)
                self.assertEqual(results["electron"]["deferred_bytes"], 10)
                self.assertIn("Slack", results["electron"]["deferred_hint"])

                # Notion opens between the scan and the cleanup.
                (support / "Notion" / "SingletonLock").symlink_to("host-2")
                with mock.patch.object(junk, "move_to_trash") as trash:
                    result = junk.clean_target("electron")
                trash.assert_not_called()
                self.assertEqual(result["failed"], 1)
                self.assertIn("Notion", result["errors"][0])

    def test_new_cache_categories_follow_the_path_policy(self):
        for root, child in (
            ("~/.cache/uv", "~/.cache/uv/wheels"),
            ("~/.cache/pip", "~/.cache/pip/http"),
            ("~/.bun/install/cache", "~/.bun/install/cache/pkg"),
            ("~/Library/pnpm/store", "~/Library/pnpm/store/v3"),
            ("~/.yarn/berry/cache", "~/.yarn/berry/cache/a.zip"),
        ):
            with self.subTest(root=root):
                self.assertTrue(
                    utils._is_under_allow_root(os.path.realpath(os.path.expanduser(child)))
                )
                self.assertFalse(
                    utils._is_under_allow_root(os.path.realpath(os.path.expanduser(root)))
                )
        for key in (
            "homebrew_cache", "pnpm_store", "yarn_cache", "bun_cache", "uv_cache",
            "go_build_cache", "playwright_browsers", "electron_app_caches", "crash_reports",
        ):
            self.assertTrue(junk.JUNK_TARGETS[key]["cleanable"], key)
        for key in ("ai_models", "claude_code_data", "claude_desktop_vm", "codex_data"):
            self.assertFalse(junk.JUNK_TARGETS[key]["cleanable"], key)
        for key in ("xcode_derived_data", "homebrew_cache", "gradle_cache", "playwright_browsers"):
            self.assertTrue(junk.JUNK_TARGETS[key]["block_when_running"], key)
        for root in junk.JUNK_TARGETS["electron_app_caches"]["roots"]:
            self.assertTrue(any(root.endswith("/" + sub) for sub in junk._ELECTRON_CACHE_SUBDIRS), root)
            for forbidden in ("Local Storage", "IndexedDB", "Session Storage", "Preferences", "Cookies"):
                self.assertNotIn(forbidden, root)
        # The app's own history and settings never enter the general cleanup.
        self.assertTrue(
            junk._is_own_data(os.path.expanduser("~/Library/Application Support/HollyOptimizer/history.json"))
        )


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.path.expanduser("~/Downloads"))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(os.path.realpath(self.temp.name))
        self.trash = self.root / "Trash"
        self.trash.mkdir()
        data = self.root / "data"
        data.mkdir()
        for patch in (
            mock.patch.object(history, "_history_path", return_value=str(data / "history.json")),
            mock.patch.object(history, "_trash_dir", return_value=str(self.trash)),
        ):
            patch.start()
            self.addCleanup(patch.stop)
        history.begin_batch("")

    def _newest_entry_id(self):
        return history.list_history()["batches"][0]["items"][0]["id"]

    def test_record_list_and_restore_roundtrip(self):
        original = self.root / "cache-folder"
        original.mkdir()
        (original / "entry.bin").write_bytes(b"x" * 10)
        trashed = self.trash / "cache-folder"
        os.rename(original, trashed)

        history.begin_batch("Limpeza de teste")
        history.record_move(
            feature="junk", original_path=str(original), trash_path=str(trashed),
            size_bytes=10, file_count=1,
        )
        listing = history.list_history()
        self.assertTrue(listing["trash_accessible"])
        self.assertEqual(len(listing["batches"]), 1)
        batch = listing["batches"][0]
        self.assertEqual(batch["label"], "Limpeza de teste")
        self.assertEqual(batch["in_trash"], 1)
        self.assertEqual(batch["items"][0]["status"], "in_trash")
        self.assertEqual(listing["totals"]["moved_bytes"], 10)

        ok, message = history.restore_move(batch["items"][0]["id"])
        self.assertTrue(ok, message)
        self.assertTrue((original / "entry.bin").is_file())
        self.assertFalse(trashed.exists())
        self.assertEqual(history.list_history()["batches"][0]["restored"], 1)

        ok, message = history.restore_move(batch["items"][0]["id"])
        self.assertFalse(ok)
        self.assertIn("já foi restaurado", message)

    def test_restore_refuses_tampered_occupied_or_unmanaged_paths(self):
        outside = self.root / "outside"
        outside.mkdir()
        history.record_move(feature="junk", original_path=str(self.root / "orig"), trash_path=str(outside))
        ok, message = history.restore_move(self._newest_entry_id())
        self.assertFalse(ok)
        self.assertIn("Lixeira", message)
        self.assertTrue(outside.exists())

        trashed = self.trash / "orig2"
        trashed.mkdir()
        occupied = self.root / "orig2"
        occupied.mkdir()
        history.record_move(feature="junk", original_path=str(occupied), trash_path=str(trashed))
        ok, message = history.restore_move(self._newest_entry_id())
        self.assertFalse(ok)
        self.assertIn("Já existe", message)
        self.assertTrue(trashed.exists())

        keychain = self.trash / "login.keychain-db"
        keychain.write_bytes(b"k")
        history.record_move(
            feature="junk",
            original_path=os.path.expanduser("~/Library/Keychains/hollyoptimizer-test.keychain-db"),
            trash_path=str(keychain),
        )
        ok, message = history.restore_move(self._newest_entry_id())
        self.assertFalse(ok)
        self.assertIn("fora das áreas", message)
        self.assertTrue(keychain.exists())

        self.assertFalse(history.restore_move("does-not-exist")[0])
        self.assertFalse(history.restore_move("")[0])

    def test_restore_reports_missing_full_disk_access(self):
        trashed = self.trash / "item"
        trashed.write_bytes(b"x")
        history.record_move(feature="junk", original_path=str(self.root / "item"), trash_path=str(trashed))
        with mock.patch.object(history, "trash_accessible", return_value=False):
            listing = history.list_history()
            ok, message = history.restore_move(self._newest_entry_id())
        self.assertFalse(listing["trash_accessible"])
        self.assertEqual(listing["batches"][0]["items"][0]["status"], "unknown")
        self.assertFalse(ok)
        self.assertIn("Acesso Total ao Disco", message)
        self.assertTrue(trashed.exists())

    def test_scan_timeline_and_growth(self):
        history.record_scan(
            free_bytes=10, total_bytes=100, cleanable_bytes=5, inventory_bytes=1,
            categories={"a": {"name": "A", "size_bytes": 100, "cleanable": True}},
        )
        history.record_scan(
            free_bytes=20, total_bytes=100, cleanable_bytes=7, inventory_bytes=1,
            categories={
                "a": {"name": "A", "size_bytes": 400, "cleanable": True},
                "b": {"name": "B", "size_bytes": 50, "cleanable": False},
                "c": {"name": "C", "size_bytes": 0, "cleanable": True},
            },
        )
        listing = history.list_history()
        self.assertEqual([scan["free_bytes"] for scan in listing["scans"]], [20, 10])
        self.assertEqual([item["key"] for item in listing["growth"]], ["a", "b"])
        self.assertEqual(listing["growth"][0]["delta_bytes"], 300)
        self.assertEqual(listing["totals"]["scans"], 2)

    def test_startup_labels_have_no_baseline_on_first_scan(self):
        self.assertIsNone(history.update_startup_labels(["a", "b"]))
        self.assertEqual(history.update_startup_labels(["a", "c"]), {"a", "b"})
        self.assertEqual(history.update_startup_labels([]), {"a", "b", "c"})

    def test_native_trash_move_records_history_only_when_a_feature_is_named(self):
        with tempfile.TemporaryDirectory(dir=os.path.expanduser("~/Downloads")) as temp_dir:
            item = Path(temp_dir, "cache.bin")
            item.write_bytes(b"x")
            foundation = mock.Mock()
            resulting = mock.Mock()
            resulting.path.return_value = str(self.trash / "cache.bin")
            native = foundation.NSFileManager.defaultManager.return_value.trashItemAtURL_resultingItemURL_error_
            native.return_value = (True, resulting, None)
            with mock.patch.dict("sys.modules", {"Foundation": foundation}):
                ok, _ = utils.move_to_trash(str(item))
                self.assertTrue(ok)
                self.assertEqual(history.list_history()["totals"]["moves"], 0)
                ok, message = utils.move_to_trash(str(item), feature="large_files", size_bytes=1, file_count=1)
            self.assertTrue(ok)
            self.assertIn("cache.bin", message)
            listing = history.list_history()
            self.assertEqual(listing["totals"]["moves"], 1)
            entry = listing["batches"][0]["items"][0]
            self.assertEqual(entry["feature"], "large_files")
            self.assertEqual(entry["original_path"], os.path.realpath(item))
            self.assertEqual(entry["trash_name"], "cache.bin")


class DashboardHealthTests(unittest.TestCase):
    def test_crash_loops_group_recent_reports_by_process(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            now = time.time()

            def report(name, age_seconds):
                path = Path(temp_dir, name)
                path.write_text("{}", encoding="utf-8")
                os.utime(path, (now - age_seconds, now - age_seconds))

            for index in range(3):
                report(f"Safari-2026-10-27-08000{index}.ips", 600 * (index + 1))
            report("Code Helper (Renderer)-2026-10-27-090000.ips", 100)
            report("Safari-2026-10-20-080000.ips", 10 * 86400)
            report("notes.txt", 10)

            loops = health.detect_crash_loops(temp_dir, now=now)
            self.assertEqual([(loop["name"], loop["count"]) for loop in loops], [("Safari", 3)])
            self.assertEqual(health.detect_crash_loops(os.path.join(temp_dir, "missing"), now=now), [])

    def test_disk_is_evaluated_against_the_goal(self):
        gb = 1024 ** 3
        self.assertEqual(health.evaluate_disk({"free_bytes": 50 * gb, "total_bytes": 500 * gb}, 20)["level"], "ok")
        below = health.evaluate_disk({"free_bytes": 12 * gb, "total_bytes": 500 * gb}, 20)
        self.assertEqual(below["level"], "attention")
        self.assertEqual(below["deficit_bytes"], 8 * gb)
        self.assertEqual(health.evaluate_disk({"free_bytes": 2 * gb, "total_bytes": 500 * gb}, 20)["level"], "critical")
        self.assertEqual(health.evaluate_disk({}, 20)["level"], "unknown")

    def test_dashboard_health_is_read_only_and_builds_alerts(self):
        gb = 1024 ** 3
        with mock.patch.object(
            health, "get_disk_usage",
            return_value={"free_bytes": 3 * gb, "total_bytes": 500 * gb, "percentage": 99},
        ), mock.patch.object(
            health, "trash_summary",
            return_value={"items": 4, "size_bytes": 2 * gb, "size_human": "2.00 GB", "accessible": True},
        ), mock.patch.object(
            health, "detect_crash_loops", return_value=[{"name": "Foo", "count": 5, "latest_ts": 0}]
        ), mock.patch.object(health, "load_settings", return_value={"free_space_goal_gb": 20}):
            report = health.get_dashboard_health()
        self.assertTrue(report["read_only"])
        self.assertEqual(
            [alert["id"] for alert in report["alerts"]],
            ["disk_critical", "trash_large", "crash_loop:Foo"],
        )

    def test_trash_summary_degrades_without_full_disk_access(self):
        with mock.patch.object(health.os, "listdir", side_effect=PermissionError(1, "Operation not permitted")):
            summary = health.trash_summary()
        self.assertFalse(summary["accessible"])
        self.assertEqual(summary["size_bytes"], 0)


class UninstallerLastUseTests(unittest.TestCase):
    def test_last_use_labels_and_unused_threshold(self):
        now = 1_800_000_000.0
        self.assertEqual(uninstaller.describe_last_use(now - 3600, 5, now=now)["last_used_label"], "usado hoje")
        self.assertEqual(uninstaller.describe_last_use(now - 2 * 86400, 5, now=now)["last_used_label"], "usado há 2 dias")
        old = uninstaller.describe_last_use(now - 120 * 86400, 1, now=now)
        self.assertTrue(old["unused"])
        self.assertEqual(old["last_used_days"], 120)
        running = uninstaller.describe_last_use(now - 120 * 86400, 1, running=True, now=now)
        self.assertFalse(running["unused"])
        self.assertEqual(running["last_used_label"], "aberto agora")
        unknown = uninstaller.describe_last_use(None, 0, now=now)
        self.assertFalse(unknown["unused"])
        self.assertIsNone(unknown["last_used_days"])


class ProcessQuitTests(unittest.TestCase):
    def test_quit_requires_fresh_identity_and_a_windowed_app(self):
        pid = 99998
        with memory._PROCESS_LOCK:
            memory._LAST_PROCESS_IDENTITIES.clear()
        ok, message = memory.quit_application(pid)
        self.assertFalse(ok)
        self.assertIn("atualize", message)

        with memory._PROCESS_LOCK:
            memory._LAST_PROCESS_IDENTITIES[pid] = {
                "uid": os.getuid(), "start_time": "t", "path": "/usr/local/bin/node",
            }
        with mock.patch.object(memory, "_get_process_info", return_value=(os.getuid(), "t", "/usr/local/bin/node")):
            ok, message = memory.quit_application(pid)
        self.assertFalse(ok)
        self.assertIn("Encerrar", message)

        app_path = "/Applications/Test.app/Contents/MacOS/Test"
        with memory._PROCESS_LOCK:
            memory._LAST_PROCESS_IDENTITIES[pid] = {"uid": os.getuid(), "start_time": "t", "path": app_path}
        fake_app = mock.Mock()
        fake_app.terminate.return_value = True
        fake_app.localizedName.return_value = "Test"
        appkit = mock.Mock()
        appkit.NSRunningApplication.runningApplicationWithProcessIdentifier_.return_value = fake_app
        with mock.patch.object(memory, "_get_process_info", return_value=(os.getuid(), "t", app_path)), \
             mock.patch.dict(sys.modules, {"AppKit": appkit}):
            ok, message = memory.quit_application(pid)
        self.assertTrue(ok, message)
        fake_app.terminate.assert_called_once()
        appkit.NSRunningApplication.runningApplicationWithProcessIdentifier_.assert_called_once_with(pid)

        self.assertFalse(memory.quit_application(True)[0])
        self.assertFalse(memory.quit_application(1)[0])
        self.assertFalse(memory.quit_application(os.getpid())[0])

    def test_readiness_levels(self):
        gb = 1024 ** 3
        self.assertEqual(memory.describe_readiness(16 * gb, 8 * gb, 0, "normal")["readiness_level"], "ok")
        self.assertEqual(memory.describe_readiness(16 * gb, 3 * gb, 0, "normal")["readiness_level"], "warning")
        self.assertEqual(memory.describe_readiness(16 * gb, 8 * gb, 2 * gb, "normal")["readiness_level"], "warning")
        self.assertEqual(memory.describe_readiness(16 * gb, 1 * gb, 0, "normal")["readiness_level"], "critical")
        self.assertEqual(memory.describe_readiness(16 * gb, 8 * gb, 0, "critical")["readiness_level"], "critical")
        self.assertEqual(memory.describe_readiness(16 * gb, 8 * gb, 5 * gb, "normal")["readiness_level"], "critical")


class StartupNewItemTests(unittest.TestCase):
    def test_items_unseen_by_previous_scans_are_flagged(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            Path(temp_dir, "com.example.agent.plist").write_bytes(
                b'<?xml version="1.0"?><plist version="1.0"><dict>'
                b'<key>Label</key><string>com.example.agent</string>'
                b'<key>Program</key><string>/bin/ls</string></dict></plist>'
            )
            dirs = {"user_agent": {"name": "Agentes", "path": temp_dir, "sudo_required": False}}
            with mock.patch.object(startup, "STARTUP_DIRS", dirs), \
                 mock.patch.object(startup, "_scan_login_items", return_value=[]), \
                 mock.patch.object(startup, "_loaded_launchd_labels", return_value=set()):
                with mock.patch("core.history.update_startup_labels", return_value=None):
                    self.assertFalse(startup.scan_startup()[0]["is_new"])
                with mock.patch("core.history.update_startup_labels", return_value={"com.other"}):
                    self.assertTrue(startup.scan_startup()[0]["is_new"])
                with mock.patch("core.history.update_startup_labels", return_value={"com.example.agent"}):
                    self.assertFalse(startup.scan_startup()[0]["is_new"])


if __name__ == "__main__":
    unittest.main()
