import contextlib
import io
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core import (
    apps,
    browser_cleaner,
    dependencies,
    diagnostics,
    duplicates,
    junk,
    large_files,
    memory,
    progress,
    security_audit,
    self_test,
    silicon,
    startup,
    uninstaller,
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
        A cache whose contents changed after the scan is still cleanable.

        The previous implementation snapshotted every descendant's mtime and
        refused the whole item when any of them moved, which is the normal
        state of a cache and blocked legitimate cleanups. The guarantees that
        actually matter are asserted by the two tests below: the root identity
        is revalidated, and the full safety gate is re-run over the subtree.
        """
        cache_parent = os.path.expanduser("~/Library/Caches")
        with tempfile.TemporaryDirectory(dir=cache_parent) as cache_root:
            scanned = Path(cache_root, "cache2")
            scanned.mkdir()
            content = scanned / "entry.bin"
            content.write_bytes(b"before")
            target = self._target(cache_root)

            with mock.patch.dict(
                browser_cleaner.BROWSER_CACHE_TARGETS, {"test": target}, clear=True
            ), mock.patch.object(
                browser_cleaner, "_browser_is_running", return_value=False
            ):
                browser_cleaner.scan_browser_caches()
                content.write_bytes(b"changed content after the scan")
                with mock.patch.object(
                    browser_cleaner, "move_to_trash", return_value=(True, "ok")
                ) as trash:
                    result = browser_cleaner.clean_browser_cache("test")

            self.assertEqual(result["moved"], 1)
            self.assertEqual(result["failed"], 0)
            trash.assert_called_once()
            self.assertEqual(trash.call_args.args[0], os.path.realpath(scanned))

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
        }

        def fake_run(command, timeout=120):
            return outputs[os.path.basename(command[0])]

        with mock.patch.object(security_audit, "run_command", side_effect=fake_run) as runner:
            report = security_audit.run_security_audit()

        self.assertTrue(report["read_only"])
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["summary"], {"ok": 5, "attention": 0, "unknown": 0})
        self.assertEqual(
            [call.args[0][1] for call in runner.call_args_list],
            ["status", "--getglobalstate", "--status", "status", "--schedule"],
        )

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


if __name__ == "__main__":
    unittest.main()
