import contextlib
import io
import unittest
from unittest import mock

import hollyoptimizer as cli


class BrowserMenuTests(unittest.TestCase):
    def test_nonpositive_selection_cannot_select_last_browser(self):
        for choice in ("0", "-1"):
            with self.subTest(choice=choice), \
                 mock.patch.object(cli, "scan_browser_caches", return_value={
                     "test": {"name": "Test", "accessible": True, "running": False,
                              "count": 1, "size_human": "1 KB", "size_bytes": 1024}
                 }), \
                 mock.patch("builtins.input", return_value=choice) as ask, \
                 mock.patch.object(cli, "clean_browser_cache") as clean, \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                cli.menu_browser_caches()

            self.assertIn("Opção inválida", output.getvalue())
            ask.assert_called_once()
            clean.assert_not_called()


class StartupMenuTests(unittest.TestCase):
    def _login_item(self):
        return {
            "kind": "login_item",
            "label": "Example",
            "category_name": "Itens de Início de Sessão",
            "exec_path": "/Applications/Example.app",
            "filepath": "",
            "is_disabled": False,
            "is_broken": False,
            "sudo_required": False,
        }

    def test_login_item_uses_dedicated_removal_after_confirmation(self):
        with mock.patch.object(cli, "scan_startup", return_value=[self._login_item()]), \
             mock.patch("builtins.input", side_effect=["1", "s", "", ""]), \
             mock.patch.object(cli, "remove_login_item", return_value=(True, "Removido")) as remove, \
             mock.patch.object(cli, "toggle_startup_item") as toggle, \
             contextlib.redirect_stdout(io.StringIO()):
            cli.menu_startup()

        remove.assert_called_once_with("Example")
        toggle.assert_not_called()

    def test_login_item_cancellation_preserves_it(self):
        with mock.patch.object(cli, "scan_startup", return_value=[self._login_item()]), \
             mock.patch("builtins.input", side_effect=["1", "n", ""]), \
             mock.patch.object(cli, "remove_login_item") as remove, \
             mock.patch.object(cli, "toggle_startup_item") as toggle, \
             contextlib.redirect_stdout(io.StringIO()):
            cli.menu_startup()

        remove.assert_not_called()
        toggle.assert_not_called()

    def test_launch_agent_keeps_toggle_behavior(self):
        item = {**self._login_item(), "kind": "launchd", "filepath": "/tmp/example.plist"}
        with mock.patch.object(cli, "scan_startup", return_value=[item]), \
             mock.patch("builtins.input", side_effect=["1", "", ""]), \
             mock.patch.object(cli, "remove_login_item") as remove, \
             mock.patch.object(cli, "toggle_startup_item", return_value=(True, "Desativado")) as toggle, \
             contextlib.redirect_stdout(io.StringIO()):
            cli.menu_startup()

        remove.assert_not_called()
        toggle.assert_called_once_with("/tmp/example.plist", disable=True)


if __name__ == "__main__":
    unittest.main()
