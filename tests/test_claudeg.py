# SPDX-License-Identifier: GPL-3.0-or-later
"""ClaudeG tests (stdlib unittest). Run: python tests/test_claudeg.py"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(os.path.dirname(HERE), "scripts")
sys.path.insert(0, SCRIPTS)

import guard_hook as g  # noqa: E402

CFG = dict(g.DEFAULTS)
NL = chr(10)
FAKE_AWS = "AKIA" + "Q7" * 8  # built at runtime so this file never contains a key-shaped literal


def bash(cmd, windows=False, cfg=CFG):
    return g.pre_event({"tool_name": "Bash", "tool_input": {"command": cmd}}, cfg, windows=windows)


def ps(cmd, windows=True, cfg=CFG):
    return g.pre_event({"tool_name": "PowerShell", "tool_input": {"command": cmd}}, cfg, windows=windows)


def edit(path, old, new, cfg=CFG):
    return g.pre_event({"tool_name": "Edit", "tool_input": {"file_path": path, "old_string": old,
                                                             "new_string": new}}, cfg)


def decision(out):
    if not out:
        return None
    return out.get("permissionDecision") or ("warn" if out.get("additionalContext") else None)


class Destructive(unittest.TestCase):
    def check(self, cmd, expected, fn=bash):
        self.assertEqual(decision(fn(cmd)), expected, cmd)

    def test_rm(self):
        self.check("rm -rf src", "ask")
        self.check("rm -r -f ./lib", "ask")
        self.check('rm -rf "$D"', "ask")
        self.check("rm -rf *", "ask")
        self.check("rm -rf node_modules dist", None)
        self.check("rm -rf /tmp/build-123", None)
        self.check("rm -rf C:/Users/HP/AppData/Local/Temp/x", None)
        self.check("rm notes.txt", None)

    def test_rm_resolves_variables_set_in_the_same_line(self):
        self.check("T=~/.mintoken-docs-tmp/d1; rm -rf $T; mkdir -p $T", None)
        self.check('D=$(mktemp -d); rm -rf "$D"', None)
        self.check("D=~/project; rm -rf ${D}", "ask")
        self.check("rm -rf ~/.cache-tmp ~/Templates", "ask")  # Templates is not a temp dir
        self.check("cd C:/Users/HP/AppData/Local/Temp/x && rm -rf MinToken", None)
        self.check("rm -rf dist build src/nbug.egg-info .venv-clean", None)
        self.check("rm -rf build 2>/dev/null", None)
        self.check("rm -rf build > log.txt", None)
        self.assertNotIn("log.txt", bash("rm -rf src > log.txt")["permissionDecisionReason"])
        self.check("find . -name __pycache__ -prune -exec rm -rf {} +", None)
        self.assertEqual(decision(g.pre_event({"tool_name": "Bash", "tool_input": {"command": "rm -rf src"},
                                               "cwd": "C:/Users/HP/AppData/Local/Temp/run1"}, CFG)), None)

    def test_rm_inside_build_folders(self):
        self.check("rm -rf versions/*/build/generated/stonecutter", None)
        self.check("rm -rf build/libs build/classes ../app/node_modules/.vite", None)
        self.assertIsNone(ps(r"Remove-Item -Recurse -Force versions\1.21\build\classes", windows=False))
        self.check("rm -rf build/../src", "ask")
        self.check("rm -rf versions/26.3", "ask")
        self.check("rm -rf bu* */src", "ask")
        self.check("rm -rf C:/build/app/src ~/out/notes", "ask")  # absolute: only the last folder counts
        self.assertEqual(decision(g.pre_event({"tool_name": "Bash", "tool_input": {"command": "rm -rf src"},
                                               "cwd": "C:/work/build/app"}, CFG)), "ask")  # cwd is not the target

    def test_safe_paths(self):
        cfg = dict(CFG, safe_paths=["Desktop/PhotonAI/.photonai_kontrol"])
        cmd = r"Remove-Item -Recurse -Force C:\Users\HP\Desktop\PhotonAI\.photonai_kontrol"
        self.assertIsNone(ps(cmd, windows=False, cfg=cfg))
        self.assertEqual(decision(ps(cmd, windows=False)), "ask")

    def test_quoted_text_is_not_a_command(self):
        self.check('grep -rn "rm -rf|reset --hard" .', None)
        self.check('git commit -m "avoid git reset --hard"', None)
        self.check("cat <<'EOF' > clean.sh" + NL + "rm -rf build/ src/" + NL + "EOF", None)

    def test_git(self):
        for cmd in ("git reset --hard", "git reset --hard origin/main", "git clean -fd", "git push --force",
                    "git push -fu origin x", "git push origin +main", "git push origin --delete old",
                    "git checkout -- a.py", "git checkout .", "git restore a.py", "git branch -D feat",
                    "git stash drop", "git stash clear", "git -C repo reset --hard", "git filter-branch x",
                    "git switch --discard-changes main"):
            self.check(cmd, "ask")
        for cmd in ("git reset --soft HEAD~1", "git clean -n", "git push --force-with-lease", "git push origin main",
                    "git checkout -b new", "git restore --staged a.py", "git branch -d done", "git stash",
                    "git status", "git log --oneline -5"):
            self.check(cmd, None)

    def test_chains_and_nesting(self):
        self.check("cd repo && git reset --hard", "ask")
        self.check("ls; rm -rf src", "ask")
        self.check('bash -c "rm -rf src"', "ask")
        self.check("sudo rm -rf /var/www", "ask")
        self.check("find . -name '*.log' -delete", "ask")
        self.check("find . -name x -exec rm {} +", "ask")

    def test_sql(self):
        self.check('psql -c "DROP TABLE users"', "ask")
        self.check('sqlite3 app.db "DELETE FROM users"', "ask")
        self.check('sqlite3 app.db "DELETE FROM users WHERE id = 1"', None)
        self.check('psql -c "SELECT 1"', None)

    def test_powershell(self):
        self.check(r"Remove-Item -Recurse -Force C:\proj\src", "ask", fn=lambda c: ps(c, windows=False))
        self.check(r'Remove-Item -Path "C:\proj\src" -r', "ask", fn=lambda c: ps(c, windows=False))
        self.check(r"Remove-Item C:\proj\notes.txt", None, fn=lambda c: ps(c, windows=False))
        self.check(r'Remove-Item -Recurse "$env:TEMP\x"', None, fn=lambda c: ps(c, windows=False))
        self.check(r"cmd /c rd /s /q C:\proj", "ask", fn=lambda c: ps(c, windows=False))
        self.check(r"Remove-Item -Recurse C:\proj\src -WhatIf", None, fn=lambda c: ps(c, windows=False))
        out = ps(r"Remove-Item -Recurse -Force C:\proj\data -ErrorAction SilentlyContinue", windows=False)
        self.assertIn(r"C:\proj\data", out["permissionDecisionReason"])
        self.assertNotIn("SilentlyContinue", out["permissionDecisionReason"])
        self.check("git push --force", "ask", fn=lambda c: ps(c, windows=False))

    def test_message_and_modes(self):
        out = bash("git reset --hard")
        self.assertIn("git reset --hard", out["permissionDecisionReason"])
        self.assertEqual(decision(bash("git reset --hard", cfg=dict(CFG, destructive="deny"))), "deny")
        self.assertIsNone(bash("git reset --hard", cfg=dict(CFG, destructive="off")))


class WindowsShell(unittest.TestCase):
    def setUp(self):
        self.real_which = g.which
        g.which = lambda name: None

    def tearDown(self):
        g.which = self.real_which

    def test_powershell_bash_syntax(self):
        self.assertEqual(decision(ps("cd x && npm test")), "deny")
        self.assertEqual(decision(ps("npm test || echo failed")), "deny")
        self.assertEqual(decision(ps("npm test 2>/dev/null")), "deny")
        self.assertEqual(decision(ps("Get-Content a.txt | head -5")), "deny")
        self.assertEqual(decision(ps("export X=1")), "deny")
        self.assertIn("Get-ChildItem -Force", ps("ls -la")["permissionDecisionReason"])
        self.assertEqual(decision(ps("mkdir -p a/b")), "deny")

    def test_powershell_valid(self):
        for cmd in ('Write-Output "a && b"', "cd x; if ($?) { npm test }", "Get-ChildItem | Select-Object -First 5",
                    "ls", "Remove-Item -Recurse -Force build", "npm test 2>$null"):
            self.assertIsNone(ps(cmd), cmd)
        self.assertIsNone(ps("cd x && npm test", cfg=dict(CFG, powershell="7")))

    def test_python_posix_paths(self):
        self.assertEqual(decision(bash("python -c \"open('/c/Users/HP/x.txt')\"", windows=True)), "deny")
        self.assertEqual(decision(bash('python -c "import json; json.load(open(\'$HOME/a.json\'))"', windows=True)),
                         "deny")
        heredoc = "python - <<'EOF'" + NL + "print(open('/c/Users/HP/a').read())" + NL + "EOF"
        self.assertEqual(decision(bash(heredoc, windows=True)), "deny")
        self.assertIsNone(bash("python -c \"import os; print(os.path.expanduser('~'))\"", windows=True))
        self.assertIsNone(bash("python /c/Users/HP/x.py --out /c/tmp", windows=True))  # args are converted
        self.assertIsNone(bash("python -c \"open('/c/Users/HP/x.txt')\"", windows=False))
        self.assertIsNone(bash("python -c \"open('/c/Users/HP/x.txt')\"", windows=True, cfg=dict(CFG, shell="off")))


class Edits(unittest.TestCase):
    def setUp(self):
        # Under home, not %TEMP%: Store Python on Windows virtualizes AppData writes.
        self.home = tempfile.mkdtemp(prefix=".claudeg-test-", dir=os.path.expanduser("~"))

    def tearDown(self):
        shutil.rmtree(self.home, ignore_errors=True)

    def test_weakened_tests(self):
        self.assertEqual(decision(edit("tests/test_a.py", "    assert f(2) == 4", "    pass")), "ask")
        self.assertEqual(decision(edit("tests/test_a.py", "def test_x():", "@pytest.mark.skip" + NL + "def test_x():")),
                         "ask")
        self.assertEqual(decision(edit("src/app.test.ts", "it('adds', () => {", "it.skip('adds', () => {")), "ask")
        self.assertEqual(decision(edit("test_a.py", "assert f(2) == 4", "assert True")), "ask")
        out = edit("tests/test_a.py", "assert f(2) == 4" + NL + "assert f(3) == 9", "assert f(2) == 4")
        self.assertIn("removes 1 assertion", out["permissionDecisionReason"])

    def test_test_edits_that_are_fine(self):
        self.assertIsNone(edit("tests/test_a.py", "assert f(2) == 4", "assert f(2) == 5"))
        self.assertIsNone(edit("tests/test_a.py", "x = 1", "x = 1" + NL + "assert g(x)"))
        self.assertIsNone(edit("src/app.py", "assert x", "pass"))  # not a test file
        self.assertIsNone(edit("ml/train.py", "model.train(x)", "model.fit(x)"))  # .fit( is not fit(

    def test_write_shrinks_test_file(self):
        path = os.path.join(self.home, "tests", "test_b.py")
        os.makedirs(os.path.dirname(path))
        with open(path, "w", encoding="utf-8") as f:
            f.write("def test_a():" + NL + "    assert 1 + 1 == 2" + NL + "    assert 2 + 2 == 4" + NL)
        out = g.pre_event({"tool_name": "Write", "tool_input": {"file_path": path, "content": "def test_a():"
                                                                 + NL + "    pass" + NL}}, CFG)
        self.assertEqual(decision(out), "ask")

    def test_secrets(self):
        out = edit("src/cfg.py", "", "KEY = '" + FAKE_AWS + "'")
        self.assertEqual(decision(out), "ask")
        self.assertNotIn(FAKE_AWS, json.dumps(out))  # never echo the value
        self.assertIsNone(edit("src/cfg.py", "KEY = '" + FAKE_AWS + "'", "KEY = '" + FAKE_AWS + "'  # old"))
        self.assertEqual(decision(edit("src/db.py", "", 'password = "hunter2hunter2"')), "warn")
        self.assertIsNone(edit("src/db.py", "", 'password = "changeme123"'))
        self.assertIsNone(edit("src/db.py", "", "password = os.environ['DB_PASSWORD']"))

    def test_placeholders(self):
        out = edit("src/app.py", "def f():" + NL + "    return 1", "def f():" + NL + "    # TODO: real logic"
                   + NL + "    return 1")
        self.assertEqual(decision(out), "warn")
        self.assertIn("TODO", out["additionalContext"])
        self.assertEqual(decision(edit("src/a.ts", "", "throw new Error('Not implemented');")), "warn")
        self.assertEqual(decision(edit("src/a.py", "", "def g(x):" + NL + "    raise NotImplementedError")), "warn")
        self.assertEqual(decision(edit("src/a.js", "", "// ... rest of the code unchanged")), "warn")
        self.assertIsNone(edit("src/srv.py", "", "def log_message(self, *a):" + NL + "    pass"))  # a real no-op
        self.assertIsNone(edit("README.md", "", "TODO: write docs"))  # not code
        self.assertIsNone(edit("src/todo.py", "", "todos.append(todo)"))  # lowercase todo is a word
        self.assertIsNone(edit("src/a.py", "# TODO: x", "# TODO: x, y"))  # not new

    def test_strongest_finding_wins(self):
        out = edit("tests/test_a.py", "assert f(2) == 4", "pass  # TODO")
        self.assertEqual(decision(out), "ask")
        self.assertIn("TODO", out["permissionDecisionReason"])

    def test_config(self):
        cfg_dir = os.path.join(self.home, ".claude")
        os.makedirs(cfg_dir)
        with open(os.path.join(cfg_dir, "claudeg.json"), "w", encoding="utf-8") as f:
            json.dump({"tests": "off", "verify": "ask", "shell": 3, "secrets": "deny", "other": "x"}, f)
        cfg = g.load_config(self.home)
        self.assertEqual((cfg["tests"], cfg["verify"], cfg["shell"], cfg["secrets"]), ("off", "block", "deny", "deny"))
        self.assertIsNone(edit("tests/test_a.py", "assert x", "pass", cfg=cfg))
        with open(os.path.join(cfg_dir, "claudeg.json"), "w", encoding="utf-8") as f:
            f.write("{broken")
        self.assertEqual(g.load_config(self.home), g.DEFAULTS)


def tool_use(name, inp, uuid):
    return {"type": "assistant", "uuid": uuid, "message": {"content": [{"type": "tool_use", "id": "t" + uuid,
                                                                        "name": name, "input": inp}]}}


def tool_result(uuid):
    return {"type": "user", "uuid": uuid, "message": {"content": [{"type": "tool_result", "tool_use_id": "t",
                                                                   "content": "ok"}]}}


def prompt(text, uuid):
    return {"type": "user", "uuid": uuid, "message": {"role": "user", "content": text}}


class Verify(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp(prefix=".claudeg-test-", dir=os.path.expanduser("~"))

    def tearDown(self):
        shutil.rmtree(self.home, ignore_errors=True)

    def transcript(self, *entries):
        path = os.path.join(self.home, "t.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            for e in entries:
                f.write(json.dumps(e) + NL)
        return path

    def stop(self, text, entries, **extra):
        data = dict({"hook_event_name": "Stop", "last_assistant_message": text,
                     "transcript_path": self.transcript(*entries)}, **extra)
        return g.stop_event(data, CFG)

    EDIT = [prompt("fix the bug", "1"), tool_use("Edit", {"file_path": "src/app.py"}, "2"), tool_result("3")]

    def test_claim_without_run_blocks(self):
        out = self.stop("Fixed: the parser now handles empty input.", self.EDIT)
        self.assertEqual(out["decision"], "block")
        self.assertIn("app.py", out["reason"])
        self.assertEqual(self.stop("Hata düzeldi, artık boş girdiyi işliyor.", self.EDIT)["decision"], "block")

    def test_run_after_edit_passes(self):
        entries = self.EDIT + [tool_use("Bash", {"command": "pytest -q"}, "4"), tool_result("5")]
        self.assertIsNone(self.stop("Fixed, 12 passed.", entries))
        entries = self.EDIT + [tool_use("mcp__Claude_Browser__computer", {"action": "screenshot"}, "4")]
        self.assertIsNone(self.stop("Fixed, the button renders.", entries))

    def test_no_block_cases(self):
        self.assertIsNone(self.stop("Fixed it, but I could not run the tests: not verified.", self.EDIT))
        self.assertIsNone(self.stop("Here is the change.", self.EDIT))  # no claim
        self.assertIsNone(self.stop("Fixed.", self.EDIT, stop_hook_active=True))
        docs = [prompt("x", "1"), tool_use("Edit", {"file_path": "README.md"}, "2"), tool_result("3")]
        self.assertIsNone(self.stop("Fixed the typo.", docs))
        old_turn = self.EDIT + [prompt("thanks, anything else?", "4")]
        self.assertIsNone(self.stop("Fixed earlier; nothing else.", old_turn))  # edit was in an earlier turn
        self.assertIsNone(self.stop("Fixed.", self.EDIT[:0]))
        self.assertIsNone(g.stop_event({"last_assistant_message": "Fixed.", "transcript_path": "missing.jsonl"}, CFG))
        self.assertIsNone(g.stop_event({"last_assistant_message": "Fixed.",
                                        "transcript_path": self.transcript(*self.EDIT)}, dict(CFG, verify="off")))


class Main(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp(prefix=".claudeg-test-", dir=os.path.expanduser("~"))

    def tearDown(self):
        shutil.rmtree(self.home, ignore_errors=True)

    def run_hook(self, mode, stdin):
        env = dict(os.environ, CLAUDEG_HOME=self.home)
        return subprocess.run([sys.executable, os.path.join(SCRIPTS, "guard_hook.py"), mode], input=stdin,
                              capture_output=True, env=env, timeout=30)

    def test_pre_end_to_end(self):
        r = self.run_hook("pre", json.dumps({"tool_name": "Bash", "tool_input": {"command": "git reset --hard"}})
                          .encode("utf-8"))
        self.assertEqual(r.returncode, 0)
        self.assertEqual(json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"], "ask")
        r = self.run_hook("pre", json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}}).encode("utf-8"))
        self.assertEqual((r.returncode, r.stdout), (0, b""))

    def test_stop_reads_utf8(self):
        path = os.path.join(self.home, "t.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            for e in Verify.EDIT:
                f.write(json.dumps(e) + NL)
        data = {"hook_event_name": "Stop", "last_assistant_message": "Sorun çözüldü.", "transcript_path": path}
        r = self.run_hook("stop", json.dumps(data, ensure_ascii=False).encode("utf-8"))
        self.assertEqual(json.loads(r.stdout)["decision"], "block")

    def test_bad_input_never_breaks(self):
        r = self.run_hook("pre", b"{not json")
        self.assertEqual((r.returncode, r.stdout), (0, b""))
        self.assertIn(b"claudeg pre", r.stderr)


if __name__ == "__main__":
    unittest.main()
