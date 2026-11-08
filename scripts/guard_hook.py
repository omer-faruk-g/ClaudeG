#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""ClaudeG hook: guards the coding-agent mistakes that rules alone do not stop.

  guard_hook.py pre    PreToolUse (Bash|PowerShell|Edit|Write|MultiEdit)
                       Bash/PowerShell: asks before destructive commands (rm -r, git reset --hard,
                                        git push --force, DROP TABLE, ...); on Windows, blocks shell
                                        mistakes that can only fail (bash syntax in PowerShell 5.1,
                                        /c/... paths or $HOME inside `python -c` code)
                       Edit/Write:      asks before a test file loses assertions or gains skip markers,
                                        and before a known API-key or private-key format is written;
                                        notes new placeholders (TODO, NotImplementedError, "rest of
                                        the code") in code files
  guard_hook.py stop   Stop: when the reply says a fix works but no command ran after the last code
                       edit, sends Claude back once to verify it or to say it is not verified

Config (optional): ~/.claude/claudeg.json, defaults: {"destructive": "ask", "tests": "ask",
"secrets": "ask", "placeholders": "warn", "shell": "deny", "verify": "block", "powershell": "5.1"}.
Checks take "ask", "deny", "warn" or "off"; verify takes "block" or "off"; powershell "5.1" or "7".
A hook must never break your session: on any error it writes to stderr and exits 0 silently.
"""
import argparse
import json
import os
import posixpath
import re
import shlex
import shutil
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

B = chr(92)  # backslash, kept out of literals so the file reads the same everywhere

DEFAULTS = {"destructive": "ask", "tests": "ask", "secrets": "ask", "placeholders": "warn",
            "shell": "deny", "verify": "block", "powershell": "5.1", "safe_paths": []}
CHOICES = {"verify": {"block", "off"}, "powershell": {"5.1", "7"}}
CHECK_MODES = {"ask", "deny", "warn", "off"}
RANK = {"warn": 1, "ask": 2, "deny": 3}
EDIT_TOOLS = {"Edit", "Write", "MultiEdit"}
CODE_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".kt", ".kts", ".go", ".rs", ".c", ".h",
            ".cc", ".cpp", ".hpp", ".cs", ".rb", ".php", ".swift", ".scala", ".sh", ".bash", ".ps1", ".psm1", ".lua",
            ".dart", ".vue", ".svelte", ".sql", ".gradle", ".groovy", ".m", ".mm", ".r", ".jl", ".ex", ".exs", ".zig"}
BIG_FILE = 4 * 1024 * 1024

# --- destructive commands -------------------------------------------------------------------------
WRAPPERS = {"sudo", "doas", "env", "nohup", "time", "nice", "command", "exec", "xargs"}
SAFE_DIRS = {"node_modules", "dist", "build", "out", "target", "obj", "__pycache__", ".pytest_cache", ".mypy_cache",
             ".ruff_cache", ".next", ".nuxt", ".cache", ".parcel-cache", ".turbo", "coverage", "htmlcov", ".tox"}
TEMP_PATH = re.compile(r"(?<![a-z])(tmp|temp|scratchpad)(?![a-z])|mktemp|^\$\{?(tmpdir|tmp|temp)\b|^\$env:(tmp|temp)\b",
                       re.I)  # a path part named tmp/temp/scratchpad, or ending -tmp, _temp, ...
SAFE_FILES = {"*.pyc", "*.pyo", ".DS_Store", "Thumbs.db"}
PS_SWITCHES = {"-recurse", "-force", "-whatif", "-confirm", "-verbose"}  # flags that take no value
PS_REMOVE = {"remove-item", "ri", "rm", "rmdir", "rd", "del", "erase"}
DISK_TOOLS = {"format-volume", "clear-disk", "initialize-disk", "diskpart"}
DB_CLIENTS = {"psql", "mysql", "mariadb", "sqlite3", "sqlcmd", "mongosh", "mongo", "clickhouse-client", "duckdb"}
SQL_DESTRUCTIVE = re.compile(r"\b(DROP\s+(TABLE|DATABASE|SCHEMA|VIEW|INDEX)|TRUNCATE(\s+TABLE)?\s+\w"
                             r"|DELETE\s+FROM\s+[\w.\"`\[\]]+\s*(;|$))|dropDatabase\(|deleteMany\(\s*\{\s*\}\s*\)", re.I)
HEREDOC = re.compile(r"<<-?[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1[^\n]*\n(.*?)(?:\n[ \t]*\2[ \t]*(?=\n|$)|\Z)", re.S)

# --- Windows shell mistakes -----------------------------------------------------------------------
BASH_ONLY = {"head": "Select-Object -First N, or Get-Content -TotalCount N", "tail": "Get-Content -Tail N",
             "grep": "Select-String, or the Grep tool", "wc": "Measure-Object -Line", "which": "(Get-Command x).Source",
             "touch": "New-Item -ItemType File", "export": "$env:NAME = 'value'", "[": "if (Test-Path x) { }",
             "[[": "if (Test-Path x) { }", "sed": "-replace, or the Edit tool", "awk": "ForEach-Object",
             "cut": "-split", "xargs": "ForEach-Object"}
BASH_FLAGS = {("rm", "-rf"): "Remove-Item -Recurse -Force", ("rm", "-fr"): "Remove-Item -Recurse -Force",
              ("ls", "-la"): "Get-ChildItem -Force", ("ls", "-al"): "Get-ChildItem -Force",
              ("ls", "-lah"): "Get-ChildItem -Force",
              ("mkdir", "-p"): "New-Item -ItemType Directory -Force", ("cp", "-rf"): "Copy-Item -Recurse -Force"}
PYTHON = re.compile(r"^(python[0-9.]*|pythonw|py)$")
POSIX_IN_CODE = re.compile(r"(?<=['\"])/[a-zA-Z]/[\w.$~ -]|\$\{?HOME\b")

# --- tests, secrets, placeholders -----------------------------------------------------------------
TEST_FILE = re.compile(r"(^|/)(tests?|__tests__|specs?)/|(^|/)test_[^/]*\.py$|_test\.(py|go)$"
                       r"|\.(spec|test)\.[cm]?[jt]sx?$|(Test|Tests|IT)\.(java|kt|cs)$")
ASSERT = re.compile(r"\bassert\w*|@Test\b|\bexpect\(|\bverify\(|\.should\b|\bt\.(Error|Fatal|Fail)\w*\(", re.I)
SKIP = re.compile(r"@Disabled\b|@Ignore\b|\[Ignore\]|\[(Fact|Theory)\(\s*Skip\s*=|@pytest\.mark\.(skip|xfail)"
                  r"|\bpytest\.(skip|xfail)\(|@unittest\.(skip|expectedFailure)|\.skipTest\("
                  r"|(?<![.\w])(it|test|describe|context)\.(skip|only|todo)\b|(?<![.\w])x(it|test|describe)\("
                  r"|(?<![.\w])f(it|describe)\(|\bt\.Skip(Now|f)?\(|assumeTrue\(\s*false")
TRIVIAL = re.compile(r"\bassert\s+True\b|assertTrue\(\s*True\s*\)|expect\(\s*true\s*\)\.toBe\(\s*true\s*\)"
                     r"|\bassert\s+(\d+)\s*==\s*\1\b")
SECRET = re.compile(r"AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
                    r"|sk-ant-[A-Za-z0-9_-]{10,}|sk-proj-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20,}"
                    r"|(sk|rk)_live_[A-Za-z0-9]{10,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}"
                    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----")
GENERIC_SECRET = re.compile(r"(?<![A-Za-z])(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token"
                            r"|token)\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]", re.I)
FAKE_VALUE = re.compile(r"^(\$|\{\{|<|%)|example|change.?me|your|dummy|fake|test|sample|placeholder|xxx|redacted|\.\.\.",
                        re.I)
PLACEHOLDER = re.compile(r"(?-i:\b(TODO|FIXME)\b)|\bNotImplemented(Error|Exception)\b|\bunimplemented!\(|\btodo!\("
                         r"|\bnot (yet )?implemented\b|(\.\.\.|…)\s*(rest|remaining|existing|other|same|unchanged|previous)\b"
                         r"|\b(rest|remainder) of (the )?(code|file|implementation|function|method|logic|class)\b"
                         r"|\b(existing|unchanged) (code|logic|implementation)\b"
                         r"|\b(your|actual|real) (code|logic|implementation) (goes )?here\b|\bimplement (this|me|later)\b",
                         re.I)

# --- verification claims (Stop) -------------------------------------------------------------------
CLAIM = re.compile(r"\b(fixed|works now|now works|is working|working now|all tests pass\w*|tests? (now )?pass\w*"
                   r"|passes now|verified|resolved|it works|should work now)\b|düzeldi|düzelttim|çözüldü|çözdüm"
                   r"|artık çalışıyor|sorunsuz çalışıyor|testler(in hepsi)? geçti|test(ler)? geçiyor|hepsi geçti"
                   r"|doğrulandı|doğruladım|hallettim|halloldu", re.I)
DISCLAIM = re.compile(r"\b(not (been )?(verified|tested|run)|unverified|untested|didn'?t (run|test|verify)"
                      r"|did not (run|test|verify)|could(n'?t| not) (run|test|verify)|can'?t (run|test|verify)"
                      r"|cannot (run|test|verify))\b|doğrulamadım|doğrulanmadı|doğrulayamadım|test etmedim|test edemedim"
                      r"|çalıştırmadım|çalıştıramadım|denemedim|deneyemedim", re.I)

DESTRUCTIVE_MSG = ("ClaudeG: destructive command: {hits}. This cannot be undone. Prefer a reversible step (git stash, "
                   "a backup copy, --force-with-lease) and run it only with the user's OK. A folder that is always safe "
                   "to delete can go into safe_paths in ~/.claude/claudeg.json.")
TESTS_MSG = ("ClaudeG: this change to {name} {what}. Making a test pass by weakening it hides the bug: fix the code, "
             "and change a test only when the user asked for it or agreed that the test is wrong.")
SECRET_MSG = ("ClaudeG: this change writes {n} value(s) to {name} that look like a real API key or private key. "
              "Keep secrets in environment variables or an untracked file, never in code or git.")
GENERIC_MSG = ("ClaudeG: {name} gets a hardcoded password or token ({keys}). Read it from an environment variable "
               "or an untracked config file instead.")
PLACEHOLDER_MSG = ("ClaudeG: this edit adds placeholder code to {name} ({found}). Write the real code, or tell the "
                   "user exactly what is unfinished (file:line); never report it as done.")
VERIFY_MSG = ("ClaudeG: your reply says it works (\"{claim}\"), but no command ran after your last code edit "
              "({name}). Run the check that proves it (the failing test, the build or the program) and report its "
              "result line. If you cannot run it, tell the user plainly that it is not verified and give the command.")
PYTHON_MSG = ("ClaudeG: Windows Python gets `python -c` code and heredocs unchanged, so /c/... paths and $HOME (which "
              "bash expands to /c/Users/...) do not exist for it. Use C:/... paths (cygpath -m) or "
              "os.path.expanduser('~') inside the code.")


def home_dir(home=None):
    return home or os.environ.get("CLAUDEG_HOME") or os.path.expanduser("~")


def long_path(path):
    """Windows MAX_PATH workaround: Claude Code project dirs can exceed 260 chars."""
    ap = os.path.abspath(path)
    if os.name != "nt" or len(ap) < 250 or ap.startswith(B + B):
        return ap
    return B + B + "?" + B + ap


def load_config(home=None):
    cfg = dict(DEFAULTS)
    try:
        with open(os.path.join(home_dir(home), ".claude", "claudeg.json"), encoding="utf-8") as f:
            user = json.load(f)
    except (OSError, ValueError):
        return cfg
    if isinstance(user, dict):
        for k, v in user.items():
            if k == "safe_paths" and isinstance(v, list):
                cfg[k] = [x for x in v if isinstance(x, str) and x.strip()]
            elif k in DEFAULTS and isinstance(v, str) and v in CHOICES.get(k, CHECK_MODES):
                cfg[k] = v
    return cfg


# --- shell parsing ---------------------------------------------------------------------------------
def strip_heredocs(cmd):
    """(command without heredoc bodies, [bodies])."""
    bodies = [m.group(3) for m in HEREDOC.finditer(cmd)]
    return HEREDOC.sub(lambda m: m.group(0)[:m.start(3) - m.start(0)], cmd), bodies


def split_segments(cmd, ps=False):
    """(simple commands split at ; & | && || and newlines outside quotes, operators && / || seen there)."""
    esc = "`" if ps else B
    segs, cur, ops, q, i = [], [], set(), None, 0
    while i < len(cmd):
        c = cmd[i]
        if c == esc and q != "'" and i + 1 < len(cmd):
            cur.append(cmd[i:i + 2])
            i += 2
            continue
        if q:
            q = None if c == q else q
            cur.append(c)
        elif c in "'\"":
            q = c
            cur.append(c)
        elif c in ";&|\n":
            if c in "&|" and cmd[i + 1:i + 2] == c:
                ops.add(c * 2)
                i += 1
            segs.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    segs.append("".join(cur))
    return [s.strip() for s in segs if s.strip()], ops


def tokens(seg, ps=False):
    try:
        toks = shlex.split(seg, posix=not ps)
    except ValueError:
        toks = seg.split()
    if ps:
        toks = [t[1:-1] if len(t) > 1 and t[0] == t[-1] and t[0] in "'\"" else t for t in toks]
    i = 0
    while i < len(toks):  # skip VAR=val prefixes and wrappers such as sudo or xargs
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[i]):
            i += 1
        elif cmd_name(toks[i]) in WRAPPERS:
            i += 1
            while i < len(toks) and toks[i].startswith("-"):
                i += 1
        else:
            break
    return toks[i:]


def cmd_name(tok):
    name = re.split(r"[/" + B + B + "]", tok)[-1].lower()
    return name[:-4] if name.endswith(".exe") else name


def expand(t, env):
    return re.sub(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", lambda m: env.get(m.group(1), m.group(0)), t)


def safe_target(t, env=None, extra=()):
    """A temp or build-output path, or one listed in safe_paths: deleting it loses nothing. $VARS set earlier in
    the same line are resolved, and a relative path is judged together with the directory it runs in. A relative
    path that runs through a build or cache folder (build/libs, versions/*/build/generated) is safe even with a glob,
    since every match stays inside that folder; `..` is resolved first, so build/../src is not."""
    env = env or {}
    t = expand(t, env)
    absolute = re.match(r"^([/~$" + B + B + "]|[A-Za-z]:)", t)
    parts = posixpath.normpath(t.replace(B, "/")).lower().split("/")
    if absolute:
        parts = parts[-1:]  # an absolute path counts only by its last folder, as before
    if any(p in SAFE_DIRS or p.endswith(".egg-info") or p.startswith(".venv-") for p in parts):
        return True
    if not absolute:
        t = env.get("PWD", "") + "/" + t
    t = t.rstrip("/" + B)
    if not t or "*" in t or "?" in t:
        return False
    norm = t.replace(B, "/").lower()
    return bool(TEMP_PATH.search(t)) or any(p.replace(B, "/").lower().rstrip("/") in norm for p in extra)


def is_recurse(arg):
    a = arg.lower()
    return len(a) > 1 and a[0] == "-" and "recurse".startswith(a[1:])


def git_destructive(args):
    i = 0
    while i < len(args) and args[i].startswith("-"):  # git -C dir / -c k=v take a value
        i += 2 if args[i] in ("-C", "-c", "--git-dir", "--work-tree") else 1
    if i >= len(args):
        return None
    sub, rest = args[i].lower(), args[i + 1:]
    flags = [a for a in rest if a.startswith("-")]
    short = "".join(a[1:] for a in flags if not a.startswith("--"))
    plain = [a for a in rest if not a.startswith("-")]
    if sub == "reset" and "--hard" in rest:
        return "git reset --hard (drops uncommitted changes)"
    if sub == "clean" and ("f" in short or "--force" in flags) and "n" not in short and "--dry-run" not in flags:
        return "git clean -f (deletes untracked files)"
    if sub == "push":
        if "--force" in flags or "f" in short or "--mirror" in flags or any(a.startswith("+") for a in plain):
            return "git push --force (can overwrite commits on the remote; --force-with-lease is safer)"
        if "--delete" in flags or "d" in short or any(a.startswith(":") for a in plain):
            return "git push --delete (deletes a remote branch)"
    if sub == "checkout" and ("--" in rest or "." in plain or "-f" in flags or "--force" in flags):
        return "git checkout -- / -f (drops uncommitted changes)"
    if sub == "restore" and not (({"--staged", "-S"} & set(flags)) and not ({"--worktree", "-W"} & set(flags))):
        return "git restore (drops uncommitted changes)"
    if sub == "switch" and ({"--discard-changes", "--force", "-f"} & set(flags)):
        return "git switch --discard-changes (drops uncommitted changes)"
    if sub == "branch" and ("D" in short or ({"--delete", "-d"} & set(flags) and {"--force", "-f"} & set(flags))):
        return "git branch -D (deletes a branch even if it is not merged)"
    if sub == "stash" and plain[:1] and plain[0] in ("drop", "clear"):
        return f"git stash {plain[0]} (deletes stashed work)"
    if sub in ("filter-branch", "filter-repo"):
        return f"git {sub} (rewrites history)"
    return None


def destructive(toks, ps, depth=0, env=None, extra=()):
    """A short description of what this simple command destroys, or None."""
    if not toks:
        return None
    name, args, skip = cmd_name(toks[0]), [], False
    for a in toks[1:]:  # drop redirections: 2>/dev/null, > out.txt
        if skip:
            skip = False
        elif re.fullmatch(r"(\d*|&)>>?|<", a):
            skip = True
        elif not re.match(r"^((\d*|&)>|<)", a):
            args.append(a)
    flags = [a for a in args if a.startswith("-")]
    lowered = [a.lower() for a in args]
    targets = [a for i, a in enumerate(args) if not a.startswith("-") and a.lower() not in ("/s", "/q")
               and not (ps and i and lowered[i - 1].startswith("-") and lowered[i - 1] not in PS_SWITCHES
                        and lowered[i - 1] not in ("-path", "-literalpath"))]  # skip values such as -ErrorAction X
    if depth < 3 and name in ("bash", "sh", "zsh") and "-c" in args[:-1]:
        return command_hits(args[args.index("-c") + 1], False, depth + 1, extra=extra)
    if depth < 3 and name in ("powershell", "pwsh") and set(lowered[:-1]) & {"-command", "-c"}:
        k = next(i for i, a in enumerate(lowered) if a in ("-command", "-c"))
        return command_hits(" ".join(args[k + 1:]), True, depth + 1, extra=extra)
    if depth < 3 and name == "cmd" and "/c" in lowered[:-1]:
        return command_hits(" ".join(args[lowered.index("/c") + 1:]), True, depth + 1, extra=extra)
    recursive = None
    if name == "rm" and not ps:
        recursive = "r" in "".join(a[1:] for a in flags if not a.startswith("--")).lower() or "--recursive" in flags
    elif name in PS_REMOVE and (ps or name in ("rd", "rmdir", "del", "erase")):
        recursive = (any(is_recurse(a) for a in flags) or "/s" in lowered) and "-whatif" not in lowered
    if recursive:
        if targets and all(safe_target(t, env, extra) for t in targets):
            return None
        return f"{toks[0]} -r {' '.join(targets) or '(no target)'} (deletes for good, no recycle bin)"
    if name == "git":
        return git_destructive(args)
    if name == "find" and ("-delete" in args or any(a in ("-exec", "-execdir") and cmd_name(b) == "rm"
                                                     for a, b in zip(args, args[1:]))):
        names = [b for a, b in zip(args, args[1:]) if a in ("-name", "-iname")]
        if names and all(n in SAFE_DIRS or n in SAFE_FILES for n in names):
            return None
        return "find -delete (deletes every match)"
    if name.startswith("mkfs") or name in DISK_TOOLS or (name == "dd" and any(a.startswith("of=/dev/") for a in args)):
        return f"{name} (overwrites a disk)"
    if name in DB_CLIENTS and SQL_DESTRUCTIVE.search(" ".join(args)):
        return "DROP / TRUNCATE / DELETE without WHERE (deletes data)"
    return None


def command_hits(cmd, ps, depth=0, cwd="", extra=()):
    body, _ = strip_heredocs(cmd) if not ps else (cmd, [])
    segs, _ = split_segments(body, ps)
    env, hits = {"PWD": cwd or ""}, []
    for s in segs:
        toks = tokens(s, ps)
        if not ps:  # remember D=... so a later `rm -rf $D` can be judged by its value
            for m in re.finditer(r"(?:^|\s)([A-Za-z_][A-Za-z0-9_]*)=(\S*)", s):
                env[m.group(1)] = expand(m.group(2).strip("'\""), env)
        if len(toks) == 2 and cmd_name(toks[0]) in ("cd", "set-location", "pushd"):
            env["PWD"] = expand(toks[1], env)
        hits.append(destructive(toks, ps, depth, env, extra))
    return "; ".join(dict.fromkeys(h for h in hits if h)) or None


def which(name):
    return shutil.which(name)


def shell_hits(cmd, ps, cfg):
    """Windows shell mistakes that can only fail, as messages."""
    msgs = []
    if ps:
        segs, ops = split_segments(cmd, True)
        if ops and cfg["powershell"] == "5.1":
            msgs.append("ClaudeG: Windows PowerShell 5.1 has no && or || (parser error). Use `A; if ($?) { B }`, "
                        "or run the line in the Bash tool.")
        if any("/dev/null" in re.sub(r"'[^']*'|\"[^\"]*\"", "''", s) for s in segs):
            msgs.append("ClaudeG: PowerShell has no /dev/null; use $null (2>$null, | Out-Null).")
        for s in segs:
            toks = tokens(s, True)
            if not toks:
                continue
            name = cmd_name(toks[0])
            if name in BASH_ONLY and (name in ("export", "[", "[[") or not which(name)):
                msgs.append(f"ClaudeG: `{name}` is bash, and this is PowerShell: use {BASH_ONLY[name]}.")
            for a in toks[1:]:
                fix = BASH_FLAGS.get((name, a.lower()))
                if fix:
                    msgs.append(f"ClaudeG: `{name} {a}` is bash; in PowerShell use {fix}.")
        return list(dict.fromkeys(msgs))
    body, bodies = strip_heredocs(cmd)
    segs, _ = split_segments(body)
    for s in segs:
        toks = tokens(s)
        if not toks or not PYTHON.match(cmd_name(toks[0])):
            continue
        code = [toks[toks.index("-c") + 1]] if "-c" in toks[1:-1] else []
        if "<<" in s:
            code += bodies
        if any(POSIX_IN_CODE.search(c) for c in code):
            return [PYTHON_MSG]
    return msgs


# --- file edits ------------------------------------------------------------------------------------
def read_file(path):
    try:
        if os.path.getsize(long_path(path)) > BIG_FILE:
            return ""
        with open(long_path(path), encoding="utf-8", errors="replace") as f:
            return f.read()
    except (OSError, TypeError, ValueError):
        return ""  # a new file


def edit_texts(tool, ti):
    """(path, old text, new text) of an Edit/Write/MultiEdit call; for Write, old is the file on disk."""
    path = ti.get("file_path") or ""
    if tool == "Write":
        return path, read_file(path), ti.get("content") or ""
    if tool == "MultiEdit":
        edits = [e for e in ti.get("edits") or [] if isinstance(e, dict)]
        return path, "\n".join(e.get("old_string") or "" for e in edits), \
            "\n".join(e.get("new_string") or "" for e in edits)
    return path, ti.get("old_string") or "", ti.get("new_string") or ""


def added(regex, old, new):
    return len(regex.findall(new)) - len(regex.findall(old))


def test_change(old, new):
    what = []
    if added(SKIP, old, new) > 0:
        what.append(f"adds {added(SKIP, old, new)} skip/only marker(s)")
    if added(ASSERT, old, new) < 0:
        what.append(f"removes {-added(ASSERT, old, new)} assertion(s)")
    if added(TRIVIAL, old, new) > 0:
        what.append("adds an always-true assertion")
    return " and ".join(what) or None


def generic_secrets(text):
    return {m.group(1).lower() for m in GENERIC_SECRET.finditer(text) if not FAKE_VALUE.search(m.group(2))}


def edit_findings(tool, ti, cfg):
    path, old, new = edit_texts(tool, ti)
    norm = path.replace(B, "/")
    name = os.path.basename(norm) or "the file"
    found = []
    if cfg["tests"] != "off" and TEST_FILE.search(norm):
        what = test_change(old, new)
        if what:
            found.append((cfg["tests"], TESTS_MSG.format(name=name, what=what)))
    if cfg["secrets"] != "off":
        n = len(set(m.group(0) for m in SECRET.finditer(new)) - set(m.group(0) for m in SECRET.finditer(old)))
        if n:
            found.append((cfg["secrets"], SECRET_MSG.format(n=n, name=name)))
        keys = generic_secrets(new) - generic_secrets(old)
        if keys:
            found.append(("warn", GENERIC_MSG.format(name=name, keys=", ".join(sorted(keys)))))
    if cfg["placeholders"] != "off" and os.path.splitext(norm)[1].lower() in CODE_EXT \
            and added(PLACEHOLDER, old, new) > 0:
        olds = {m.group(0).strip() for m in PLACEHOLDER.finditer(old)}
        news = list(dict.fromkeys(m.group(0).strip().split("\n")[0][:30] for m in PLACEHOLDER.finditer(new)
                                  if m.group(0).strip() not in olds))
        found.append((cfg["placeholders"], PLACEHOLDER_MSG.format(name=name, found=", ".join(news[:3]))))
    return found


# --- events ----------------------------------------------------------------------------------------
def decide(found):
    """Strongest finding wins: deny > ask > warn. Returns PreToolUse hookSpecificOutput or None."""
    if not found:
        return None
    top = max(found, key=lambda f: RANK[f[0]])[0]
    text = " ".join(dict.fromkeys(m for _, m in found))
    if top == "warn":
        return {"hookEventName": "PreToolUse", "additionalContext": text}
    return {"hookEventName": "PreToolUse", "permissionDecision": top, "permissionDecisionReason": text}


def pre_event(data, cfg, windows=None):
    tool, ti = data.get("tool_name"), data.get("tool_input") or {}
    found = []
    if tool in ("Bash", "PowerShell"):
        ps, cmd = tool == "PowerShell", ti.get("command") or ""
        if cfg["destructive"] != "off":
            hits = command_hits(cmd, ps, cwd=data.get("cwd") or "", extra=cfg["safe_paths"])
            if hits:
                found.append((cfg["destructive"], DESTRUCTIVE_MSG.format(hits=hits)))
        if cfg["shell"] != "off" and (os.name == "nt" if windows is None else windows):
            found += [(cfg["shell"], m) for m in shell_hits(cmd, ps, cfg)]
    elif tool in EDIT_TOOLS:
        found = edit_findings(tool, ti, cfg)
    return decide(found)


def is_prompt(d):
    """A message the user typed (not a tool result, injected text or compaction summary)."""
    if d.get("type") != "user" or d.get("isMeta") or d.get("isCompactSummary"):
        return False
    c = (d.get("message") or {}).get("content")
    if isinstance(c, list):
        return not any(isinstance(b, dict) and b.get("type") == "tool_result" for b in c)
    return isinstance(c, str)


def turn_tools(transcript_path, max_bytes=2 * 1024 * 1024):
    """[(tool name, input)] of the current turn, oldest first, read from the transcript's end."""
    try:
        f = open(long_path(transcript_path), "rb")
    except (OSError, TypeError, ValueError):
        return []
    with f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(max(0, size - max_bytes))
        raw = f.read().split(b"\n")
    if size > max_bytes:
        raw = raw[1:]  # first line may be cut
    calls = []
    for line in reversed(raw):
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if not isinstance(d, dict) or d.get("isSidechain"):
            continue
        if is_prompt(d):
            break
        if d.get("type") == "assistant":
            for b in reversed((d.get("message") or {}).get("content") or []):
                if isinstance(b, dict) and b.get("type") == "tool_use":
                    calls.append((b.get("name"), b.get("input") or {}))
    return calls[::-1]


def stop_event(data, cfg):
    """Stop output dict, or None to let Claude stop."""
    if cfg["verify"] == "off" or data.get("stop_hook_active"):
        return None
    text = data.get("last_assistant_message") or ""
    claim = CLAIM.search(text)
    if not claim or DISCLAIM.search(text):
        return None
    calls = turn_tools(data.get("transcript_path"))
    edits = [i for i, (n, ti) in enumerate(calls) if n in EDIT_TOOLS
             and os.path.splitext(str(ti.get("file_path") or ""))[1].lower() in CODE_EXT]
    if not edits:
        return None
    later = calls[edits[-1] + 1:]
    if any(n in ("Bash", "PowerShell") or str(n).startswith("mcp__") for n, _ in later):
        return None
    name = os.path.basename(str(calls[edits[-1]][1].get("file_path")).replace(B, "/"))
    return {"decision": "block", "reason": VERIFY_MSG.format(claim=claim.group(0), name=name)}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("mode", choices=["pre", "stop"])
    a = p.parse_args(argv)
    try:
        data = json.loads(sys.stdin.buffer.read().decode("utf-8", errors="replace") or "{}")
        cfg = load_config()
        if a.mode == "pre":
            out = pre_event(data, cfg)
            out = out and {"hookSpecificOutput": out}
        else:
            out = stop_event(data, cfg)
        if out:
            print(json.dumps(out, ensure_ascii=False))
    except Exception as e:  # a guard must never break the session; report and step aside
        print(f"claudeg {a.mode}: {type(e).__name__}: {e}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
