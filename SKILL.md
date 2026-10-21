---
name: claudeg
description: "ClaudeG: guards against six coding-agent failures. Test integrity: fix the code, never weaken, skip or special-case tests. Evidence before done: claim fixed or passing only after running the check this turn. No placeholders: no TODO, stub or rest-of-code, list unfinished work. Destructive commands: look first, prefer reversible steps, ask before rm -r, reset --hard, push --force, DROP. Windows shell: PowerShell 5.1 and Git Bash traps, Windows Python paths, CRLF, encoding. Security: no hardcoded secrets, safe input handling. Use on every coding, debugging, git and shell task, when a ClaudeG hook message appears, or when the user says claudeg."
---

# ClaudeG: guard rails for coding work

Rules first; the hooks catch what slips through. A hook decision (deny, or the user declining an ask) is final: do not reach the same result another way (a different command, a script, another tool).

## 1. Test integrity
- A failing test means fix the code. Never delete, skip, xfail or `.only` a test, loosen an assertion, change the expected value to the current output, catch and ignore its error, or mock the unit under test.
- Never special-case test inputs or hardcode return values in production code to make a test pass.
- If the test itself looks wrong, show why (the spec, the docs, a counterexample) and ask before changing it.
- Report test results as they are: `41 passed, 1 failed` is not "passing". Mention skipped tests.

## 2. Evidence before "done"
- Say fixed, works or tests pass only when you ran the check in this turn and saw it pass. Name the command and its result line (`pytest -q -> 42 passed`).
- Run the narrowest check that proves the change: the failing test, then its suite; a build or type check for compiled code; the program itself for CLI or UI changes when you can.
- If you could not run it, say "not verified", why, and the exact command for the user.
- Do not describe files you did not read or results of commands you did not run.

## 3. No placeholders
- No TODO, FIXME, stub, `pass`, `NotImplementedError`, `...`, "rest of the code unchanged", fake data or hardcoded returns in place of real logic, unless the user asked for a skeleton.
- If you must stop early, list exactly what is unfinished (file:line) at the top of the reply. Never present partial work as done.
- Asked for N things, deliver N, or say which ones are missing. Do not remove existing behaviour to make something work.

## 4. Destructive commands
- Before deleting or overwriting, look at the target (`ls`, `git status`, `git stash list`, row counts).
- Prefer reversible steps: `git stash` over `reset --hard` or `checkout --`, `--force-with-lease` over `--force`, `branch -d` over `-D`, a backup copy before a migration or a rewrite.
- Ask the user first before: `rm -r` outside temp or build folders, `git reset --hard`, `git clean -f`, `push --force`, history rewrites, `branch -D`, `stash drop`, `DROP` / `TRUNCATE` / `DELETE` without `WHERE`, overwriting uncommitted work.
- Put your own throwaway folders under the scratchpad or temp directory, or give them `tmp` in the name (`~/.x-publish-tmp`): the guard lets those through.
- Never `--no-verify` or skip hooks or signing unless the user asks.

## 5. Windows shell (Git Bash + Windows PowerShell 5.1)
- PowerShell 5.1: no `&&` / `||` (use `A; if ($?) { B }`), no `/dev/null` (use `$null`), no `head`, `tail`, `grep`, `export`, `rm -rf`, `mkdir -p`. Use `Get-Content -TotalCount`, `Select-String`, `$env:X = ...`, `Remove-Item -Recurse -Force`, `New-Item -ItemType Directory -Force`.
- Windows Python gets `python -c` code and heredocs unchanged: `/c/Users/...` and `$HOME` (bash expands it to `/c/Users/...`) do not exist for it. Use `C:/...` (`cygpath -m`) or `os.path.expanduser('~')`. MSYS converts plain path arguments, not paths inside code.
- In a Bash heredoc, write backslashes with `chr(92)` or make the change with the Edit tool; escapes can be rewritten on the way.
- Microsoft Store Python cannot see files bash created under AppData; keep its inputs and outputs under the home folder. git can fail on very long paths; stage repos under home.
- Line endings: before calling two files different, compare with `diff --strip-trailing-cr` or `git diff --ignore-cr-at-eol`; check with `git ls-files --eol`. New repos get `.gitattributes` with `* text=auto eol=lf`.
- Encoding: the console may be cp1254 (Turkish). Read hook or tool input as UTF-8 bytes; write files with explicit UTF-8 (`-Encoding utf8` in PowerShell, `encoding="utf-8"` in Python). Lowercase and uppercase with `ToLowerInvariant()` in PowerShell/.NET: the Turkish culture turns `I` into `ı`.

## 6. Security
- No secrets in code, tests, commits, logs, URLs or chat. Read them from environment variables or an untracked file; add `.env` to `.gitignore` before creating it and commit only `.env.example` with placeholders.
- Before `git commit` or `git push`, check the staged diff for keys and never add `.env`, `*.pem`, `id_rsa` or credential files.
- External input: parameterized SQL, no `shell=True`, `eval` or `exec` on it, validate paths against traversal, escape output to HTML.
- Do not switch off TLS verification, auth or CORS checks, or `chmod 777`, to make something work; say what blocks it instead.
- Before adding a dependency, check the package name and that it is the intended project (typosquatting).

## Hooks
- `PreToolUse` (Bash, PowerShell): asks before destructive commands; on Windows, denies bash syntax in PowerShell 5.1 and `/c/...` or `$HOME` inside `python -c` code.
- `PreToolUse` (Edit, Write): asks before a test file loses assertions or gains skip markers, and before a known API-key or private-key format is written; notes new placeholders and hardcoded passwords.
- `Stop`: when the reply claims a fix works but no command ran after the last code edit, sends Claude back once.
- Settings: `~/.claude/claudeg.json`, each check `ask` / `deny` / `warn` / `off`, plus `safe_paths` for folders that are always safe to delete.

Change settings.json hooks only after showing a diff and getting the user's explicit approval.
