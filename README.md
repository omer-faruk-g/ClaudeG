# ClaudeG

ClaudeG is a [Claude Code](https://code.claude.com) skill that guards against six mistakes coding agents keep making, whatever the model:

1. **Weakening tests** to make them pass: deleting or skipping a test, loosening an assertion, special-casing test inputs.
2. **Saying "fixed" without checking**: claiming a change works when nothing was run after the edit.
3. **Leaving placeholders**: `TODO`, stubs, `NotImplementedError`, "rest of the code unchanged", presented as finished work.
4. **Destructive commands**: `rm -rf`, `git reset --hard`, `git push --force`, `DROP TABLE`, run without looking at the target.
5. **Windows shell traps**: bash syntax in Windows PowerShell 5.1, `/c/...` paths and `$HOME` inside `python -c` code, CRLF and encoding surprises.
6. **Security slips**: API keys written into code, unsafe input handling.

ClaudeG gives Claude rules for all six, plus two small hooks that ask, block or remind where the rules alone slip.

## What it does

| Part | What happens |
|---|---|
| Rules (`SKILL.md`) | Fix the code, not the test; show a reason and ask before changing a test. Claim success only with a command run this turn and its result line, or say "not verified". No placeholders; list unfinished work. Look before deleting, prefer reversible steps, ask before destructive commands. Windows PowerShell 5.1 / Git Bash / Windows Python / CRLF / encoding rules. No secrets in code or git; safe input handling; no switching off TLS or auth to make something work. A hook decision is final: never reach the same result another way. |
| Command guard (`PreToolUse`, `Bash`, `PowerShell`) | **Asks you** before `rm -r` / `Remove-Item -Recurse` outside temp and build folders, `git reset --hard`, `git clean -f`, `git push --force` / `--delete`, `git checkout --`, `git restore`, `git branch -D`, `git stash drop/clear`, history rewrites, `find -delete`, disk tools, and `DROP` / `TRUNCATE` / `DELETE` without `WHERE` in database clients. Quoted text, commit messages and heredoc bodies are not commands; `D=...; rm -rf $D` is judged by the value of `D`. On Windows it **blocks** commands that can only fail: `&&`, `||`, `/dev/null`, `head`, `export`, `rm -rf`, `mkdir -p` in PowerShell 5.1, and `/c/...` or `$HOME` inside `python -c` code or a Python heredoc. |
| Edit guard (`PreToolUse`, `Edit`, `Write`) | **Asks you** before a test file loses assertions, gains skip / xfail / `.only` markers or an always-true assertion, and before a value with a known API-key or private-key format is written to any file (the value is never echoed). **Notes** to Claude new placeholders in code files and hardcoded passwords or tokens. |
| Verify check (`Stop`) | When Claude's reply says it works ("fixed", "tests pass", "düzeldi", "doğrulandı", …) but no command ran after its last code edit, Claude is sent back once to run the check or to say plainly that it is not verified. |

The hooks print nothing when there is nothing to say, so they add no tokens then.

## Install

```bash
git clone https://github.com/omer-faruk-g/ClaudeG ~/.claude/skills/claudeg
```

Then add the hooks to `~/.claude/settings.json`. Merge them with any hooks you already have. If `python` is not on your PATH, use `python3` or the interpreter's full path; if `~` is not expanded on your system, write the script's full path.

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash|PowerShell|Edit|Write|MultiEdit", "hooks": [ { "type": "command", "command": "python ~/.claude/skills/claudeg/scripts/guard_hook.py pre", "timeout": 5 } ] }
    ],
    "Stop": [
      { "hooks": [ { "type": "command", "command": "python ~/.claude/skills/claudeg/scripts/guard_hook.py stop", "timeout": 5 } ] }
    ]
  }
}
```

Optional settings in `~/.claude/claudeg.json` (defaults shown). Each check takes `ask`, `deny`, `warn` (a note to Claude only) or `off`; `verify` takes `block` or `off`; set `powershell` to `7` if your PowerShell tool runs PowerShell 7, where `&&` works. `safe_paths` lists folders that are always fine to delete (matched as part of the path).

```json
{ "destructive": "ask", "tests": "ask", "secrets": "ask", "placeholders": "warn", "shell": "deny",
  "verify": "block", "powershell": "5.1", "safe_paths": [] }
```

Tests: `python ~/.claude/skills/claudeg/tests/test_claudeg.py` (26 tests, stdlib only).

## Example (one user's transcripts, 11 days)

Every past tool call was replayed through the hook:

| Calls | Result |
|---|---|
| 3,264 Bash | 113 asks: mostly `rm -rf` of the agent's own scratch folders in the home directory and of experiment-output folders in a project; 1 block, the `/c/...` path in `python -c` that had failed in that session |
| 476 PowerShell | 16 asks, all `Remove-Item -Recurse` of project folders; 0 blocks |
| 2,051 Edit, 630 Write | 8 asks for test files that lost assertions or gained skip markers (here all deliberate rewrites, which you would approve); 3 notes (placeholders, hardcoded password). A Write is compared with the file as it is today, so these counts are approximate |
| 1,171 turns (Stop) | 3 blocks, each a "fixed" / "doğrulandı" with no command after the last code edit |

Run the replay on your own transcripts and your numbers will differ. Naming throwaway folders `…-tmp` or putting them under the temp directory, and listing regenerated output folders in `safe_paths`, removes most of the asks.

## Limits

- It is a seatbelt, not a sandbox. Commands hidden in scripts, `eval`, variables set in an earlier command, or a heredoc piped into a shell are not seen.
- The test check counts assertions and skip markers. It cannot tell a legitimate refactor from weakening, so it asks; changing an expected value to match buggy output is not detected.
- Placeholder and hardcoded-password checks are notes, not blocks, and match patterns, not meaning.
- The verify check knows English and Turkish claim phrases only. Any command after the last edit counts as a check, even `ls`. It blocks at most once per stop.
- Windows checks assume Windows PowerShell 5.1 for the PowerShell tool and a native Windows Python.
- On Windows each hook call adds about 0.25 s, mostly Python start-up.
- Nothing is changed in your settings without you: the hooks are added by hand.

## Background

- [Hooks reference](https://code.claude.com/docs/en/hooks): `PreToolUse` can return `permissionDecision` `ask` (the reason is shown to you) or `deny` (the reason is shown to Claude), or add `additionalContext`; `Stop` receives `last_assistant_message` and `stop_hook_active`, and `decision: "block"` with a `reason` sends Claude back to work.

## Türkçe özet

ClaudeG, kodlama ajanlarının modelden bağımsız tekrarladığı altı hataya karşı koruma sağlar:

- **Test hilesi:** Test geçmiyorsa kod düzeltilir. Test silinmez, atlanmaz, assert gevşetilmez. Bir test dosyası assert kaybederse ya da skip işareti alırsa hook sana sorar.
- **Doğrulamadan "bitti":** "Düzeldi" ya da "testler geçti" ancak bu turda çalıştırılan bir komutla söylenir. Son kod düzenlemesinden sonra hiç komut çalışmadıysa Claude bir kez geri gönderilir.
- **Yarım kod:** TODO, boş fonksiyon, "kodun geri kalanı aynı" yazılmaz. Bitmeyen iş açıkça listelenir.
- **Geri alınamaz komutlar:** `rm -rf`, `git reset --hard`, `push --force`, `DROP TABLE` öncesi hook sana sorar. Geçici ve build klasörleri serbest; her zaman silinebilecek klasörleri `safe_paths` ile ekleyebilirsin.
- **Windows tuzakları:** PowerShell 5.1'de `&&`, `/dev/null`, `head`, `rm -rf`; `python -c` kodu içinde `/c/...` ya da `$HOME` kullanmak. Bunlar zaten hata vereceği için engellenir. Kurallar CRLF, cp1254 kodlaması ve Türkçe `I/ı` sorununu da kapsar.
- **Güvenlik:** Koda API anahtarı yazılırken sorar ve anahtarı hiçbir mesajda göstermez.

Kurulum için yukarıdaki `git clone` komutunu çalıştır ve hook'ları `~/.claude/settings.json`'a ekle.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
