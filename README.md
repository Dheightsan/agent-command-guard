# agent-command-guard

A small hook that stops a coding agent from running a few commands you can't take back. It's one Python file with no dependencies.

I run Claude Code on my own Windows laptop for many hours a day, in Git Bash and PowerShell. This is the guard I use there. I wrote it with Claude Code itself. Most rules came after an agent did something bad on my machine, the rest after I found a hole while testing.

## What it blocks

- Deleting a drive root, the home folder, key folders inside home (`.ssh`, `.claude`, `.gradle`, `Documents`...) or a path you list in the config. Covers Bash, PowerShell and cmd forms, with `sudo`, `env`, `nohup`, `cmd /c`, `powershell -Command`, `/bin/rm` and `\rm` in front.
- `rm -rf $X` when the same command set `X` to one of those paths or to an almost empty string.
- Deleting the `.git` folder of the current repo or of a protected path.
- A download that goes straight into a shell or interpreter: `curl | bash`, `bash <(curl ...)`, `iwr | iex`, `iex (New-Object Net.WebClient).DownloadString(...)`, `curl | python`.
- Reading or copying credential files (`.ssh/id_*`, `.git-credentials`, `.npmrc`, `.netrc`, `gradle.properties`, `gh` tokens...), from the shell, from `python -c`/`node -e` or with the Read tool.
- `find /` on a whole drive without `-maxdepth`. On Windows a stray one left millions of open handles and ate GBs of kernel memory twice.
- `git reset --hard` and `git push --force`. `--force-with-lease` still works.
- The same rules inside `bash -c '...'` and `python -c '...'`, up to three levels deep.
- The same deletes when they're hidden, like `timeout 5 rm -rf ~`, `su -c '...'`, `"r""m" -rf ~`, `X=rm; $X -rf ~`, `echo ~ | xargs rm -rf`, `find ~ -delete`, a `for` loop over protected paths, or `shutil.rmtree` and `execSync` with the path inside. It resolves `..` and `/mnt/c` in a path before it checks it.

Mentioning a dangerous command inside a commit message, a grep or a heredoc doesn't trigger it. I ran it over 52,321 real Bash and PowerShell commands from 30 days of my own agent sessions. It blocked 75 of them, about 0.1%. Most were real hits, like `find` runs over a whole drive and reads of `gradle.properties`. A few were false alarms, mostly a PR body or heredoc whose text looked like a command. My first version blocked 74. The extra one is a heredoc that wrote a test file full of attacks. Each call takes around 2 ms.

## Install (Claude Code)

Copy `guard.py` somewhere stable and add it to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell|Read|Edit|Write|MultiEdit|NotebookEdit",
        "hooks": [{ "type": "command", "command": "python -S /path/to/guard.py" }]
      }
    ]
  }
}
```

Exit code 2 blocks the call and Claude Code shows the reason to the model. If the guard itself crashes it also returns 2, so a bug fails closed.

Other agents or scripts can call it directly:

```
python guard.py --check "rm -rf ~"
```

It prints the reason and exits with 2, or prints `allowed` and exits with 0.

## Config

Optional. Copy `guard.config.example.json` to `guard.config.json` next to `guard.py`, or point `AGENT_GUARD_CONFIG` at one:

```json
{ "protected_paths": ["C:/work/main-repo"] }
```

## Tests

```
python -m unittest discover -s tests -v
```

The tests have four groups: the normal cases, the bypasses I found in my own earlier version, the disguised deletes, and the known gaps below. The gaps are written as expected failures, so if one gets fixed the test run tells you.

Most of the hidden deletes come from the adversarial corpus of [nah](https://github.com/manuelschipper/nah), which is MIT. It has 49 ways to write `rm -rf` on a root and I swapped the target for the home folder and a protected repo. My first version stopped 14 of them. This one stops 48.

## Known gaps

This reads the command as text, so it catches mistakes. An agent that wants to get around it can. These still pass:

- `echo $(rm -rf ~)` and a script written to a file and run in a second step
- An encoded command, like `echo ... | base64 -d | sh`
- `cd ~ && rm -rf *`, where the danger is in the folder you're standing in
- `rm -rf $X/` when nothing in the command sets `X`
- `mv ~ /tmp/x`, `rsync --delete` into the home, and PowerShell's `$_.Delete()` inside a loop
- A path read into a variable, like `IFS=~ read -r a b <<< "x/y"; rm -rf "$a"` (the one nah case that passes)

For a real boundary you need a container or a separate user account.

## License

MIT
