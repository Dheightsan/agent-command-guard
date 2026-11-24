# Security

## Reporting a vulnerability

If you find a way to get a destructive command or a credential read past the guard, please report it privately through [GitHub's private vulnerability reporting](https://github.com/Dheightsan/agent-command-guard/security/advisories/new). Don't open a public issue for it.

Send the exact command, which shell you used and what the guard returned. A test case in the same format as `tests/test_guard.py` helps a lot.

## Disclosure

I maintain this alone in my free time, so I can't promise a response time. I'll answer as soon as I can, fix it in a private advisory when it makes sense, and credit you in the fix commit if you want. Please give me a reasonable time to fix it before you publish the details.

## Scope

The gaps already listed in the README under "Known gaps" don't need a report.

Only the latest commit on `main` is supported.
