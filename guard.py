"""agent-command-guard: a PreToolUse hook that stops a coding agent from running a few
commands that cannot be undone (wiping a drive or the home folder, piping a download into a
shell, reading credential files, rewriting git history).

It is a seatbelt, not a sandbox. It reads the command as text with regular expressions, so a
determined agent can still get around it (see README, "Known gaps"). The goal is to catch the
common mistakes an agent makes on its own, with very few false positives.

Claude Code: register it as a PreToolUse hook. It reads the event as JSON on stdin and exits
with 2 (blocked, reason on stderr) or 0 (allowed).
Any other agent or script: python guard.py --check "rm -rf ~"
"""
import json
import os
import re
import sys

PREFIX = "[agent-guard]"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# guard.config.json next to this file, or the path in AGENT_GUARD_CONFIG:
#   {"protected_paths": ["C:/work/main-repo"]}
# A protected path can't be deleted whole (with or without /*), and neither can its .git folder.

_HOME = (
    r"(?:~|\$home|\$\{home\}|\$env:userprofile|%userprofile%|"
    r"[a-z]:[\\/]users[\\/][^\\/*]+|/[a-z]/users/[^/*]+|/home/[^/*]+|/users/[^/*]+|/root)"
)
_HOME_DIRS = r"\.claude|\.ssh|\.gradle|\.config|\.aws|\.gnupg|documents|desktop|onedrive|appdata"

_RAIZ = None
_GIT_DIR = None


def _path_regex(path):
    """Regex for a path in its Windows (C:\\x, C:/x) and Git Bash (/c/x) forms, lowercase."""
    p = path.strip().replace("\\", "/").rstrip("/").lower()
    m = re.fullmatch(r"([a-z]):/(.*)", p)
    if m:
        drive, rest = m.groups()
        cuerpo = r"[\\/]".join(re.escape(x) for x in rest.split("/") if x)
        return r"(?:" + drive + r":[\\/]|/" + drive + r"/)" + cuerpo
    return r"[\\/]".join(re.escape(x) for x in p.split("/"))


def configure(protected_paths=()):
    """Builds the path patterns. Called on import with the config file; tests call it directly."""
    global _RAIZ, _GIT_DIR
    extra = [_path_regex(p) for p in protected_paths if p.strip()]
    proyectos = "".join("|" + e + r"[\\/]?\*?" for e in extra)
    _RAIZ = re.compile(
        r"[a-z]:[\\/]?\*?|/\*?|/[a-z]/?\*?|"
        + _HOME + r"(?:[\\/](?:" + _HOME_DIRS + r"))?[\\/]?\*?"
        + proyectos
    )
    # The .git folder of the current repo (".git", "./.git") or of a protected path. With any other
    # path in front (copy_of_some_source/.git) it passes: dropping the .git of a copied source tree
    # is a normal step. .git/index.lock, .github and .gitignore don't match.
    gits = "".join("|" + e + r"[\\/]\.git[\\/]?" for e in extra)
    _GIT_DIR = re.compile(r"(?:\.[\\/])?\.git[\\/]?" + gits)


def _load_config():
    ruta = os.environ.get("AGENT_GUARD_CONFIG") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "guard.config.json"
    )
    try:
        with open(ruta, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


configure(_load_config().get("protected_paths", []))


# ---------------------------------------------------------------------------
# Entry point for one tool call
# ---------------------------------------------------------------------------

def evaluate(data):
    """Checks one Claude Code PreToolUse event. Returns (exit_code, message)."""
    if not isinstance(data, dict):
        return 2, PREFIX + " Invalid input: expected a JSON object."

    tool_input = data.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = data  # older flat schema

    tool_name = str(data.get("tool_name", ""))
    file_path = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "").lower()
    if file_path and _CREDENCIALES.search(file_path):
        return 2, (
            PREFIX + " Blocked: {} is a credentials file. An agent doesn't read or edit it; "
            "ask the user for the value you need, without the secret.".format(file_path)
        )
    if tool_name == "Read":
        # Read is only checked against credential files: reading .env.example is fine.
        return 0, ""
    if file_path and re.search(r"\.env|secrets|id_rsa|credentials", file_path):
        return 2, PREFIX + " Blocked: writing to a sensitive file ({}).".format(file_path)

    command = str(tool_input.get("command", "")).lower()
    if command:
        motivo = check_command(command)
        if motivo:
            return 2, motivo
    return 0, ""


def check_command(command, nivel=0):
    """Returns the block reason for a shell command (Bash, PowerShell or cmd), or None.
    nivel counts the wrappers already opened (bash -c, python -c), up to 3."""
    command = command.lower()
    if re.search(r"\bformat\s+[a-z]:", command) or _borra_raiz(command):
        return PREFIX + " Blocked: deletes a drive root, the home folder, a protected path or a .git folder."

    if _borra_variable(command):
        return (
            PREFIX + " Blocked: recursive or forced delete of a bare variable ($X) that was set to a "
            "root, the home folder or an almost empty value. Write the literal path."
        )

    if _descarga_a_shell(command):
        return (
            PREFIX + " Blocked: a download runs straight in a shell (curl | bash, bash <(curl), "
            "iwr | iex). Save it to a file, read it, and ask the user before running it."
        )

    if _lee_credenciales(command):
        return (
            PREFIX + " Blocked: the command reads or copies a credentials file "
            "(.ssh/id_*, .git-credentials, .npmrc, gradle.properties...)."
        )

    if _find_raiz(command):
        return (
            PREFIX + " Blocked: find from the root of a drive. A stray find / can hold millions of "
            "handles and GBs of kernel memory. Search a concrete folder, or add -maxdepth 3."
        )

    git = _git_destructivo(command)
    if git:
        return (
            PREFIX + " Blocked: {}. It throws away work or rewrites remote history with no way back. "
            "Ask the user with the exact command (or use --force-with-lease for a push).".format(git)
        )

    if nivel < 3:
        for cuerpo, es_python in _envueltos(command):
            motivo = _python_destructivo(cuerpo, nivel) if es_python else check_command(cuerpo, nivel + 1)
            if motivo:
                return motivo + " (inside bash -c or python -c)"
    return None


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

# Wrappers that can sit before the real verb: sudo, env VAR=x, command, nohup, time, nice,
# exec, cmd /c, powershell -command.
_PREFIJO = (
    r"(?:sudo(?:\s+-\w+)*|env(?:\s+-\w+)*(?:\s+\w+=\S*)*|command|builtin|exec|nohup|time|"
    r"nice(?:\s+-n\s*-?\d+)?|cmd(?:\.exe)?\s+/c|(?:powershell|pwsh)(?:\.exe)?(?:\s+-\w+)*?\s+-c(?:ommand)?)"
)
# Delete verbs of Bash, cmd and PowerShell (with aliases) at the start of a segment. Also with a
# leading backslash (\rm skips aliases) or a full path (/bin/rm, /usr/bin/rm). Requiring the
# start avoids blocking prose that contains "del" inside a script.
_VERBO_BORRADO = re.compile(
    r"^[\s('\"&]*(?:" + _PREFIJO + r"\s+['\"]?)*\\?(?:(?:/usr)?/bin/)?"
    r"(?P<verbo>rm|remove-item|ri|del|erase|rd|rmdir)(?:\.exe)?\s(?P<resto>.*)$",
    re.S,
)
_VERBOS_CMD = ("del", "erase", "rd", "rmdir")

# Files with credentials (Read, Edit, Write and shell).
_CREDENCIALES = re.compile(
    r"\.gradle[\\/]gradle\.properties|\.ssh[\\/]id_|\.aws[\\/]credentials|\.git-credentials|"
    r"(?:^|[\\/\s'\"])\.npmrc\b|\.pypirc|\.docker[\\/]config\.json|\.claude[\\/]\.credentials\.json|"
    r"\.netrc\b|\.config[\\/]gh[\\/]hosts\.yml"
)
_VAR_SOLA = re.compile(r"\$(?:\{\w+\}|env:\w+|\w+)")
_RECURSIVO = re.compile(r"(?:^|\s)(?:-[a-z]*[rf][a-z]*|--recursive|--force|/s)(?=\s|$)")
_ASIGNA = re.compile(r"(?:^|[\s;&(])\$?(\w+)\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s;]+)")


def _tramos(command):
    """Splits on ; | && || and newlines, not inside quotes. Each line starts with no open quote,
    so a stray apostrophe in a heredoc doesn't glue lines together."""
    for linea in command.split("\n"):
        actual, comilla, i = [], None, 0
        while i < len(linea):
            c = linea[i]
            if comilla:
                if c == comilla:
                    comilla = None
                actual.append(c)
            elif c in "'\"":
                comilla = c
                actual.append(c)
            elif c in ";|" or linea.startswith("&&", i):
                yield "".join(actual)
                actual = []
                if linea.startswith(("&&", "||"), i):
                    i += 1
            else:
                actual.append(c)
            i += 1
        yield "".join(actual)


def _borra_raiz(command):
    """True if a segment deletes a root, the home folder, a protected path or a .git folder."""
    for tramo in _tramos(command):
        m = _VERBO_BORRADO.match(tramo)
        if not m:
            continue
        es_cmd = m.group("verbo") in _VERBOS_CMD
        for palabra in m.group("resto").split():
            palabra = palabra.strip("'\"(),")
            if es_cmd and re.fullmatch(r"/[a-z?]", palabra):
                continue  # del /f /q, rd /s: switches, not drives
            if palabra.startswith(("-path:", "-literalpath:")):
                palabra = palabra.split(":", 1)[1].strip("'\"")
            if _RAIZ.fullmatch(palabra) or _GIT_DIR.fullmatch(palabra):
                return True
    return False


def _borra_variable(command):
    """True if a segment deletes, recursively or forced, a target that is only a variable which
    the same command set to a root, the home folder or an almost empty value. Without an
    assignment in the command it can't know (loops, $_), so it passes. The common healthy
    pattern S=work_dir; rm -rf "$S"; mkdir -p "$S" passes too."""
    asignadas = {m.group(1): m.group(2).strip("'\"") for m in _ASIGNA.finditer(command)}
    for tramo in _tramos(command):
        m = _VERBO_BORRADO.match(tramo)
        if not m or not _RECURSIVO.search(tramo):
            continue
        for palabra in m.group("resto").split():
            palabra = palabra.strip("'\"(),")
            if not _VAR_SOLA.fullmatch(palabra):
                continue
            nombre = re.sub(r"^\$(?:env:)?\{?|\}$", "", palabra)
            valor = asignadas.get(nombre)
            if valor is not None and (_RAIZ.fullmatch(valor.lower()) or len(valor.strip("/\\")) < 4):
                return True
    return False


_DESCARGA_SHELL = re.compile(
    r"\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|\n]*\|\s*(?:sudo\s+)?"
    r"(?:(?:(?:ba|z|da)?sh|iex|invoke-expression|powershell|pwsh)\b|"
    r"(?:python3?|py|node|perl|ruby)(?:\.exe)?(?:\s+-)?\s*(?=$|[;&)]))"
)
# bash <(curl ...), source <(wget ...)
_DESCARGA_SUB = re.compile(r"(?:\b(?:ba|z|da)?sh|\bsource|(?:^|\s)\.)\s+<\(\s*(?:curl|wget)\b")
# iex (iwr ...), iex (new-object net.webclient).downloadstring(...)
_IEX_DESCARGA = re.compile(
    r"\b(?:iex|invoke-expression)\b[\s(&]*(?:\(\s*)?(?:iwr|irm|invoke-webrequest|invoke-restmethod|"
    r"(?:new-object\s+)?(?:system\.)?net\.webclient)|"
    r"\b(?:iex|invoke-expression)\b.*\.downloadstring\(|\.downloadstring\(.*\|\s*(?:iex|invoke-expression)\b"
)


def _fuera_de_comillas(linea, pos):
    antes = linea[:pos]
    return antes.count("'") % 2 == 0 and antes.count('"') % 2 == 0


def _descarga_a_shell(command):
    """True if a line downloads something and hands it to a shell or interpreter, outside quotes."""
    for linea in command.split("\n"):
        for patron in (_DESCARGA_SHELL, _DESCARGA_SUB, _IEX_DESCARGA):
            for m in patron.finditer(linea):
                if _fuera_de_comillas(linea, m.start()):
                    return True
    return False


_LEE = re.compile(
    r"(?:^|[\s(|;&])(?:cat|type|get-content|gc|head|tail|less|more|grep|rg|sed|awk|cp|copy|copy-item|"
    r"scp|base64|xxd|strings|select-string|sls|python3?|py|node|perl|ruby)(?:\.exe)?\s|"
    r"\[(?:system\.)?io\.file\]::(?:read|copy|open)"
)


def _lee_credenciales(command):
    """True if a segment names a credentials file next to something that reads or copies it.
    Only naming it (an exclusion list for a backup) doesn't block."""
    for tramo in _tramos(command):
        if _CREDENCIALES.search(tramo) and _LEE.search(tramo):
            return True
    return False


# find at the start of a segment (with timeout, nice or sudo in front) and the paths it gets
# before the first expression. Root = "/", "/c", "C:/" or "C:\". With -maxdepth 3 or less it
# passes: it's fast and doesn't leave processes behind.
_FIND = re.compile(
    r"^[\s(&]*(?:(?:sudo|nice|timeout\s+\S+)\s+)*(?:['\"]?(?:/usr/bin/|[a-z]:[\\/][^'\"]*[\\/]))?"
    r"find(?:\.exe)?['\"]?\s+(.*)$"
)
_RAIZ_FIND = re.compile(r"/|/[a-z]/?|[a-z]:[\\/]?")
_FIND_CORTO = re.compile(r"-maxdepth\s+[0-3]\b")


def _es_unidad(palabra):
    """/x is only a root if drive X: exists: /I, /V or /N are switches of the Windows find.
    Outside Windows, only /c and /d count."""
    if re.fullmatch(r"/[a-z]/?", palabra):
        if os.name == "nt":
            return os.path.isdir(palabra[1] + ":\\")
        return palabra[1] in "cd"
    return True


def _find_raiz(command):
    for tramo in _tramos(command):
        m = _FIND.match(tramo)
        if not m or _FIND_CORTO.search(m.group(1)):
            continue
        for palabra in m.group(1).split():
            palabra = palabra.strip("'\"")
            if palabra.startswith(("-", "(", "!", "\\(")):
                break
            if _RAIZ_FIND.fullmatch(palabra) and _es_unidad(palabra):
                return True
    return False


# git with its global options (-C dir, -c k=v, --no-pager...) at the start of a segment.
_GIT = re.compile(
    r"^[\s(&]*(?:sudo\s+)?git(?:\.exe)?"
    r"(?:\s+(?:-[cC]\s+(?:'[^']*'|\"[^\"]*\"|\S+)|--[\w-]+(?:=\S+)?))*\s+(\w[\w-]*)\b(.*)$",
    re.S,
)


def _git_destructivo(command):
    """Reason if a segment is git reset --hard or git push --force (-f, +branch).
    --force-with-lease and --soft/--mixed pass. Only at the start of a segment, outside quotes:
    a commit message or a grep that names the command doesn't block."""
    for tramo in _tramos(command):
        m = _GIT.match(tramo)
        if not m:
            continue
        sub, resto = m.group(1), m.group(2).split()
        if sub == "reset" and "--hard" in resto:
            return "git reset --hard"
        if sub == "push":
            for t in resto:
                t = t.strip("'\"")
                if t == "--force" or t.startswith("--force="):
                    return "git push " + t.split("=")[0]
                if re.fullmatch(r"-[a-z]+", t) and "f" in t:
                    return "git push " + t
                if re.fullmatch(r"\+[\w./:-]+", t):
                    return "git push with +refspec (forces the push)"
    return None


_ENVUELTO = re.compile(
    r"^[\s(&]*(?:sudo\s+)?(?:(?:/usr/bin/|/bin/)?(?:ba|z|da)?sh|python3?|py)(?:\.exe)?"
    r"\s+(?:-[\w-]+(?:\s+[^\s-]\S*)?\s+)*?-[a-z]*c\s+(?P<q>['\"])(?P<cuerpo>.*?)(?<!\\)(?P=q)",
    re.S,
)
_PY = re.compile(r"^[\s(&]*(?:sudo\s+)?(?:python3?|py)(?:\.exe)?\s")


def _envueltos(command):
    """Bodies of bash -c '...' and python -c '...': (text, is_python)."""
    for tramo in _tramos(command):
        m = _ENVUELTO.match(tramo)
        if m:
            yield m.group("cuerpo"), bool(_PY.match(tramo))


_PY_BORRA = re.compile(r"rmtree|os\.remove|os\.unlink|os\.rmdir|\.unlink\(|\.rmdir\(|shutil\.move")
_LITERAL = re.compile(r"""(['"])(.*?)(?<!\\)\1""", re.S)


def _python_destructivo(cuerpo, nivel):
    """python -c: blocks deleting a root, the home folder or .git, and checks with the shell
    rules the strings that reach os.system or subprocess."""
    literales = [l[1].replace("\\\\", "/").replace("\\", "/") for l in _LITERAL.findall(cuerpo)]
    if _PY_BORRA.search(cuerpo):
        for lit in literales:
            lit = lit.strip().lower()
            if lit and (_RAIZ.fullmatch(lit) or _GIT_DIR.fullmatch(lit)):
                return PREFIX + " Blocked: deletes a drive root, the home folder or a .git folder."
    if re.search(r"os\.system|subprocess|popen", cuerpo):
        for lit in literales:
            motivo = check_command(lit, nivel + 1)
            if motivo:
                return motivo
    if _CREDENCIALES.search(cuerpo) and re.search(r"\bopen\(|read_text|read_bytes", cuerpo):
        return PREFIX + " Blocked: the script opens a credentials file."
    return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["--check"]:
        motivo = check_command(" ".join(argv[1:]))
        print(motivo or "allowed")
        return 2 if motivo else 0

    input_data = sys.stdin.read()
    if not input_data.strip():
        return 0
    try:
        data = json.loads(input_data)
    except json.JSONDecodeError as exc:
        print(f"{PREFIX} Invalid JSON input: {exc}", file=sys.stderr)
        return 2
    try:
        exit_code, message = evaluate(data)
    except Exception as exc:  # fail closed
        print(f"{PREFIX} Internal error: {exc}", file=sys.stderr)
        return 2
    if message:
        # With exit 2, Claude Code shows stderr to the model as the reason.
        print(message, file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
