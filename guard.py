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
    r"(?:~|\$home|\$\{home\}|\$userprofile|\$\{userprofile\}|\$env:userprofile|\$env:home|%userprofile%|"
    r"[a-z]:[\\/]users[\\/][^\\/*]+|/[a-z]/users/[^/*]+|/home/[^/*]+|/users/[^/*]+|/root)"
)
# Folders of the home that are never deleted whole. The .claude subfolders hold work that isn't
# regenerated (transcripts, skills, hooks, rules, agents); a deeper subfolder still passes.
_HOME_DIRS = (
    r"\.claude(?:[\\/](?:projects|skills|hooks|rules|agents))?|\.ssh|\.gradle|\.config|\.aws|\.gnupg|"
    r"documents|desktop|onedrive|appdata(?:[\\/](?:local|roaming))?"
)

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
        + _HOME + r"(?:[\\/](?:" + _HOME_DIRS + r"))?[\\/]?\*?|"
        + _HOME + r"[\\/]\.\.(?:[\\/].*)?|"  # ~/.. climbs out of the home
        r"(?:[a-z]:[\\/]|/[a-z]/)(?:users|windows)[\\/]?\*?|/home[\\/]?\*?|/users[\\/]?\*?|"
        r"(?:\$env:|\$|%)(?:appdata|localappdata|onedrive)%?[\\/]?\*?"
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
    motivo = _revisar(command, nivel)
    if motivo or nivel:
        return motivo
    # The same command as the shell would see it (continued lines joined, $'\x72\x6d' decoded),
    # and then with the variables that the command itself sets replaced (X=rm; $X -rf ~).
    normal = _normalizar(command)
    if normal != command:
        motivo = _revisar(normal, 0)
    if not motivo and _SOSPECHA.search(normal.replace('"', "").replace("'", "").replace("\\", "")):
        expandido = _expandir(normal)
        if expandido != normal and (_borra_raiz(expandido) or _borra_disfrazado(expandido, 0)):
            motivo = _MSG_DESTRUCTIVO + " (after replacing the variables the command sets)"
    return motivo


def _revisar(command, nivel):
    if re.search(r"\bformat\s+[a-z]:", command) or _borra_raiz(command):
        return PREFIX + " Blocked: deletes a drive root, the home folder, a protected path or a .git folder."

    if _borra_disfrazado(command, nivel):
        return (
            _MSG_DESTRUCTIVO + ", behind a wrapper (timeout, eval, sudo -u, su -c, trap, xargs...), a pipe, "
            "a loop or a call (os.system, rmtree, execSync). If the delete is legit, write the exact subfolder."
        )

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
            motivo = _python_destructivo(cuerpo, nivel) if es_python else _revisar(cuerpo, nivel + 1)
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
            if _protegida(palabra):
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
            if valor is not None and (_protegida(valor.lower()) or len(valor.strip("/\\")) < 4):
                return True
    return False


def _ruta(palabra):
    """The path as it resolves: no quotes, / instead of \\, no //, /./ or x/.., and /mnt/c or
    /cygdrive/c as /c. So /c/Users/me/../me, "$HOME"/ and C:\\work\\.\\ don't slip through."""
    p = palabra.replace('"', "").replace("'", "").strip("(),;")
    if p.startswith(("-path:", "-literalpath:")):
        p = p.split(":", 1)[1]
    if p.startswith("\\\\?\\"):
        p = p[4:]
    q = p.replace("\\", "/")
    if "/" not in q:
        return p
    q = re.sub(r"^/(?:mnt|cygdrive)/([a-z])(?=/|$)", r"/\1", q)
    partes = []
    for i, s in enumerate(q.split("/")):
        if s == "." or (s == "" and i > 0):
            continue
        if (s == ".." and partes and partes[-1] not in ("", "..", "~")
                and not partes[-1].startswith(("$", "%")) and not re.fullmatch(r"[a-z]:", partes[-1])):
            partes.pop()
            continue
        partes.append(s)
    r = "/".join(partes)
    if r == "":
        return "/" if q.startswith("/") else p
    return r


def _protegida(palabra):
    """True if the word, once resolved, is a root, the home folder, a protected path or a .git folder."""
    # A lone "\n" or "\t" is an escape inside some text, not drive /n.
    if re.fullmatch(r"\\[a-z]", palabra.strip("'\"(),;")):
        return False
    r = _ruta(palabra)
    return bool(r and (_RAIZ.fullmatch(r) or _GIT_DIR.fullmatch(r)))


# ---- Disguised deletes ------------------------------------------------------------------------
# Measured with the adversarial corpus of nah (MIT, 49 templates of rm -rf on a root): the guard
# above alone blocked 14 of 49. What got through: rm behind a wrapper that isn't a known prefix
# (timeout 5, eval, sudo -u x, setsid, docker exec...), inside a string another program runs
# (su -c '...', trap '...', node -e, os.system), a disguised verb ("r""m", r\m, $'\x72\x6d',
# X=rm; $X) or a delete split across a pipe or a loop. To avoid blocking prose (a report or a commit
# message that names the command), the wrapper rules only look at segments whose first word runs
# something.
_MSG_DESTRUCTIVO = PREFIX + " Blocked: deletes a drive root, the home folder, a protected path or a .git folder"
_SOSPECHA = re.compile(
    r"\brm|remove-item|\brd\b|\bdel\b|\berase\b|delete|unlink|removedirs|remove_dir_all|"
    r"(?:^|\s)-[a-z]*(?:r[a-z]*f|f[a-z]*r)[a-z]*(?=\s|$)"
)
_EJECUTOR = frozenset(
    "eval su sudo doas runas script trap at batch crontab watch ssh wsl xargs parallel sh bash zsh dash ksh "
    "fish node nodejs deno bun perl php ruby lua python python3 py pwsh powershell cmd env nohup timeout time "
    "nice ionice chrt taskset stdbuf setsid flock chroot unshare nsenter systemd-run docker podman kubectl "
    "exec command builtin strace ltrace busybox tmux screen expect find start-process saps invoke-expression "
    "iex invoke-command icm start-job sajb schtasks wscript cscript mshta & .".split()
)
_VERBO_SUELTO = re.compile(r"(?:(?:/usr)?/bin/)?(?:rm|remove-item)(?:\.exe)?")
_VERBO_TUBERIA = re.compile(r"(?:(?:/usr)?/bin/)?(?:rm|remove-item|ri|del|erase|rd|rmdir)(?:\.exe)?")
_RF = re.compile(r"-[a-z]*[rf][a-z]*|--recursive|--force|/s|/q")
_RF_AMBOS = re.compile(r"-(?=[a-z]*r)(?=[a-z]*f)[a-z]{2,4}")
_RF_BORRA = re.compile(r"-r[a-z]*|-f|-fr|-fo(?:rce)?|--recursive|--force|/s|/q")
_ANTES_VERBO = frozenset("xargs % foreach-object foreach sudo {".split())
_ANSI_C = re.compile(r"\$'((?:\\.|[^'\\])*)'")
_LLAMADA = re.compile(
    r"(?:system|exec\w*|popen|spawn\w*|run|call|check_output|check_call|shell_exec|passthru|getoutput|"
    r"getstatusoutput)\s*\(\s*(['\"])(.*?)(?<!\\)\1",
    re.S,
)
_LLAMADA_LISTA = re.compile(
    r"(?:run|call|popen|check_output|check_call|spawn\w*|exec\w*)\s*\(\s*((?:['\"][\w./\\-]*['\"]\s*,\s*)?)"
    r"\[([^\]]*)\]"
)
_API_BORRA = re.compile(
    r"(?:rmtree|os\.remove|os\.unlink|os\.rmdir|removedirs|rmsync|rmdirsync|unlinksync|fs\.rm|remove_dir_all|"
    r"\[(?:system\.)?io\.(?:directory|file)\]::delete)\s*\(\s*r?(['\"])(.*?)(?<!\\)\1",
    re.S,
)
_LISTA = frozenset("ls dir gci get-childitem get-item gi find echo printf write-output".split())
_FILTRO = re.compile(r"(?:^|\s)-(?:filter|include|exclude|i?name|i?path|i?regex|mtime|mmin|newer|size|empty)\b")
_FOR_SH = re.compile(r"\bfor\s+(\w+)\s+in\s+([^;\n]+?)\s*[;\n]\s*do\b(.*?)(?:\bdone\b|$)", re.S)
_FOR_PS = re.compile(r"\bforeach\s*\(\s*\$(\w+)\s+in\s+([^)]*)\)\s*\{(.*?)\}", re.S)


def _ansi_c(m):
    s = re.sub(r"\\x([0-9a-f]{1,2})", lambda h: chr(int(h.group(1), 16)), m.group(1))
    return re.sub(r"\\([0-7]{1,3})", lambda o: chr(int(o.group(1), 8)), s)


def _normalizar(command):
    """Joins lines continued with ' \\' or ' `' and decodes bash ANSI-C quotes."""
    if "\n" in command:
        command = re.sub(r"(?<=[ \t])[\\`]\r?\n[ \t]*", " ", command)
    if "$'" in command:
        command = _ANSI_C.sub(_ansi_c, command)
    return command


def _expandir(command):
    """Replaces $X and ${X} with the literal value the same command assigns (X=rm; Z=/c/x)."""
    asignadas = {}
    for m in _ASIGNA.finditer(command):
        valor = m.group(2).strip("'\"")
        if valor and "$" not in valor and len(valor) < 200:
            asignadas[m.group(1)] = valor
    if not asignadas:
        return command
    return re.sub(
        r"\$\{(\w+)\}|\$(\w+)",
        lambda m: asignadas.get(m.group(1) or m.group(2), m.group(0)),
        command,
    )


def _palabras(tramo):
    """Shell words of a segment, without quotes: (text, is_phrase). A phrase is quoted text with
    spaces. Outside quotes, spaces and ( ) ` , [ ] separate words."""
    out, act, comilla, frase, hubo = [], [], None, False, False
    i, n = 0, len(tramo)
    while i < n:
        c = tramo[i]
        if comilla:
            if c == "\\" and comilla == '"' and i + 1 < n and tramo[i + 1] in '"\\':
                act.append(tramo[i + 1])
                i += 2
                continue
            if c == comilla:
                comilla = None
            else:
                act.append(c)
                if c in " \t":
                    frase = True
        elif c in "'\"":
            comilla, hubo = c, True
        elif c in " \t()`,[]":
            if act or hubo:
                out.append(("".join(act), frase))
            act, frase, hubo = [], False, False
        else:
            act.append(c)
        i += 1
    if act or hubo:
        out.append(("".join(act), frase))
    return out


def _nombre(palabra):
    """Program name: no path, no .exe, no escape backslashes."""
    p = palabra.replace("\\", "/").rstrip("/")
    p = p.rsplit("/", 1)[-1]
    return p[:-4] if p.endswith(".exe") else p


def _rm_con_destino(simples):
    """True if the words hold an rm or Remove-Item followed by -r/-f and a protected target."""
    for i, p in enumerate(simples):
        if _VERBO_SUELTO.fullmatch(p.replace("\\", "")):
            resto = simples[i + 1:]
            if any(_RF.fullmatch(r) for r in resto) and any(_protegida(r) for r in resto):
                return True
    return False


def _borra_disfrazado(command, nivel):
    """True if the command deletes a protected target without rm at the start of a segment."""
    if not _SOSPECHA.search(command.replace('"', "").replace("'", "").replace("\\", "")):
        return False
    for tramo in _tramos(command):
        pal = _palabras(tramo)
        if not pal:
            continue
        simples = [p for p, frase in pal if not frase]
        crudo = tramo.lstrip(" \t(&{")
        primera = _nombre(pal[0][0])
        # $cmd at the start (not PowerShell's "$x = ..."), $(...) or `...`: the verb comes from a substitution.
        var_cmd = bool(re.fullmatch(r"\$\{?\w+\}?", pal[0][0])) and not (len(pal) > 1 and pal[1][0].startswith("="))
        ejecuta = (primera in _EJECUTOR or var_cmd or crudo.startswith(("$(", "`"))
                   or bool(re.fullmatch(r"\w+=", pal[0][0])))
        if simples and (ejecuta or _VERBO_SUELTO.fullmatch(simples[0].replace("\\", ""))):
            if _rm_con_destino(simples):
                return True
        if var_cmd and len(simples) > 1:
            # $cmd -rf /: we can't know what $cmd is, but -rf on a root has no healthy reading.
            # Only short bash flags (-rf, -fr, -rfv): PowerShell's -Filter or -Force don't count.
            if any(_RF_AMBOS.fullmatch(p) for p in simples[1:]) and any(_protegida(p) for p in simples[1:]):
                return True
        if nivel < 3 and (ejecuta or "<<<" in tramo):
            for p, frase in pal:
                if not frase:
                    continue
                if primera == "crontab":
                    p = re.sub(r"^\s*(?:[\d*/,-]+\s+){5}", "", p)  # the cron schedule goes before the command
                if _borra_raiz(p) or _borra_disfrazado(p, nivel + 1):
                    return True
    if nivel < 3:
        for m in _LLAMADA.finditer(command):
            lit = m.group(2).replace("\\'", "'").replace('\\"', '"')
            if " " in lit and (_borra_raiz(lit) or _borra_disfrazado(lit, nivel + 1)):
                return True
    for m in _LLAMADA_LISTA.finditer(command):
        if _rm_con_destino([p for p, _ in _palabras(m.group(1) + " " + m.group(2))]):
            return True
    for m in _API_BORRA.finditer(command):
        if _protegida(m.group(2).replace("\\\\", "/").strip()):
            return True
    return _find_borra(command) or _borra_en_tuberia(command) or _bucle_borra(command)


def _find_borra(command):
    """find <protected target> -delete or -exec rm, without a name filter: deletes everything inside."""
    for tramo in _tramos(command):
        m = _FIND.match(tramo)
        if not m:
            continue
        resto = m.group(1)
        if not re.search(r"(?:^|\s)-delete\b|-(?:exec|execdir|ok)\s+\S*\brm\b", resto) or _FILTRO.search(resto):
            continue
        for palabra in resto.split():
            if palabra.startswith(("-", "(", "!", "\\(")):
                break
            if _protegida(palabra):
                return True
    return False


def _tuberias(command):
    """Pipelines of the command: lists of stages split by | (not by ; && ||), without cutting quotes."""
    for linea in command.split("\n"):
        if "|" not in linea:
            continue
        etapas, actual, comilla, i = [], [], None, 0
        while i < len(linea):
            c = linea[i]
            if comilla:
                if c == comilla:
                    comilla = None
                actual.append(c)
            elif c in "'\"":
                comilla = c
                actual.append(c)
            elif c == ";" or linea.startswith(("&&", "||"), i):
                etapas.append("".join(actual))
                if len(etapas) > 1:
                    yield etapas
                etapas, actual = [], []
                if c != ";":
                    i += 1
            elif c == "|":
                etapas.append("".join(actual))
                actual = []
            else:
                actual.append(c)
            i += 1
        etapas.append("".join(actual))
        if len(etapas) > 1:
            yield etapas


def _borra_en_tuberia(command):
    """ls ~ | xargs rm -rf, gci C:\\Users\\me | Remove-Item -Recurse: lists a protected target with
    no filter and the next stage deletes what it gets."""
    for etapas in _tuberias(command):
        for k in range(1, len(etapas)):
            antes = [p for p, _ in _palabras(etapas[k - 1])]
            if not antes or _FILTRO.search(etapas[k - 1]):
                continue
            lista = _nombre(antes[0]) in _LISTA or etapas[k - 1].lstrip().startswith(("'", '"', "@("))
            if not lista or not any(_protegida(p.lstrip("@")) for p in antes):
                continue
            ahora = [p.replace("\\", "") for p, frase in _palabras(etapas[k]) if not frase]
            # The delete verb has to lead the stage (after xargs, %, foreach-object or a brace):
            # a stray "del" or "rd" inside a long block doesn't count.
            verbo = None
            for j, p in enumerate(ahora[:6]):
                if _VERBO_TUBERIA.fullmatch(p):
                    verbo = j
                    break
                if not (p in _ANTES_VERBO or p.startswith(("-", "{"))):
                    break
            if verbo is not None and any(_RF_BORRA.fullmatch(p) for p in ahora[verbo + 1:]):
                return True
    return False


def _bucle_borra(command):
    """for d in ~ /c/work; do rm -rf $d; done and foreach ($d in 'C:\\') { Remove-Item -Recurse $d }."""
    for patron in (_FOR_SH, _FOR_PS):
        for m in patron.finditer(command):
            if not any(_protegida(p) for p, _ in _palabras(m.group(2))):
                continue
            var = m.group(1)
            for tramo in _tramos(m.group(3)):
                tramo = re.sub(r"^\s*(?:do\b|\{)\s*", "", tramo)
                if (_VERBO_BORRADO.match(tramo) and _RECURSIVO.search(tramo)
                        and re.search(r"\$\{?" + re.escape(var) + r"\b", tramo)):
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
            if lit and _protegida(lit):
                return PREFIX + " Blocked: deletes a drive root, the home folder or a .git folder."
    if re.search(r"os\.system|subprocess|popen", cuerpo):
        for lit in literales:
            motivo = _revisar(lit.lower(), nivel + 1)
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
