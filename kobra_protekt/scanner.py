"""Analyse de l'appareil (Windows) — port de AppScanner + DeviceChecker.

Équivalent Windows du scan d'applis Android :
  • fichiers des dossiers surveillés (Téléchargements, Bureau, Temp, Démarrage) :
    empreinte SHA-256 comparée à la base ;
  • processus en cours : chemin de l'exécutable, empreinte, emplacement suspect ;
  • persistance : dossiers Démarrage et clés Run ;
  • connexions réseau actives (netstat) : IP distantes comparées aux C2 connus ;
  • comportement : exécution depuis Temp/AppData, binaire non signé.

L'analyse ne lance jamais les fichiers ; elle les lit seulement.
"""
from __future__ import annotations
import hashlib
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field

from .signatures import SignatureDB

IS_WIN = sys.platform.startswith("win")

THREAT = "threat"
REVIEW = "review"

MAX_HASH_BYTES = 256 * 1024 * 1024  # on ne lit pas au-delà (gros fichiers)


@dataclass
class Finding:
    name: str                       # nom affiché (fichier ou processus)
    path: str                       # chemin complet (cible de suppression)
    verdict: str                    # THREAT | REVIEW
    kind: str                       # "file" | "process" | "connection"
    reasons: list = field(default_factory=list)
    sha256: str = ""
    pid: int = 0
    remote_ip: str = ""             # pour les indicateurs réseau
    remote_host: str = ""
    confirmed: bool = False         # menace confirmée (liste/empreinte) -> signalement possible
    signed: bool | None = None      # binaire signé Authenticode

    @property
    def title(self) -> str:
        return self.name or os.path.basename(self.path) or self.remote_ip


def sha256_file(path: str) -> str:
    try:
        if os.path.getsize(path) > MAX_HASH_BYTES:
            return ""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:  # noqa: BLE001
        return ""


def default_watch_dirs() -> list[str]:
    home = os.path.expanduser("~")
    cands = [
        os.path.join(home, "Downloads"),
        os.path.join(home, "Desktop"),
        os.environ.get("TEMP", os.path.join(home, "AppData", "Local", "Temp")),
    ]
    if IS_WIN:
        appdata = os.environ.get("APPDATA", "")
        cands.append(os.path.join(appdata, r"Microsoft\Windows\Start Menu\Programs\Startup"))
    return [c for c in cands if c and os.path.isdir(c)]


SUSPICIOUS_LOC = re.compile(r"\\(Temp|AppData\\Local\\Temp|Downloads)\\", re.I)
SCAN_EXT = {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
            ".jar", ".msi", ".com", ".sys"}


def _authenticode_signed(path: str) -> bool | None:
    if not IS_WIN:
        return None
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"(Get-AuthenticodeSignature -LiteralPath '{path}').Status"],
            capture_output=True, text=True, timeout=15)
        return out.stdout.strip() == "Valid"
    except Exception:  # noqa: BLE001
        return None


def scan_files(db: SignatureDB, dirs: list[str], progress=lambda a, b: None) -> list[Finding]:
    found: list[Finding] = []
    files: list[str] = []
    for d in dirs:
        for root, _, names in os.walk(d):
            depth = root[len(d):].count(os.sep)
            if depth > 4:
                continue
            for n in names:
                if os.path.splitext(n)[1].lower() in SCAN_EXT:
                    files.append(os.path.join(root, n))
    total = len(files) or 1
    for i, p in enumerate(files):
        progress(i + 1, total)
        digest = sha256_file(p)
        if not digest:
            continue
        reasons, verdict, confirmed = [], None, False
        if digest in db.hashes:
            reasons.append("Fichier identique à un malware connu (empreinte)")
            verdict, confirmed = THREAT, True
        elif SUSPICIOUS_LOC.search(p) and os.path.splitext(p)[1].lower() in {".exe", ".scr", ".com"}:
            signed = _authenticode_signed(p)
            if signed is False:
                reasons.append("Exécutable non signé lancé depuis un dossier temporaire")
                verdict = REVIEW
        if verdict:
            found.append(Finding(name=os.path.basename(p), path=p, verdict=verdict,
                                 kind="file", reasons=reasons, sha256=digest,
                                 confirmed=confirmed))
    return found


def _running_processes() -> list[tuple[int, str, str]]:
    """Renvoie (pid, nom, chemin). Windows : WMIC/PowerShell ; sinon /proc."""
    procs = []
    if IS_WIN:
        try:
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-CimInstance Win32_Process | "
                 "Select-Object ProcessId,Name,ExecutablePath | ConvertTo-Csv -NoTypeInformation"],
                capture_output=True, text=True, timeout=30).stdout
            for line in out.splitlines()[1:]:
                m = re.match(r'"(\d+)","([^"]*)","([^"]*)"', line)
                if m:
                    procs.append((int(m.group(1)), m.group(2), m.group(3)))
        except Exception:  # noqa: BLE001
            pass
    else:  # dev sous Linux
        for pid in [d for d in os.listdir("/proc") if d.isdigit()]:
            try:
                exe = os.readlink(f"/proc/{pid}/exe")
                procs.append((int(pid), os.path.basename(exe), exe))
            except Exception:  # noqa: BLE001
                continue
    return procs


def scan_processes(db: SignatureDB, progress=lambda a, b: None) -> list[Finding]:
    found: list[Finding] = []
    procs = _running_processes()
    total = len(procs) or 1
    for i, (pid, name, path) in enumerate(procs):
        progress(i + 1, total)
        if not path or not os.path.isfile(path):
            continue
        digest = sha256_file(path)
        reasons, verdict, confirmed = [], None, False
        if digest and digest in db.hashes:
            reasons.append("Processus identique à un malware connu (empreinte)")
            verdict, confirmed = THREAT, True
        elif SUSPICIOUS_LOC.search(path):
            signed = _authenticode_signed(path)
            if signed is False:
                reasons.append("Processus non signé exécuté depuis un dossier temporaire")
                verdict = REVIEW
        if verdict:
            found.append(Finding(name=name, path=path, verdict=verdict, kind="process",
                                 reasons=reasons, sha256=digest, pid=pid, confirmed=confirmed))
    return found


def scan_connections(db: SignatureDB) -> list[Finding]:
    """Connexions actives dont l'IP distante est un C2 connu."""
    found: list[Finding] = []
    if not (IS_WIN or sys.platform.startswith("linux")):
        return found
    try:
        cmd = ["netstat", "-ano"] if IS_WIN else ["ss", "-tunp"]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout
    except Exception:  # noqa: BLE001
        return found
    seen = set()
    for line in out.splitlines():
        for ip in re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})", line):
            if ip in db.bad_ips and ip not in seen:
                seen.add(ip)
                found.append(Finding(
                    name=f"Connexion vers {ip}", path="", verdict=THREAT,
                    kind="connection", remote_ip=ip, confirmed=True,
                    reasons=["Connexion active vers un serveur de commande (C2) connu"]))
    return found


def full_scan(db: SignatureDB, dirs: list[str] | None = None,
              progress=lambda phase, a, b: None) -> list[Finding]:
    dirs = dirs or default_watch_dirs()
    out: list[Finding] = []
    out += scan_files(db, dirs, lambda a, b: progress("files", a, b))
    out += scan_processes(db, lambda a, b: progress("proc", a, b))
    out += scan_connections(db)
    # tri : menaces d'abord
    out.sort(key=lambda f: (f.verdict != THREAT, f.title.lower()))
    return out
