"""Base de signatures et mise à jour depuis des listes publiques.

Port Windows de la logique Android (FeedUpdater + core/ThreatDatabase). On
télécharge des listes publiques puis on compare **localement** :

  • abuse.ch Feodo Tracker  — IP de serveurs de commande (C2) de botnets.
  • abuse.ch URLhaus        — domaines/URL distribuant des malwares.
  • abuse.ch MalwareBazaar  — empreintes SHA-256 des derniers malwares (clé gratuite).
  • Listes supplémentaires  — jusqu'à 10 URL https (SHA-256, STIX2, hostfile).

Rien n'est envoyé à ces services : on ne fait que télécharger les listes.
"""
from __future__ import annotations
import json
import os
import re
import time
from dataclasses import dataclass, field, asdict

from . import net

APP_DIR = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"),
                       "KobraProtekt")
DB_PATH = os.path.join(APP_DIR, "signatures.json")
MAX_LIST_BYTES = 8 * 1024 * 1024  # garde-fou (cf. LimitedInputStream Android)

FEODO_IPS = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
URLHAUS_HOSTS = "https://urlhaus.abuse.ch/downloads/text_online/"

SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$")


@dataclass
class SignatureDB:
    hashes: set = field(default_factory=set)      # SHA-256 de fichiers malveillants
    bad_ips: set = field(default_factory=set)      # IP de C2 connues
    bad_domains: set = field(default_factory=set)  # domaines connus
    updated: float = 0.0
    sources: dict = field(default_factory=dict)    # nom -> compte

    # ---- persistance ----
    @classmethod
    def load(cls) -> "SignatureDB":
        try:
            with open(DB_PATH, encoding="utf-8") as f:
                d = json.load(f)
            return cls(
                hashes=set(d.get("hashes", [])),
                bad_ips=set(d.get("bad_ips", [])),
                bad_domains=set(d.get("bad_domains", [])),
                updated=d.get("updated", 0.0),
                sources=d.get("sources", {}),
            )
        except Exception:  # noqa: BLE001
            return cls()

    def save(self) -> None:
        os.makedirs(APP_DIR, exist_ok=True)
        d = {
            "hashes": sorted(self.hashes),
            "bad_ips": sorted(self.bad_ips),
            "bad_domains": sorted(self.bad_domains),
            "updated": self.updated,
            "sources": self.sources,
        }
        tmp = DB_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f)
        os.replace(tmp, DB_PATH)

    @property
    def total(self) -> int:
        return len(self.hashes) + len(self.bad_ips) + len(self.bad_domains)

    def is_stale(self, hours: int = 24) -> bool:
        return (time.time() - self.updated) > hours * 3600


def _dl(url: str) -> str:
    txt = net.get_text(url, timeout=25)
    return txt[:MAX_LIST_BYTES]


def _parse_hostfile(text: str) -> set:
    out = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # format hostfile "0.0.0.0 domaine" ou URL brute
        for tok in re.split(r"\s+", line):
            tok = tok.strip().lower()
            m = re.match(r"https?://([^/]+)/?", tok)
            host = m.group(1) if m else tok
            host = host.split(":")[0]
            if DOMAIN_RE.match(host):
                out.add(host)
    return out


def update(db: SignatureDB, mb_key: str = "", extra_urls: list[str] | None = None,
           progress=lambda s: None) -> list[str]:
    """Met à jour la base. Renvoie un journal lisible."""
    log: list[str] = []

    # 1) Feodo — IP de C2
    try:
        progress("Feodo Tracker (C2)…")
        ips = {ln.strip() for ln in _dl(FEODO_IPS).splitlines()
               if IPV4_RE.match(ln.strip())}
        db.bad_ips |= ips
        db.sources["Feodo Tracker"] = len(ips)
        log.append(f"Feodo Tracker : {len(ips)} IP C2")
    except net.HttpError as e:
        log.append(f"Feodo Tracker : échec ({e})")

    # 2) URLhaus — domaines
    try:
        progress("URLhaus (domaines)…")
        doms = _parse_hostfile(_dl(URLHAUS_HOSTS))
        db.bad_domains |= doms
        db.sources["URLhaus"] = len(doms)
        log.append(f"URLhaus : {len(doms)} hôtes")
    except net.HttpError as e:
        log.append(f"URLhaus : échec ({e})")

    # 3) MalwareBazaar — empreintes récentes (clé gratuite requise)
    if mb_key:
        try:
            progress("MalwareBazaar (empreintes)…")
            body = net.post_form(
                "https://mb-api.abuse.ch/api/v1/",
                {"query": "get_recent", "selector": "time"},
                headers={"Auth-Key": mb_key}, timeout=30)
            data = json.loads(body)
            got = set()
            for item in data.get("data", [])[:1000]:
                h = (item.get("sha256_hash") or "").lower()
                if SHA256_RE.fullmatch(h):
                    got.add(h)
            db.hashes |= got
            db.sources["MalwareBazaar"] = len(got)
            log.append(f"MalwareBazaar : {len(got)} empreintes")
        except Exception as e:  # noqa: BLE001
            log.append(f"MalwareBazaar : échec ({e})")
    else:
        log.append("MalwareBazaar : désactivé (pas de clé)")

    # 4) Listes supplémentaires (reconnaissance de format automatique)
    for url in (extra_urls or [])[:10]:
        try:
            progress(f"Liste : {url[:40]}…")
            txt = _dl(url)
            h = {m.lower() for m in SHA256_RE.findall(txt)}
            d = _parse_hostfile(txt)
            db.hashes |= h
            db.bad_domains |= d
            log.append(f"{url[:40]} : {len(h)} empreintes, {len(d)} hôtes")
        except net.HttpError as e:
            log.append(f"{url[:40]} : échec ({e})")

    db.updated = time.time()
    try:
        db.save()
    except Exception as e:  # noqa: BLE001
        log.append(f"Enregistrement : échec ({e})")
    return log
