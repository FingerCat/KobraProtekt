"""Garde-fous de signalement — port fidèle de core/ReportPolicy.java.

On ne signale une adresse que si la menace est CONFIRMÉE et si l'adresse
appartient vraisemblablement au serveur malveillant lui-même. Un faux
signalement nuit à un tiers innocent.
"""
from __future__ import annotations
from enum import Enum

from .investigate import IpInfo

# Réseaux de diffusion mutualisés : la même IP sert des milliers de sites légitimes.
CDN = ("cloudflare", "akamai", "fastly", "cloudfront", "edgecast", "incapsula",
       "imperva", "bunnycdn", "bunny.net", "cdn77", "stackpath", "sucuri")

# Plateformes partagées : l'IP n'identifie pas un client particulier.
SHARED = ("firebase", "googleusercontent", "amazonaws", "azurewebsites",
          "herokuapp", "render.com", "vercel", "netlify", "github.io",
          "pages.dev", "workers.dev")


class Decision(Enum):
    ALLOWED = "allowed"
    NOT_CONFIRMED = "not_confirmed"
    SHARED_PLATFORM = "shared_platform"
    WEAK_EVIDENCE = "weak_evidence"
    CDN = "cdn"
    NO_ADDRESS = "no_address"


def is_public_ipv4(ip: str) -> bool:
    try:
        parts = [int(p) for p in ip.split(".")]
    except ValueError:
        return False
    if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
        return False
    a, b = parts[0], parts[1]
    if a in (0, 10, 127): return False
    if a == 172 and 16 <= b <= 31: return False
    if a == 192 and b == 168: return False
    if a == 169 and b == 254: return False
    if a >= 224: return False
    if a == 100 and 64 <= b <= 127: return False  # CGNAT
    return True


def is_cdn_or_shared(net_info: IpInfo) -> bool:
    if net_info is None:
        return False
    s = f"{net_info.name} {net_info.handle} {net_info.org}".lower()
    if any(c in s for c in CDN):
        return True
    if any(p in s for p in SHARED):
        return True
    # Les frontaux Google servent des services partagés ; Google Cloud non.
    return "google" in s and "cloud" not in s


def evaluate(confirmed_threat: bool, ip: str, net_info: IpInfo) -> Decision:
    if not confirmed_threat:
        return Decision.NOT_CONFIRMED
    if not ip or not is_public_ipv4(ip):
        return Decision.NO_ADDRESS
    if is_cdn_or_shared(net_info):
        # CDN vs plateforme partagée : message distinct, même refus.
        s = f"{net_info.name} {net_info.handle} {net_info.org}".lower()
        return Decision.CDN if any(c in s for c in CDN) else Decision.SHARED_PLATFORM
    return Decision.ALLOWED


HUMAN = {
    Decision.ALLOWED: "Signalement possible : menace confirmée, adresse propre au serveur.",
    Decision.NOT_CONFIRMED: "Menace non confirmée : pas de signalement (éviter d'accuser un innocent).",
    Decision.SHARED_PLATFORM: "Plateforme partagée : l'IP ne désigne pas un responsable unique.",
    Decision.WEAK_EVIDENCE: "Preuve trop faible pour signaler.",
    Decision.CDN: "Réseau de diffusion (CDN) : l'IP sert aussi des sites légitimes.",
    Decision.NO_ADDRESS: "Pas d'adresse IP publique exploitable.",
}
