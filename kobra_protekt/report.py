"""Signalement — compile le dossier de preuves puis prépare l'envoi.

Conforme au choix validé : l'app trace l'hébergeur, compile AUTOMATIQUEMENT le
dossier (RDAP/DNS/géo/réputation) et pré-remplit le signalement, mais
n'envoie RIEN sans la validation de la personne (un clic). Garde-fous de
ReportPolicy appliqués en amont.

Trois canaux, tous relus avant départ :
  • Hébergeur : courriel pré-rédigé (mailto) vers le contact d'abus.
  • AbuseIPDB : publication via l'API, seulement après confirmation.
  • France : ouverture de cybermalveillance.gouv.fr pour le dépôt officiel.
"""
from __future__ import annotations
import datetime
import urllib.parse

from . import net
from .investigate import Investigation
from .scanner import Finding

CYBERMALVEILLANCE = "https://www.cybermalveillance.gouv.fr/diagnostic"
PLAINTE_INFO = "https://www.service-public.fr/particuliers/vosdroits/F34059"


def build_dossier(finding: Finding, inv: Investigation) -> str:
    """Rapport texte à conserver comme preuve (équivalent « Partager le rapport »)."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    L = []
    L.append("=" * 60)
    L.append("KOBRA PROTEKT — DOSSIER DE PREUVES")
    L.append(f"Établi le {now}")
    L.append("=" * 60)
    L.append("")
    L.append("MENACE DÉTECTÉE")
    L.append(f"  Élément       : {finding.title}")
    if finding.path:
        L.append(f"  Emplacement   : {finding.path}")
    if finding.sha256:
        L.append(f"  Empreinte     : SHA-256 {finding.sha256}")
    if finding.pid:
        L.append(f"  Processus     : PID {finding.pid}")
    L.append(f"  Verdict       : {'MENACE CONFIRMÉE' if finding.confirmed else 'À VÉRIFIER'}")
    for r in finding.reasons:
        L.append(f"  Raison        : {r}")
    L.append("")
    L.append("INFRASTRUCTURE RELEVÉE (serveurs, hébergeur — pas une personne)")
    L.append(f"  Indicateur    : {inv.indicator}")
    if inv.ips:
        L.append(f"  Adresse(s) IP : {', '.join(inv.ips)}")
    n = inv.net_info
    if n and n.ip:
        L.append(f"  Réseau        : {n.name or '—'} ({n.handle or '—'})")
        L.append(f"  Hébergeur     : {n.org or '—'}")
        L.append(f"  Pays          : {n.country or '—'}")
        L.append(f"  Enregistré    : {n.registered or '—'}")
        L.append(f"  Contact abus  : {n.abuse_email or '—'}")
    rep = inv.reputation
    if rep and rep.score >= 0:
        L.append(f"  AbuseIPDB     : score {rep.score}/100, {rep.total_reports} signalement(s)"
                 + (f", dernier {rep.last_reported}" if rep.last_reported else ""))
    L.append("")
    L.append("MÉTHODE ET LIMITES")
    L.append("  • Fichier lu sans être exécuté ; aucune connexion au serveur suspect.")
    L.append("  • Infrastructure identifiée via DNS et RDAP (registres publics).")
    L.append("  • Une IP ne prouve pas l'identité d'une personne : usurpation,")
    L.append("    partage NAT, machine tierce compromise sont possibles.")
    L.append("  • Seule une enquête officielle peut obtenir l'identité du client")
    L.append("    auprès de l'hébergeur (France : plainte / cybermalveillance.gouv.fr).")
    L.append("=" * 60)
    return "\n".join(L)


def abuse_email_mailto(inv: Investigation, dossier: str) -> str:
    """Courriel pré-rédigé (en anglais) vers le contact d'abus de l'hébergeur."""
    to = inv.net_info.abuse_email or ""
    subject = f"Abuse report: malicious host {inv.indicator}"
    body = (
        "Hello,\n\n"
        f"The following host on your network appears to be used for malicious "
        f"activity (malware command-and-control / distribution): {inv.indicator}"
        + (f" ({', '.join(inv.ips)})" if inv.ips else "") + ".\n\n"
        "Evidence collected locally (the suspect host was never contacted):\n\n"
        + dossier + "\n\n"
        "Please investigate and take appropriate action.\n\nRegards,\n")
    q = urllib.parse.urlencode({"subject": subject, "body": body},
                               quote_via=urllib.parse.quote)
    return f"mailto:{to}?{q}"


def submit_abuseipdb(ip: str, comment: str, key: str,
                     categories: str = "15,20,21") -> str:
    """Publie le signalement sur AbuseIPDB. Appelé UNIQUEMENT après validation.

    Catégories : 15=Hacking, 20=Exploited Host, 21=Web App Attack (par défaut).
    """
    if not key:
        raise net.HttpError("Clé AbuseIPDB manquante (onglet Sources).")
    return net.post_form(
        "https://api.abuseipdb.com/api/v2/report",
        {"ip": ip, "categories": categories, "comment": comment[:1024]},
        headers={"Key": key, "Accept": "application/json"}, timeout=25)
