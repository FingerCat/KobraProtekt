"""Enquête — désigne l'INFRASTRUCTURE (serveurs, hébergeur), jamais une personne.

Port de Investigator + core/RdapParser + core/AbuseIpDbParser.

Important, repris de l'app Android :
  • On n'identifie pas une personne : on désigne des serveurs et leur hébergeur.
    Seule une enquête officielle peut obtenir l'identité du client.
  • On ne se connecte JAMAIS au serveur suspect. On interroge seulement des
    registres publics : résolution DNS, RDAP (rdap.org), et AbuseIPDB (clé).
  • L'identité d'un certificat/whois est déclarée et peut être fausse.
"""
from __future__ import annotations
import socket
from dataclasses import dataclass

from . import net


@dataclass
class IpInfo:
    ip: str = ""
    name: str = ""          # nom du réseau / netname
    handle: str = ""
    org: str = ""
    country: str = ""
    abuse_email: str = ""
    registered: str = ""


@dataclass
class Reputation:
    score: int = -1         # AbuseIPDB abuseConfidenceScore 0..100, -1 inconnu
    total_reports: int = 0
    last_reported: str = ""


def resolve(host: str) -> list[str]:
    """Résolution DNS (interroge un résolveur, ne contacte pas l'hôte suspect)."""
    ips = set()
    try:
        for fam, _, _, _, sockaddr in socket.getaddrinfo(host, None):
            ips.add(sockaddr[0])
    except Exception:  # noqa: BLE001
        pass
    return sorted(ips)


def _entities_abuse(entities, out: IpInfo):
    """Parcourt les entités RDAP pour trouver le contact d'abus (vCard)."""
    for ent in entities or []:
        roles = ent.get("roles", [])
        vcard = ent.get("vcardArray")
        email = ""
        org = ""
        if isinstance(vcard, list) and len(vcard) == 2:
            for item in vcard[1]:
                if not isinstance(item, list) or len(item) < 4:
                    continue
                if item[0] == "email":
                    email = item[3]
                elif item[0] == "fn" and not org:
                    org = item[3]
        if "abuse" in roles and email and not out.abuse_email:
            out.abuse_email = email
        if org and not out.org:
            out.org = org
        _entities_abuse(ent.get("entities"), out)


def rdap_ip(ip: str) -> IpInfo:
    info = IpInfo(ip=ip)
    try:
        d = net.get_json(f"https://rdap.org/ip/{ip}", timeout=20)
    except net.HttpError:
        return info
    info.name = d.get("name", "")
    info.handle = d.get("handle", "")
    info.country = d.get("country", "")
    for ev in d.get("events", []):
        if ev.get("eventAction") in ("registration", "last changed") and not info.registered:
            info.registered = ev.get("eventDate", "")[:10]
    _entities_abuse(d.get("entities"), info)
    return info


def rdap_domain(domain: str) -> dict:
    try:
        return net.get_json(f"https://rdap.org/domain/{domain}", timeout=20)
    except net.HttpError:
        return {}


def abuseipdb(ip: str, key: str) -> Reputation:
    if not key:
        return Reputation()
    try:
        d = net.get_json(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
            headers={"Key": key, "Accept": "application/json"}, timeout=20)
        data = d.get("data", {})
        return Reputation(
            score=int(data.get("abuseConfidenceScore", -1)),
            total_reports=int(data.get("totalReports", 0)),
            last_reported=(data.get("lastReportedAt") or "")[:10])
    except Exception:  # noqa: BLE001
        return Reputation()


@dataclass
class Investigation:
    indicator: str            # IP ou domaine relevé
    ips: list
    net_info: IpInfo
    reputation: Reputation
    is_ip: bool


def investigate(indicator: str, abuse_key: str = "") -> Investigation:
    indicator = indicator.strip()
    is_ip = all(p.isdigit() for p in indicator.split(".")) and indicator.count(".") == 3
    ips = [indicator] if is_ip else resolve(indicator)
    primary = ips[0] if ips else ""
    net_info = rdap_ip(primary) if primary else IpInfo()
    rep = abuseipdb(primary, abuse_key) if primary else Reputation()
    return Investigation(indicator=indicator, ips=ips, net_info=net_info,
                         reputation=rep, is_ip=is_ip)
