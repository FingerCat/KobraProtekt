"""Accès réseau — HTTPS uniquement, délais courts, jamais vers un serveur suspect.

Comme dans l'app Android (classe Http), on n'autorise que https. Ce module sert
UNIQUEMENT à télécharger des listes publiques de signatures et à interroger des
registres publics (DNS, RDAP, AbuseIPDB). Il n'est jamais utilisé pour se
connecter à une adresse relevée comme suspecte.
"""
from __future__ import annotations
import json
import urllib.request
import urllib.error

USER_AGENT = "KobraProtekt/1.0 (+defensive-scanner)"


class HttpError(Exception):
    pass


def _open(url: str, headers: dict | None = None, data: bytes | None = None,
          timeout: int = 20):
    if not url.lower().startswith("https://"):
        raise HttpError("Seul https est autorisé : " + url)
    req = urllib.request.Request(url, data=data)
    req.add_header("User-Agent", USER_AGENT)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    return urllib.request.urlopen(req, timeout=timeout)


def get_text(url: str, headers: dict | None = None, timeout: int = 20) -> str:
    try:
        with _open(url, headers, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        raise HttpError(f"HTTP {e.code}")
    except Exception as e:  # noqa: BLE001
        raise HttpError(str(e))


def get_json(url: str, headers: dict | None = None, timeout: int = 20):
    return json.loads(get_text(url, headers, timeout))


def post_form(url: str, fields: dict, headers: dict | None = None,
              timeout: int = 20):
    import urllib.parse
    body = urllib.parse.urlencode(fields).encode()
    h = {"Content-Type": "application/x-www-form-urlencoded"}
    h.update(headers or {})
    try:
        with _open(url, h, data=body, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        raise HttpError(f"HTTP {e.code}: {e.read().decode('utf-8','replace')[:200]}")
    except Exception as e:  # noqa: BLE001
        raise HttpError(str(e))
