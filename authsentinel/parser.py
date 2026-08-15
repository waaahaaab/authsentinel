"""
parser.py — Transforme une ligne brute de /var/log/auth.log
en objet Python structuré (AuthEvent).

Format des logs cible : Ubuntu 26.04 (rsyslog moderne, ISO 8601)
Exemple de ligne brute :
2026-08-05T21:12:53.922295+01:00 WAHAB sshd-session[31772]: Failed password for wahab from 127.0.0.1 port 34612 ssh2
"""

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class AuthEvent:
    """Représente un événement d'authentification structuré."""
    timestamp: datetime       # date/heure de l'événement
    event_type: str           # ex: "failed_password", "accepted_password", "sudo_command", etc.
    user: Optional[str] = None       # utilisateur concerné (si applicable)
    ip: Optional[str] = None         # adresse IP source (si applicable, ex: connexions SSH)
    raw_line: str = ""        # la ligne brute d'origine, gardée pour debug/audit


# --- Expressions régulières pour chaque pattern ---
# On les compile à l'avance (re.compile) pour de meilleures performances,
# car ces regex seront réutilisées sur des milliers de lignes.

RE_TIMESTAMP = re.compile(r'^(\S+)\s+\S+\s+(.*)$')
# \S+ (1er groupe) = le timestamp ISO 8601 (ex: 2026-08-05T21:12:53.922295+01:00)
# \S+ (non capturé) = le hostname (ex: WAHAB), qu'on ignore pour l'instant
# (.*) (2e groupe)  = le reste de la ligne (process[PID]: message...)

RE_FAILED_PASSWORD = re.compile(
    r'sshd(?:-session)?\[\d+\]: Failed password for (\S+) from (\S+)'
)
RE_ACCEPTED_PASSWORD = re.compile(
    r'sshd(?:-session)?\[\d+\]: Accepted password for (\S+) from (\S+)'
)
RE_SUDO_COMMAND = re.compile(
    r'sudo:\s+(\S+)\s+:.*COMMAND=(.+)$'
)
RE_NEW_USER = re.compile(
    r'useradd\[\d+\]: new user: name=(\S+?),'
)
RE_FAILED_SU = re.compile(
    r'su\[\d+\]: FAILED SU \(to (\S+)\) (\S+) on'
)
RE_SESSION_OPENED = re.compile(
    r'pam_unix\(\S+:session\): session opened for user ([^\s(]+)'
)
RE_SESSION_CLOSED = re.compile(
    r'pam_unix\(\S+:session\): session closed for user (\S+)'
)


def parse_timestamp(raw_ts: str) -> datetime:
    """
    Convertit le timestamp ISO 8601 (avec microsecondes et timezone)
    en objet datetime Python.

    Ex: "2026-08-05T21:12:53.922295+01:00" -> datetime(...)
    """
    return datetime.fromisoformat(raw_ts)


def parse_line(line: str) -> Optional[AuthEvent]:
    """
    Transforme une ligne brute de auth.log en AuthEvent structuré.
    Retourne None si la ligne ne correspond à aucun pattern connu
    (ex: bruit, événement non pertinent pour la détection d'intrusion).
    """
    line = line.strip()
    if not line:
        return None

    # Étape 1 : extraire le timestamp et le reste du message
    ts_match = RE_TIMESTAMP.match(line)
    if not ts_match:
        return None  # ligne malformée, on ne sait pas la parser

    raw_ts, rest = ts_match.groups()

    try:
        timestamp = parse_timestamp(raw_ts)
    except ValueError:
        return None  # timestamp illisible, on ignore la ligne

    # Étape 2 : tester chaque pattern connu, dans un ordre précis
    # (les patterns les plus spécifiques d'abord pour éviter les faux positifs)

    m = RE_FAILED_PASSWORD.search(rest)
    if m:
        return AuthEvent(
            timestamp=timestamp,
            event_type="failed_password",
            user=m.group(1),
            ip=m.group(2),
            raw_line=line,
        )

    m = RE_ACCEPTED_PASSWORD.search(rest)
    if m:
        return AuthEvent(
            timestamp=timestamp,
            event_type="accepted_password",
            user=m.group(1),
            ip=m.group(2),
            raw_line=line,
        )

    m = RE_FAILED_SU.search(rest)
    if m:
        return AuthEvent(
            timestamp=timestamp,
            event_type="failed_su",
            user=m.group(2),   # l'utilisateur qui a tenté le su
            ip=None,           # pas d'IP pertinente pour un su local
            raw_line=line,
        )

    m = RE_NEW_USER.search(rest)
    if m:
        return AuthEvent(
            timestamp=timestamp,
            event_type="new_user",
            user=m.group(1),
            ip=None,
            raw_line=line,
        )

    m = RE_SUDO_COMMAND.search(rest)
    if m:
        return AuthEvent(
            timestamp=timestamp,
            event_type="sudo_command",
            user=m.group(1),
            ip=None,
            raw_line=line,
        )

    m = RE_SESSION_OPENED.search(rest)
    if m:
        return AuthEvent(
            timestamp=timestamp,
            event_type="session_opened",
            user=m.group(1),
            ip=None,
            raw_line=line,
        )

    m = RE_SESSION_CLOSED.search(rest)
    if m:
        return AuthEvent(
            timestamp=timestamp,
            event_type="session_closed",
            user=m.group(1),
            ip=None,
            raw_line=line,
        )

    # Aucun pattern connu ne correspond : ligne ignorée (bruit)
    return None