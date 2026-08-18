"""
rules.py — Définit les règles de détection d'intrusion.

Chaque règle reçoit les AuthEvent produits par parser.py et décide
si elle déclenche une alerte (Alert) ou non.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from authsentinel.parser import AuthEvent


@dataclass
class Alert:
    """Représente une alerte de sécurité déclenchée par une règle."""
    severity: str       # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    rule_name: str       # ex: "BruteForce SSH"
    message: str          # description lisible de l'alerte
    timestamp: datetime   # moment de la détection
    source_event: AuthEvent  # l'événement qui a déclenché l'alerte


class Rule(ABC):
    """
    Classe abstraite : le "contrat" que toute règle de détection doit respecter.
    Une règle ne fait qu'une chose : recevoir un événement, et dire si
    ça déclenche une alerte ou non.
    """

    @abstractmethod
    def check(self, event: AuthEvent) -> Optional[Alert]:
        """
        Analyse un événement et retourne une Alert si un comportement
        suspect est détecté, sinon None.
        """
        raise NotImplementedError


class BruteForceRule(Rule):
    """
    Détecte une attaque par force brute SSH :
    déclenche une alerte si `max_attempts` échecs de connexion
    proviennent de la même IP en moins de `window_seconds` secondes.
    """

    def __init__(self, max_attempts: int = 5, window_seconds: int = 60):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        # Historique des échecs par IP : { "1.2.3.4": [timestamp1, timestamp2, ...] }
        self._failed_attempts_by_ip: dict[str, list[datetime]] = {}

    def check(self, event: AuthEvent) -> Optional[Alert]:
        # Cette règle ne s'intéresse qu'aux échecs de connexion SSH
        if event.event_type != "failed_password":
            return None

        ip = event.ip
        if ip is None:
            return None  # pas d'IP exploitable, on ignore

        # Récupère l'historique existant pour cette IP (liste vide si nouvelle IP)
        history = self._failed_attempts_by_ip.setdefault(ip, [])
        history.append(event.timestamp)

        # Nettoie l'historique : ne garde que les tentatives dans la fenêtre de temps
        cutoff = event.timestamp.timestamp() - self.window_seconds
        history[:] = [ts for ts in history if ts.timestamp() >= cutoff]

        # Vérifie si le seuil est dépassé
        if len(history) >= self.max_attempts:
            return Alert(
                severity="CRITICAL",
                rule_name="BruteForce SSH",
                message=(
                    f"{len(history)} tentatives de connexion echouees "
                    f"depuis {ip} en moins de {self.window_seconds}s"
                ),
                timestamp=event.timestamp,
                source_event=event,
            )

        return None