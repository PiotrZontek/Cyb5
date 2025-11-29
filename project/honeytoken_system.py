"""
Lokalny system Honeytoken do monitorowania wycieku danych i nieautoryzowanego dostępu.
Implementuje różne typy tokenów: HTTP, DNS, File, Database, Credential.
"""

import json
import hashlib
import secrets
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from enum import Enum
import urllib.parse


class TokenType(Enum):
    """Typy dostępnych honeytokenów"""
    HTTP = "http"
    DNS = "dns"
    FILE = "file"
    DATABASE = "database"
    CREDENTIAL = "credential"
    API_KEY = "api_key"


class AlertSeverity(Enum):
    """Poziomy zagrożenia"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HoneytokenAlert:
    """Pojedynczy alert o aktywacji honeytokenu"""

    def __init__(self, token_id: str, token_type: TokenType, severity: AlertSeverity,
                 message: str, context: Dict[str, Any] = None):
        self.token_id = token_id
        self.token_type = token_type
        self.severity = severity
        self.message = message
        self.timestamp = datetime.now()
        self.context = context or {}

    def to_dict(self) -> Dict:
        return {
            "token_id": self.token_id,
            "token_type": self.token_type.value,
            "severity": self.severity.value,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "context": self.context
        }

    def __str__(self) -> str:
        return (
            f"[{self.severity.value.upper()}] Token '{self.token_id}' aktywowany\n"
            f"Typ: {self.token_type.value}\n"
            f"Czas: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Wiadomość: {self.message}\n"
            f"Kontekst: {json.dumps(self.context, indent=2, ensure_ascii=False)}"
        )


class Honeytoken:
    """Pojedynczy honeytoken"""

    def __init__(self, token_id: str, token_type: TokenType, value: str,
                 description: str = "", severity: AlertSeverity = AlertSeverity.MEDIUM):
        self.token_id = token_id
        self.token_type = token_type
        self.value = value
        self.description = description
        self.severity = severity
        self.created_at = datetime.now()
        self.activated = False
        self.activation_attempts = []

    def record_activation(self, context: Dict[str, Any] = None) -> HoneytokenAlert:
        """Zanotuj aktywację tokenu i zwróć alert"""
        self.activated = True
        attempt_info = {
            "timestamp": datetime.now().isoformat(),
            "context": context or {}
        }
        self.activation_attempts.append(attempt_info)

        alert = HoneytokenAlert(
            self.token_id,
            self.token_type,
            self.severity,
            f"Honeytoken '{self.description}' został aktywowany!",
            context
        )
        return alert

    def to_dict(self) -> Dict:
        return {
            "token_id": self.token_id,
            "token_type": self.token_type.value,
            "value": self.value,
            "description": self.description,
            "severity": self.severity.value,
            "created_at": self.created_at.isoformat(),
            "activated": self.activated,
            "activation_count": len(self.activation_attempts)
        }


class HoneytokenSystem:
    """Główny system zarządzania honeytokenami"""

    def __init__(self, storage_dir: str = ".honeytokens"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(exist_ok=True)

        self.tokens: Dict[str, Honeytoken] = {}
        self.alerts: List[HoneytokenAlert] = []
        self.alert_callbacks: List[callable] = []

        self._load_tokens()

    def create_token(self, token_type: TokenType, description: str = "",
                     severity: AlertSeverity = AlertSeverity.MEDIUM) -> Honeytoken:
        """Utwórz nowy honeytoken"""
        token_id = f"token_{secrets.token_hex(8)}"

        # Generuj wartość tokenu w zależności od typu
        if token_type == TokenType.HTTP:
            value = self._generate_http_token(token_id)
        elif token_type == TokenType.DNS:
            value = self._generate_dns_token(token_id)
        elif token_type == TokenType.API_KEY:
            value = self._generate_api_key_token()
        elif token_type == TokenType.DATABASE:
            value = self._generate_database_token()
        else:
            value = secrets.token_urlsafe(32)

        token = Honeytoken(token_id, token_type, value, description, severity)
        self.tokens[token_id] = token
        self._save_tokens()

        return token

    def _generate_http_token(self, token_id: str) -> str:
        """Generuj HTTP token (URL)"""
        return f"http://localhost:8888/api/honeytoken/{token_id}"

    def _generate_dns_token(self, token_id: str) -> str:
        """Generuj DNS token (domena)"""
        return f"{token_id}.honeytoken.local"

    def _generate_api_key_token(self) -> str:
        """Generuj fałszywy klucz API"""
        return f"sk_{secrets.token_hex(32)}"

    def _generate_database_token(self) -> str:
        """Generuj fałszywe poświadczenia bazy danych"""
        return f"dbuser_{secrets.token_hex(8)}:pwd_{secrets.token_hex(8)}"

    def activate_token(self, token_id: str, context: Dict[str, Any] = None) -> Optional[HoneytokenAlert]:
        """Aktywuj honeytoken (symulacja aktywacji/narażenia)"""
        if token_id not in self.tokens:
            return None

        token = self.tokens[token_id]
        alert = token.record_activation(context)
        self.alerts.append(alert)
        self._save_tokens()
        self._trigger_alert_callbacks(alert)

        return alert

    def check_token_value(self, value: str, context: Dict[str, Any] = None) -> Optional[HoneytokenAlert]:
        """Sprawdź czy podana wartość pasuje do któregoś z tokenów"""
        for token_id, token in self.tokens.items():
            if token.value == value:
                return self.activate_token(token_id, context)
        return None

    def register_alert_callback(self, callback: callable):
        """Zarejestruj callback wywoływany przy aktywacji tokenu"""
        self.alert_callbacks.append(callback)

    def _trigger_alert_callbacks(self, alert: HoneytokenAlert):
        """Wyzwól wszystkie zarejestrowane callbacki"""
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                print(f"Błąd w alert callback: {e}")

    def get_alert_summary(self) -> Dict[str, Any]:
        """Podsumowanie alertów"""
        return {
            "total_alerts": len(self.alerts),
            "critical_alerts": sum(1 for a in self.alerts if a.severity == AlertSeverity.CRITICAL),
            "high_alerts": sum(1 for a in self.alerts if a.severity == AlertSeverity.HIGH),
            "activated_tokens": sum(1 for t in self.tokens.values() if t.activated),
            "total_tokens": len(self.tokens),
            "recent_alerts": [a.to_dict() for a in self.alerts[-10:]]
        }

    def get_token(self, token_id: str) -> Optional[Honeytoken]:
        """Pobierz token po ID"""
        return self.tokens.get(token_id)

    def list_tokens(self) -> List[Dict]:
        """Wylistuj wszystkie tokeny"""
        return [t.to_dict() for t in self.tokens.values()]

    def list_alerts(self) -> List[Dict]:
        """Wylistuj wszystkie alerty"""
        return [a.to_dict() for a in self.alerts]

    def _save_tokens(self):
        """Zapisz tokeny do pliku"""
        data = {
            "tokens": {tid: t.to_dict() for tid, t in self.tokens.items()},
            "alerts": [a.to_dict() for a in self.alerts]
        }
        tokens_file = self.storage_dir / "tokens.json"
        with open(tokens_file, 'w') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _load_tokens(self):
        """Wczytaj tokeny z pliku"""
        tokens_file = self.storage_dir / "tokens.json"
        if not tokens_file.exists():
            return

        try:
            with open(tokens_file, 'r') as f:
                data = json.load(f)

            # Rekonstruuj tokeny (uproszczony format)
            for token_id, token_data in data.get("tokens", {}).items():
                token = Honeytoken(
                    token_data["token_id"],
                    TokenType(token_data["token_type"]),
                    token_data["value"],
                    token_data["description"],
                    AlertSeverity(token_data["severity"])
                )
                self.tokens[token_id] = token
        except Exception as e:
            print(f"Błąd wczytywania tokenów: {e}")

    def export_report(self, filename: str = "honeytoken_report.json"):
        """Eksportuj raport o tokenach i alertach"""
        report = {
            "generated_at": datetime.now().isoformat(),
            "summary": self.get_alert_summary(),
            "tokens": self.list_tokens(),
            "alerts": self.list_alerts()
        }

        report_path = self.storage_dir / filename
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        return str(report_path)
