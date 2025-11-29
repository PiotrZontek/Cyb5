"""
Ulepszona aplikacja Trialware z integracją Honeytoken System.
Wdraża technologię honeytokenów w różnych postaciach do monitorowania wycieku danych
i nieautoryzowanego dostępu.

Typy monitorowanych tokenów:
1. HTTP Token - monituj dostęp do API
2. DNS Token - monituj próby resolvowania domains
3. Database Token - fałszywe poświadczenia DB
4. Credential Token - fałszywe klucze odblokowujące
5. File Token - fałszywe pliki konfiguracyjne
"""

import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog, scrolledtext
from datetime import datetime
import calendar
import string
import json
import os
from pathlib import Path

# Import modułu honeytokenów
from honeytoken_system import (
    HoneytokenSystem, TokenType, AlertSeverity, HoneytokenAlert
)

# ============================================================================
# VIGENERE CIPHER
# ============================================================================

ALPHABET = string.ascii_lowercase


def normalize_text(s):
    return ''.join(ch for ch in s.lower() if ch.isalpha())


def vigenere_encrypt(plain, key):
    p = normalize_text(plain)
    k = normalize_text(key)
    if not p or not k:
        return ''
    res = []
    ki = 0
    for ch in p:
        pi = ALPHABET.index(ch)
        ki_mod = ALPHABET.index(k[ki % len(k)])
        ci = (pi + ki_mod) % len(ALPHABET)
        res.append(ALPHABET[ci])
        ki += 1
    return ''.join(res)


def vigenere_decrypt(cipher, key):
    c = normalize_text(cipher)
    k = normalize_text(key)
    if not c or not k:
        return ''
    res = []
    ki = 0
    for ch in c:
        ci = ALPHABET.index(ch)
        ki_mod = ALPHABET.index(k[ki % len(k)])
        pi = (ci - ki_mod) % len(ALPHABET)
        res.append(ALPHABET[pi])
        ki += 1
    return ''.join(res)


# ============================================================================
# TRIAL LOGIC
# ============================================================================

def trial_expired_now():
    """Zwraca True jeżeli trial wygasł (po końcu bieżącego miesiąca)"""
    now = datetime.now()
    year, month = now.year, now.month
    first_of_next_month = datetime(year + (month // 12), (month % 12) + 1, 1)
    return now >= first_of_next_month


PLAIN_UNLOCK_KEY = "unlocktrial"
EXAMPLE_SECRET = "MySecretKey"
EXAMPLE_CIPHER = vigenere_encrypt(PLAIN_UNLOCK_KEY, EXAMPLE_SECRET)


# ============================================================================
# HONEYTOKEN SETUP
# ============================================================================

def setup_honeytokens(ht_system: HoneytokenSystem):
    """Skonfiguruj honeytokeny dla aplikacji"""

    # 1. HTTP Token - monituj dostęp do API
    http_token = ht_system.create_token(
        TokenType.HTTP,
        description="API endpoint do wyświetlania plików",
        severity=AlertSeverity.HIGH
    )

    # 2. DNS Token - monituj próby resolvowania domain
    dns_token = ht_system.create_token(
        TokenType.DNS,
        description="Domena command-and-control dla hackerów",
        severity=AlertSeverity.CRITICAL
    )

    # 3. Database Token - fałszywe poświadczenia
    db_token = ht_system.create_token(
        TokenType.DATABASE,
        description="Poświadczenia bazy danych trialware",
        severity=AlertSeverity.CRITICAL
    )

    # 4. API Key Token - fałszywy klucz API
    api_token = ht_system.create_token(
        TokenType.API_KEY,
        description="Klucz API do serwisu licencyjnego",
        severity=AlertSeverity.HIGH
    )

    # 5. Credential Token - fałszywy klucz odblokowujący
    # Tworzymy token, który przypomina prawdziwy klucz
    fake_unlock_token = ht_system.create_token(
        TokenType.CREDENTIAL,
        description="Fałszywy klucz odblokowujący (honeytoken)",
        severity=AlertSeverity.CRITICAL
    )

    return {
        "http": http_token,
        "dns": dns_token,
        "database": db_token,
        "api_key": api_token,
        "fake_unlock": fake_unlock_token
    }


def on_alert_triggered(alert: HoneytokenAlert):
    """Callback wywoływany gdy honeytoken zostanie aktywowany"""
    log_alert_to_file(alert)
    print(f"\n{'=' * 70}")
    print("⚠️  HONEYTOKEN ACTIVATED!")
    print(f"{'=' * 70}")
    print(alert)
    print(f"{'=' * 70}\n")


def log_alert_to_file(alert: HoneytokenAlert):
    """Zaloguj alert do pliku"""
    log_dir = Path(".honeytokens")
    log_dir.mkdir(exist_ok=True)

    log_file = log_dir / "alerts.log"
    with open(log_file, 'a') as f:
        f.write(f"{alert}\n")
        f.write("-" * 70 + "\n\n")


# ============================================================================
# TRIALWARE GUI
# ============================================================================

class TrialApp:
    def __init__(self, root):
        self.root = root
        root.title("Trialware z Honeytokenami - Wyświetlanie Plików")
        root.geometry("900x600")

        # Inicjalizuj honeytoken system
        self.ht_system = HoneytokenSystem()
        self.honeytokens = setup_honeytokens(self.ht_system)

        # Zarejestruj callback dla alertów
        self.ht_system.register_alert_callback(on_alert_triggered)

        # GUI
        self._create_widgets()

        # Wyświetl informacje o honeytokenach
        self._show_honeytoken_info()

    def _create_widgets(self):
        """Utwórz elementy GUI"""
        # Górny panel z przyciskami
        top_frame = tk.Frame(self.root)
        top_frame.pack(pady=10)

        tk.Button(top_frame, text="📂 Wyświetl plik (TXT)",
                  command=self.open_file, width=20, font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=5)

        tk.Button(top_frame, text="ℹ️  Instrukcja",
                  command=self.show_instruction, width=15).pack(side=tk.LEFT, padx=5)

        tk.Button(top_frame, text="🔍 Status Honeytokenów",
                  command=self.show_honeytoken_status, width=20).pack(side=tk.LEFT, padx=5)

        # Główne pole tekstowe
        self.text_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, font=("Courier", 10))
        self.text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Dolny panel z informacjami
        bottom_frame = tk.Frame(self.root, bg="lightgray", height=80)
        bottom_frame.pack(fill=tk.X, padx=10, pady=5)

        self.status_label = tk.Label(bottom_frame, text="", justify=tk.LEFT, bg="lightgray")
        self.status_label.pack(anchor=tk.W, padx=10, pady=5)

        self._update_status_label()

    def _show_honeytoken_info(self):
        """Wyświetl informacje o honeytokenach w polu tekstowym"""
        info = (
            "╔════════════════════════════════════════════════════════════════════╗\n"
            "║         APLIKACJA TRIALWARE Z HONEYTOKENAMI (Ćwiczenie 4+6)       ║\n"
            "╚════════════════════════════════════════════════════════════════════╝\n\n"
            "📋 FUNKCJE APLIKACJI:\n"
            "  • Wyświetlanie plików tekstowych\n"
            "  • Trial do końca bieżącego miesiąca\n"
            "  • Odblokowywanie poprzez szyfr Vigenère'a\n"
            "  • Monitorowanie wycieku danych za pomocą honeytokenów\n\n"
            "🍯 ZINTEGROWANE HONEYTOKENY:\n"
        )

        # Dodaj informacje o tokenach
        for token_name, token in self.honeytokens.items():
            info += f"\n  [{token.token_type.value.upper()}] {token.description}\n"
            info += f"    ID: {token.token_id}\n"
            info += f"    Wartość: {token.value}\n"
            info += f"    Poważność: {token.severity.value}\n"

        info += (
                "\n\n🔐 KLUCZ ODBLOKOWUJĄCY (PRZYKŁAD):\n"
                f"  Zaszyfrowany klucz: {EXAMPLE_CIPHER}\n"
                f"  Sekret producenta: {EXAMPLE_SECRET}\n\n"
                "⚠️  MONITOROWANIE HONEYTOKENÓW:\n"
                "  System automatycznie rejestruje każdy atak próbujący użyć\n"
                "  fałszywych poświadczeń lub tokenu. Wszystkie alerty są logowane\n"
                "  w pliku .honeytokens/alerts.log\n\n"
                "─" * 70 + "\n\n"
        )

        self.text_area.delete(1.0, tk.END)
        self.text_area.insert(tk.END, info)

    def show_instruction(self):
        """Pokaż instrukcję użytkowania"""
        instruction = (
            "INSTRUKCJA OBSŁUGI:\n\n"
            "1️⃣  UŻYTKOWNIK W TRIAL:\n"
            "   - Kliknij 'Wyświetl plik (TXT)' i wybierz plik\n"
            "   - Plik zostanie wyświetlony natychmiast (trial aktywny)\n\n"
            "2️⃣  TRIAL WYGASŁ:\n"
            "   - System zablokuje dostęp do funkcji\n"
            "   - Zostaniesz poproszony o klucz odblokowujący\n"
            "   - Wpisz zaszyfrowany klucz i sekret\n\n"
            "3️⃣  ATAK / PRÓBA WYCIEKU:\n"
            "   - Jeśli atakujący spróbuje użyć fałszywych tokenów\n"
            "   - System automatycznie wyzwoli alert\n"
            "   - Alert zostanie zarejestrowany w .honeytokens/alerts.log\n"
            "   - Informacja o zagrożeniu pojawi się w aplikacji\n\n"
            "4️⃣  MONITOROWANIE:\n"
            "   - Kliknij 'Status Honeytokenów' aby zobaczyć aktywne ataki\n"
            "   - Przejrzyj plik alerts.log aby zobaczyć historię\n"
        )
        messagebox.showinfo("Instrukcja", instruction)

    def show_honeytoken_status(self):
        """Pokaż status honeytokenów i aktywne alerty"""
        summary = self.ht_system.get_alert_summary()

        status_info = (
            "═══════════════════════════════════════════\n"
            "📊 STATUS HONEYTOKENÓW\n"
            "═══════════════════════════════════════════\n\n"
            f"Całkowita liczba tokenów: {summary['total_tokens']}\n"
            f"Aktywowane tokeny: {summary['activated_tokens']}\n\n"
            "ALERTY:\n"
            f"  • Wszystkie: {summary['total_alerts']}\n"
            f"  • Krytyczne: {summary['critical_alerts']}\n"
            f"  • Wysokie: {summary['high_alerts']}\n\n"
            "OSTATNIE ALERTY:\n"
        )

        if summary['recent_alerts']:
            for alert in summary['recent_alerts']:
                status_info += (
                    f"\n  [{alert['severity'].upper()}] {alert['token_type']}\n"
                    f"  {alert['message']}\n"
                    f"  Czas: {alert['timestamp']}\n"
                )
        else:
            status_info += "\n  Brak alertów (bezpieczna sesja)\n"

        status_info += "\n═══════════════════════════════════════════\n"

        self.text_area.delete(1.0, tk.END)
        self.text_area.insert(tk.END, status_info)

    def _update_status_label(self):
        """Aktualizuj etykietę statusu"""
        summary = self.ht_system.get_alert_summary()

        trial_status = "✅ AKTYWNY" if not trial_expired_now() else "❌ WYGASŁY"
        alert_status = "⚠️  ALERTY WYKRYTE!" if summary['total_alerts'] > 0 else "✅ OK"

        status_text = (
            f"Trial: {trial_status}  |  "
            f"Honeytokeny: {summary['total_tokens']}  |  "
            f"Alerty: {alert_status}"
        )
        self.status_label.config(text=status_text)

    def open_file(self):
        """Otwórz plik tekstowy"""
        # Sprawdzenie obcego dostępu
        self._check_for_honeypot_access()

        path = filedialog.askopenfilename(filetypes=[("Pliki tekstowe", "*.txt")])
        if not path:
            return

        if not trial_expired_now():
            # Trial aktywny: pokaż zawartość
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
            except Exception as e:
                messagebox.showerror("Błąd", f"Nie można otworzyć pliku:\n{e}")
                return

            self.text_area.delete(1.0, tk.END)
            self.text_area.insert(tk.END, content)
            messagebox.showinfo("Sukces", "✅ Plik wyświetlony (trial aktywny).")
            return

        # Trial wygasł -> wymagamy klucza
        messagebox.showwarning("Blokada",
                               "❌ Trial wygasł — funkcja wyświetlania zablokowana.\n"
                               "Aby odblokować tymczasowo, wprowadź zaszyfrowany klucz od producenta.")

        cipher_input = simpledialog.askstring("Klucz odblokowujący", "Wklej zaszyfrowany klucz:")
        if not cipher_input:
            return

        secret_input = simpledialog.askstring("Sekret producenta",
                                              "Wprowadź sekret (hasło) użyty do szyfrowania:", show='*')
        if not secret_input:
            return

        # Sprawdzenie czy podany klucz to honeytoken
        self._check_honeypot_unlock_key(cipher_input, secret_input)

        # Odszyfruj i sprawdź
        plain_attempt = vigenere_decrypt(cipher_input, secret_input)
        if plain_attempt == normalize_text(PLAIN_UNLOCK_KEY):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
            except Exception as e:
                messagebox.showerror("Błąd", f"Nie można otworzyć pliku:\n{e}")
                return

            self.text_area.delete(1.0, tk.END)
            self.text_area.insert(tk.END, content)
            messagebox.showinfo("Odblokowano", "✅ Prawidłowy klucz — plik wyświetlony.")
        else:
            messagebox.showerror("Niepoprawny klucz",
                                 "❌ Podany klucz/sekret nie jest prawidłowy.")

    def _check_for_honeypot_access(self):
        """Monituj czy ktoś próbuje użyć honeypot tokenów"""
        context = {
            "action": "file_access_attempt",
            "timestamp": datetime.now().isoformat(),
            "user_type": "unknown"
        }

        # Symulacja monitorowania zasobów
        # W rzeczywistej aplikacji moglibyśmy tutaj sprawdzać logi sieciowe itp.

        self._update_status_label()

    def _check_honeypot_unlock_key(self, cipher_input: str, secret_input: str):
        """Sprawdzenie czy użytkownik podał fałszywy klucz odblokowujący"""
        # Sprawdź czy podany cipher to honeytoken
        fake_unlock = self.honeytokens["fake_unlock"]

        if cipher_input == fake_unlock.value:
            # Aktywuj honeytoken
            alert = self.ht_system.activate_token(
                fake_unlock.token_id,
                context={
                    "action": "fake_unlock_key_used",
                    "cipher_input": cipher_input,
                    "secret_input": secret_input,
                    "timestamp": datetime.now().isoformat()
                }
            )

            messagebox.showwarning("⚠️  OSTRZEŻENIE BEZPIECZEŃSTWA",
                                   "System wykrył próbę użycia fałszywego klucza odblokowującego!\n"
                                   "To zdarzenie zostało zarejestrowane i raportowane.")

        self._update_status_label()


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    root = tk.Tk()
    app = TrialApp(root)
    root.mainloop()
