"""
Konsolowa demonstracja Honeytokenów w aplikacji Trialware.
Umożliwia testowanie różnych scenariuszy ataków i monitorowania.
"""

import string
from datetime import datetime
from honeytoken_system import HoneytokenSystem, TokenType, AlertSeverity

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


PLAIN_UNLOCK_KEY = "unlocktrial"
EXAMPLE_SECRET = "MySecretKey"
EXAMPLE_CIPHER = vigenere_encrypt(PLAIN_UNLOCK_KEY, EXAMPLE_SECRET)


# ============================================================================
# HONEYTOKEN DEMO
# ============================================================================

def print_header(title):
    """Wyświetl nagłówek"""
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}\n")


def print_success(msg):
    """Wyświetl komunikat sukcesu"""
    print(f"✅ {msg}")


def print_warning(msg):
    """Wyświetl ostrzeżenie"""
    print(f"⚠️  {msg}")


def print_error(msg):
    """Wyświetl błąd"""
    print(f"❌ {msg}")


def print_info(msg):
    """Wyświetl informację"""
    print(f"ℹ️  {msg}")


def setup_honeytokens(ht_system):
    """Skonfiguruj honeytokeny"""
    print_info("Konfigurowanie honeytokenów...")

    tokens = {}

    # HTTP Token
    tokens['http'] = ht_system.create_token(
        TokenType.HTTP,
        description="API endpoint do wyświetlania plików",
        severity=AlertSeverity.HIGH
    )
    print_success(f"HTTP Token: {tokens['http'].value}")

    # DNS Token
    tokens['dns'] = ht_system.create_token(
        TokenType.DNS,
        description="Domena command-and-control",
        severity=AlertSeverity.CRITICAL
    )
    print_success(f"DNS Token: {tokens['dns'].value}")

    # Database Token
    tokens['db'] = ht_system.create_token(
        TokenType.DATABASE,
        description="Poświadczenia bazy danych",
        severity=AlertSeverity.CRITICAL
    )
    print_success(f"Database Token: {tokens['db'].value}")

    # API Key Token
    tokens['api'] = ht_system.create_token(
        TokenType.API_KEY,
        description="Klucz API do serwisu licencyjnego",
        severity=AlertSeverity.HIGH
    )
    print_success(f"API Key Token: {tokens['api'].value}")

    # Fake Unlock Token
    tokens['unlock'] = ht_system.create_token(
        TokenType.CREDENTIAL,
        description="Fałszywy klucz odblokowujący",
        severity=AlertSeverity.CRITICAL
    )
    print_success(f"Fake Unlock Token: {tokens['unlock'].value}")

    return tokens


def demo_scenario_1(ht_system, tokens):
    """Scenariusz 1: Atakujący próbuje użyć fałszywych poświadczeń DB"""
    print_header("SCENARIUSZ 1: Próba dostępu do bazy danych za pomocą honeypot credentials")

    db_token = tokens['db']
    print_info(f"Honeytoken bazy danych: {db_token.value}")
    print_info("Atakujący próbuje zalogować się do bazy...")

    # Sprawdzenie czy podane poświadczenia pasują do honeytokenu
    alert = ht_system.check_token_value(
        db_token.value,
        context={
            "attack_type": "unauthorized_database_access",
            "credentials": db_token.value,
            "timestamp": datetime.now().isoformat()
        }
    )

    if alert:
        print_error("ATAK WYKRYTY!")
        print(f"Token ID: {alert.token_id}")
        print(f"Severość: {alert.severity.value}")
        print(f"Wiadomość: {alert.message}")
    else:
        print_success("Brak zagrożenia")


def demo_scenario_2(ht_system, tokens):
    """Scenariusz 2: Atakujący próbuje użyć fałszywego klucza API"""
    print_header("SCENARIUSZ 2: Próba autoryzacji z fałszywym kluczem API")

    api_token = tokens['api']
    print_info(f"Honeytoken API: {api_token.value}")
    print_info("Atakujący wysyła żądanie z kluczem API...")

    alert = ht_system.check_token_value(
        api_token.value,
        context={
            "attack_type": "invalid_api_key",
            "api_key": api_token.value,
            "endpoint": "/api/unlock",
            "timestamp": datetime.now().isoformat()
        }
    )

    if alert:
        print_error("ATAK WYKRYTY!")
        print(f"Typ ataku: invalid_api_key")
        print(f"Endpoint: /api/unlock")
    else:
        print_success("Brak zagrożenia")


def demo_scenario_3(ht_system, tokens):
    """Scenariusz 3: Monitorowanie użycia fałszywego klucza odblokowującego"""
    print_header("SCENARIUSZ 3: Próba odblokowywania za pomocą honeypot klucza")

    unlock_token = tokens['unlock']
    print_info("Atakujący próbuje odblokować aplikację...")

    # Symulacja wpisania złego klucza
    user_input_cipher = unlock_token.value  # Atakujący wpisał honeytoken!
    user_input_secret = "some_random_secret"

    print_info(f"Użytkownik wpisał klucz: {user_input_cipher}")
    print_info(f"Użytkownik wpisał sekret: {user_input_secret}")

    # Sprawdzenie czy to honeytoken
    alert = ht_system.check_token_value(
        user_input_cipher,
        context={
            "attack_type": "fake_unlock_key_used",
            "cipher_input": user_input_cipher,
            "secret_input": user_input_secret,
            "timestamp": datetime.now().isoformat()
        }
    )

    if alert:
        print_error("ATAK WYKRYTY!")
        print_error("Użytkownik próbował użyć fałszywego klucza odblokowującego!")
    else:
        print_success("Klucz nie jest honeytokenem")


def demo_scenario_4(ht_system, tokens):
    """Scenariusz 4: Prawidłowa próba dostępu (nie honeytoken)"""
    print_header("SCENARIUSZ 4: Prawidłowa autoryzacja (nie honeytoken)")

    print_info("Użytkownik próbuje zalogować się z prawidłowymi poświadczeniami...")

    real_credentials = "valid_user:password_hash_12345"
    print_info(f"Poświadczenia: {real_credentials}")

    # Sprawdzenie czy pasuje do któregoś honeytokenu
    alert = ht_system.check_token_value(real_credentials)

    if alert:
        print_error("ATAK - honeytoken aktywowany!")
    else:
        print_success("Dostęp dopuszczony - poświadczenia nie są honeytokenem")


def demo_scenario_5(ht_system, tokens):
    """Scenariusz 5: Ręczna aktywacja honeytokenu (np. plik skonfiskowany)"""
    print_header("SCENARIUSZ 5: Detekcja wycieku konfiguracyjnego pliku")

    print_info("Znaleziono plik konfiguracyjny zawierający honeytoken...")

    db_token = tokens['db']
    alert = ht_system.activate_token(
        db_token.token_id,
        context={
            "attack_type": "config_file_leaked",
            "source": "git_repository",
            "file": "config.json",
            "discovered_at": "github.com/attacker/stolen-repo",
            "timestamp": datetime.now().isoformat()
        }
    )

    if alert:
        print_error("WYCIEK DANYCH WYKRYTY!")
        print_error(f"Token: {alert.token_id}")
        print_error(f"Kontekst: {alert.context}")


def show_alert_summary(ht_system):
    """Pokaż podsumowanie alertów"""
    print_header("PODSUMOWANIE ALERTÓW")

    summary = ht_system.get_alert_summary()

    print(f"Całkowita liczba tokenów:    {summary['total_tokens']}")
    print(f"Aktywowanych tokenów:        {summary['activated_tokens']}")
    print(f"Wszystkich alertów:          {summary['total_alerts']}")
    print(f"  - Krytycznych:             {summary['critical_alerts']}")
    print(f"  - Wysokich:                {summary['high_alerts']}")

    if summary['recent_alerts']:
        print(f"\n{'─' * 70}")
        print("OSTATNIE ALERTY:")
        print(f"{'─' * 70}")
        for alert in summary['recent_alerts']:
            print(f"\n[{alert['severity'].upper()}] {alert['token_type']}")
            print(f"  Token ID: {alert['token_id']}")
            print(f"  Wiadomość: {alert['message']}")
            print(f"  Czas: {alert['timestamp']}")
    else:
        print("\n✅ Brak alertów - system bezpieczny")


def show_all_tokens(ht_system):
    """Pokaż wszystkie tokeny"""
    print_header("WSZYSTKIE HONEYTOKENY")

    tokens = ht_system.list_tokens()

    for i, token in enumerate(tokens, 1):
        status = "🔴 AKTYWNY" if token['activated'] else "🟢 Nieaktywny"
        print(f"\n{i}. {token['description']}")
        print(f"   ID: {token['token_id']}")
        print(f"   Typ: {token['token_type']}")
        print(f"   Wartość: {token['value']}")
        print(f"   Poważność: {token['severity']}")
        print(f"   Status: {status}")
        if token['activation_count'] > 0:
            print(f"   Liczba aktywacji: {token['activation_count']}")


def export_report(ht_system):
    """Eksportuj raport"""
    report_path = ht_system.export_report()
    print_success(f"Raport wyeksportowany do: {report_path}")


def main():
    """Główna funkcja demonstracji"""

    print("""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║         HONEYTOKEN SYSTEM - DEMONSTRACJA BEZPIECZEŃSTWA           ║
    ║                 Trialware z Monitorowaniem Wycieku                ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """)

    # Inicjalizacja systemu
    ht_system = HoneytokenSystem()
    tokens = setup_honeytokens(ht_system)

    print_header("DOSTĘPNE SCENARIUSZE")

    scenarios = [
        ("1", "Próba dostępu do bazy danych", lambda: demo_scenario_1(ht_system, tokens)),
        ("2", "Próba autoryzacji z fałszywym API", lambda: demo_scenario_2(ht_system, tokens)),
        ("3", "Próba odblokowywania z honeypot kluczem", lambda: demo_scenario_3(ht_system, tokens)),
        ("4", "Prawidłowa autoryzacja (bez honeytokenu)", lambda: demo_scenario_4(ht_system, tokens)),
        ("5", "Wyciek konfiguracyjnego pliku", lambda: demo_scenario_5(ht_system, tokens)),
        ("s", "Pokaż podsumowanie alertów", lambda: show_alert_summary(ht_system)),
        ("t", "Pokaż wszystkie honeytokeny", lambda: show_all_tokens(ht_system)),
        ("e", "Eksportuj raport", lambda: export_report(ht_system)),
        ("a", "Wykonaj wszystkie scenariusze", None),
        ("q", "Wyjście", None),
    ]

    while True:
        print("\nWYBIERZ OPCJĘ:")
        for key, desc, _ in scenarios:
            print(f"  {key}) {desc}")

        choice = input("\nTwój wybór: ").strip().lower()

        if choice == 'q':
            print_success("Koniec programu")
            break
        elif choice == 'a':
            demo_scenario_1(ht_system, tokens)
            demo_scenario_2(ht_system, tokens)
            demo_scenario_3(ht_system, tokens)
            demo_scenario_4(ht_system, tokens)
            demo_scenario_5(ht_system, tokens)
            show_alert_summary(ht_system)
        else:
            for key, _, func in scenarios:
                if key == choice and func:
                    func()
                    break
            else:
                print_error("Nieznana opcja")

    # Na koniec eksportuj raport
    print_header("RAPORT KOŃCOWY")
    export_report(ht_system)


if __name__ == "__main__":
    main()
