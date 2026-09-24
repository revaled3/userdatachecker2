# Steam userdata – sprawdzanie zmian (dziennik USN)

Sprawdza, czy w folderze `Steam\userdata` ktoś **usuwał, przenosił lub zmieniał nazwy** folderów/plików – wraz z datą i godziną.
Dane pochodzą z dziennika zmian NTFS (USN Journal), który Windows prowadzi automatycznie.

Skrypt **tylko odczytuje** dane – niczego nie usuwa, nie zmienia i nigdzie nie wysyła.

## Jak uruchomić

1. Naciśnij **Win + R**, wpisz `powershell` i naciśnij Enter.
2. Wklej poniższą komendę i naciśnij Enter:

```powershell
irm https://raw.githubusercontent.com/revaled3/userdatachecker2/main/check.ps1 | iex
```

3. Potwierdź okno **UAC** (uprawnienia administratora są potrzebne do odczytu dziennika USN).
4. Po ~30–60 s raport:
   - otworzy się w przeglądarce jako strona HTML,
   - zostanie zapisany w folderze **Pobrane** jako `steam_userdata_log.html` i `steam_userdata_log.txt`,
   - zostanie skopiowany do schowka – wystarczy wkleić go (Ctrl+V) osobie, która o niego prosi.

## Co oznaczają wyniki

| Operacja | Znaczenie |
|---|---|
| USUNIĘTO (do Kosza) | folder przeniesiony do Kosza (zwykłe Delete) |
| USUNIĘTO TRWALE | usunięty z pominięciem Kosza (Shift+Del) lub opróżniono Kosz |
| ZMIENIONO NAZWĘ | zmiana nazwy w tym samym miejscu |
| PRZENIESIONO ... | zmiana lokalizacji folderu |
| PRZYWRÓCONO z Kosza | folder odzyskany z Kosza |

Automatyczna praca Steama (pliki `*.tmp`, `*.vdf~`, foldery `*cache\`, `logs\`, `gamerecordings\`) jest pomijana.

Uwaga: dziennik USN ma ograniczony rozmiar – starsze zdarzenia (zwykle sprzed kilku dni) mogą być już nadpisane.
Zakres czasu, który obejmuje analiza, jest podany w raporcie.
