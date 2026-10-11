# Explizites temporäres natives Testprofil

Für die Entwicklung des nativen Grafiktreibers ist jetzt `temporary-native-test` auswählbar. Es beschreibt einen späteren Geräteversuch mit ausgeschaltetem **Firmware-UEFI-Secure-Boot** und erlaubt unveränderte, per SHA-256 an den gepinnten OpenCore-Release gebundene unsignierte EFI-Komponenten. `strict-secure-boot` bleibt der Standard aller CLI- und API-Aufrufe. Jeder temporäre Test benötigt deshalb ausdrücklich seinen Profilparameter.

| Prüfung | `strict-secure-boot` (Standard) | `temporary-native-test` (ausdrückliche Auswahl) |
| --- | --- | --- |
| Firmwarezustand | Aktiviertes UEFI Secure Boot nachweisen | Bewusst deaktivierten Testzustand nachweisen; unbekannt bleibt unbekannt |
| EFI-Authenticode und Firmware-Zusatzvertrauen | Erforderlich, separat zu verifizieren | Keine Testvoraussetzung; gepinnte Original-EFI darf unsigniert sein |
| Vault-Vorschlag | `Secure` | `Optional`; bei ausdrücklich beibehaltenem `Secure` gelten dessen Prüfungen weiter |
| Apple `SecureBootModel` | Eigene Prüfung, standardmäßig `Default` | Eigene Prüfung, weiterhin `Default`; Firmware-Profil deaktiviert Apple Secure Boot nicht |
| SIP-/AMFI-/Gatekeeper-Umgehung | Nicht zugelassen | Nicht zugelassen |
| Apple-signierte Recovery | `DmgLoading=Signed` | Weiterhin `DmgLoading=Signed` |
| Native CPU-/ACPI-/USB-/Kext- und Windows-Bootprüfung | Offen bis zum Gerätenachweis | Offen bis zum Gerätenachweis |
| Bootbereitschaft und SSD-`Apply` | Offline immer `false`, Apply gesperrt | Offline immer `false`, Apply gesperrt |

`DisableSecurityPolicy=false` und `ProtectSecureBoot=true` bleiben in beiden Vorschlägen erhalten. Das Werkzeug umgeht keine aktive Firmware-Richtlinie und ändert keine BIOS-Einstellung. Eigene Schlüssel werden weder erzeugt noch eingetragen. Microsoft-/OEM-Schlüssel, die interne Windows-Installation und der Windows-Rückweg bleiben eigenständige Anforderungen.

Apple Secure Boot, Firmware Secure Boot und Vault sind getrennte Ebenen. Das neue Profil erlaubt nicht automatisch das Laden einer unsignierten macOS-Kext. Die Grafik-Kext benötigt weiterhin eine native Zulassung unter der ausgewählten Apple-Boot-, SIP- und Signaturrichtlinie. Grafikbeschleunigung und ein erfolgreicher Geräte-Boot werden durch die Profilauswahl nicht bestätigt. Die Grundlagen stehen im [gepinnten OpenCore-Handbuch](https://github.com/acidanthera/OpenCorePkg/blob/6fe4d15cb66596d99d8cfedce69d8fc6dad71886/Docs/Configuration.tex), insbesondere Vault, SecureBootModel, ProtectSecureBoot und UEFI Secure Boot.

Aus dem Repository-Verzeichnis, mit ausdrücklich gewählter Quelle:

```powershell
python tools/qualify_opencore.py audit --config examples/inspection-template.plist --profile temporary-native-test
python tools/qualify_opencore.py propose --config examples/inspection-template.plist --stage-name native-test-001 --profile temporary-native-test
```

Der Vorschlag liegt ausschließlich unter `private/staging/native-test-001`. Persönliche Kennungen und Hardwareeinträge der Quelle bleiben lokal. Die öffentliche Vorlage enthält absichtlich keine qualifizierte Samsung-/Mac-Identität und ist für einen Boot ungeeignet. Die Befehle beschreiben die Schnittstelle; bei der Profiländerung wurde der vorhandene Geräte-Dateistand nicht neu erzeugt.

`prepare_offline.py` akzeptiert den Parameter bei `assemble` und `preflight`. Ein späterer neuer Dateistand benötigt eine eigenständig geprüfte Quelle und einen neuen Namen. Für eine lesende Bewertung des vorhandenen Snapshots:

```powershell
python tools/prepare_offline.py preflight --stage-name external-ssd-review-001 --profile temporary-native-test
pwsh -NoProfile -File tools/Prepare-ExternalSsd.ps1 -Mode Preflight -BackupConfirmed -EntireExternalDiskAuthorized -StageName external-ssd-review-001 -Profile temporary-native-test
```

Die Auswahl schreibt den Snapshot nicht um. Neue Manifeste halten die Profilkennung fest; historische Manifeste ohne Kennung werden als damaliges strenges Profil beschrieben. Berichte unterscheiden Snapshot und aktuell gewähltes Bewertungsprofil. Die vorhandene strenge Konfiguration besitzt weiterhin `Vault=Secure`; ein Optional-Vault-Vorschlag erfordert eine neue Konfigurationskopie. Ein geänderter Manifestwert ersetzt diese Konfiguration nicht.

Im temporären SSD-Preflight ist die externe Firmware-Vertrauenskette **nicht erforderlich**, ihr Prüfergebnis bleibt unbekannt. Sie wird nicht als erfolgreich bestätigt. Der deaktivierte Firmwarezustand, native Bootqualifikation, Gerätebindung, Sicherung, Installationsdaten und Windows-Rückweg bleiben zu prüfen. `Apply` endet in beiden Profilen vor jeder Geräteabfrage mit Exitcode 4. Der lesende Preflight endet bei offenen Bedingungen mit Exitcode 2, bei ungültigen Eingaben mit Exitcode 3.

Die zwölf bekannten Deklarationsfelder benötigen echte boolesche Werte. Das Testprofil benötigt `firmware_secure_boot_disabled_for_test`; das strenge Profil benötigt den aktivierten Zustand sowie Trust-/EFI-Signaturnachweise. Eingabedeklarationen bleiben ungeprüfte Angaben. `examples/prerequisite-declarations.json` enthält ausschließlich `false` als neutrale Vorlage.

Lokale Prüfungen: **145 Python-Tests und 16 PowerShell-Tests** ohne Fehler. Das originale `ocvalidate` 1.0.8 akzeptiert beide Sample-Vorschläge im reinen Schematest; die öffentliche Vorlage bleibt wegen fehlender Identität abgelehnt. Die bestehende CI prüft diese Tests automatisch. Ein neuer Online-Lauf und native Samsung-Tests stehen nach Veröffentlichung noch aus.
