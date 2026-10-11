# LunarBridge OpenCore

Dieses eigenständige Modul bereitet eine überprüfbare OpenCore-Konfiguration für einen Samsung Galaxy Book5 Pro16 NP960XHA-KG3DE vor: Windows auf der internen NVMe, natives macOS Tahoe auf einer externen USB-C-SSD und eine sichtbare Systemauswahl mit einer vollständig geprüften Secure-Boot-Kette.

Implementiert sind ein Offline-Validator, ein Generator für unveränderte Original- und vorgeschlagene Konfigurationskopien, eine bewusst unvollständige öffentliche Vorlage, eine Prüfung mit dem originalen `ocvalidate` aus OpenCore 1.0.8 und eine konkrete private Offline-EFI mit Dateimanifest und Recovery-Authentifizierung. Konfigurationskopien entstehen ausschließlich unter `private/staging`, neue Offline-Dateistände unter `private/assembly`. Die Werkzeuge installieren keinen Bootloader und verändern keine Firmware, Bootreihenfolge oder Partition.

121 lokale Tests bestanden unter Windows. Das originale `ocvalidate` akzeptiert das originale Sample, eine reine Schema-Testkonfiguration mit unterstütztem Modell und den Vorschlag aus dem originalen Sample. Die öffentliche Vorlage lässt `SystemProductName` und persönliche Kennungen leer und wird dadurch absichtlich abgelehnt. Ein Geräte-Boot wurde nicht durchgeführt. Der konkrete lokale Offline-Dateistand umfasst sieben Dateien; das Recovery-Paar wurde mit Apples fester RSA/SHA-256-Signatur und allen 92 Bild-Chunks geprüft. Der Nachweis steht in [docs/ASSEMBLY_VALIDATION.json](docs/ASSEMBLY_VALIDATION.json).

OpenCore 1.0.8 wurde am 11. Oktober 2026 als aktueller offizieller Release geprüft. Commit, Archiv, Sample, Werkzeuge und originale EFI-Dateien sind in [reference-lock.json](reference-lock.json) mit SHA-256 festgehalten. Die vorhandenen Originaldateien `BOOTx64.efi`, `OpenCore.efi`, `OpenRuntime.efi` und `OpenHfsPlus.efi` sind noch unsigniert. Die maßgeblichen Grenzen und erforderlichen Nachweise stehen in [docs/SECURE_BOOT.md](docs/SECURE_BOOT.md) und [docs/NATIVE_PLATFORM.md](docs/NATIVE_PLATFORM.md).

Voraussetzung ist Python 3.12 oder neuer. Aus dem Repository-Verzeichnis:

```powershell
python tools/qualify_opencore.py audit --config examples/inspection-template.plist
python tools/qualify_opencore.py propose --config examples/inspection-template.plist --stage-name review-001
python -m unittest discover -s tests -p "test_*.py" -v
```

`audit` gibt JSON ohne SMBIOS-Kennungen oder vollständige Eingabepfade aus. Exitcode 2 bedeutet offene Bedingungen oder blockierende Befunde, Exitcode 3 ungültige Eingaben. `ready_for_boot` bleibt ausdrücklich `false`: Offline-Prüfungen und eingegebene Voraussetzungen ersetzen keinen Geräte-Nachweis. Die vorgeschlagene Konfiguration und ihre unveränderte Quelle stehen lokal unter `private/staging/review-001/`; dieser Ordner ist ignoriert. Zum Rücknehmen wird nur dieser neu erstellte Arbeitsordner verworfen. Die ausgewählte Quelldatei bleibt unverändert.

Für eine vollständige Dateiprüfung können `--oc-root` mit einer ausdrücklich gewählten offline liegenden `OC`-Kopie, `--ocvalidate` mit dem passenden originalen Werkzeug und `--declarations` angegeben werden. Der Validator verlangt, dass die ausgewählte Konfiguration genau den Bytes von `OC/config.plist` entspricht. Er erkennt fehlende Dateien, unsichere Pfade, falsche Architekturen, unpassende Versionswerkzeuge, fehlende Signaturtabellen und beschädigte Vault-Dateihashes. Vorhandene Signaturdaten beweisen weder Signaturgültigkeit noch Firmware-Vertrauen.

Das bereits geladene offizielle Archiv kann separat geprüft werden:

```powershell
python tools/verify_reference.py --archive PFAD-ZUM-OpenCore-1.0.8-RELEASE.zip
```

Alternativ lädt `--download` genau das gepinnte offizielle Archiv und prüft dessen Größe und SHA-256 vor jeder Werkzeugausführung. Dabei werden ausschließlich das Sample und `ocvalidate` in einen temporären privaten Prüfbereich geschrieben. Die GitHub-Workflow-Prüfung führt dieselben Tests und die passende Linux-Ausgabe des originalen Validators aus; sie ist kein Test auf dem Samsung.

[docs/CONFIGURATION.md](docs/CONFIGURATION.md) erklärt die konkreten Änderungen. [docs/EXTERNAL_BOOT.md](docs/EXTERNAL_BOOT.md) behandelt die externe SSD, Recovery ohne zusätzlichen Stick und den Windows-Fallback. GPU, I2C, Kamera, Audio, Funk und weitere Hardware bleiben getrennte Treibermodule; OpenCore enthält hier keine Sammel-Kext. Die Grafikentwicklung liegt im [LunarBridge-Hackintosh-Projekt](https://github.com/IT-EXPRESS-Bayern/LunarBridge-Hackintosh).

[docs/OFFLINE_ASSEMBLY.md](docs/OFFLINE_ASSEMBLY.md) beschreibt den neuen Vorbereiter, die konkrete private Dateistruktur, die vollständige Änderungserkennung und die Reihenfolge von Kext-/EFI-Signierung, Vault, Schlüssel-Einbettung und finalen Ladersignaturen. Der Vault-Schlüsselgenerator wurde nicht ausgeführt. Eine veränderte Konfiguration oder Moduldatei setzt die zugehörigen Vault-/Signierungsnachweise erneut auf offen; die echte Windows-/macOS-/Firmware-Abnahme bleibt erforderlich.

[docs/LunarBridge-SSD-Plan.md](docs/LunarBridge-SSD-Plan.md) und [docs/LunarBridge-SSD-Preflight.json](docs/LunarBridge-SSD-Preflight.json) ergänzen einen lesenden PowerShell-Preflight für die privat gebundene externe Lexar-SSD: geplant sind eine 2-GiB-FAT32-ESP für EFI/Recovery und die verbleibende unformatierte Zielpartition. Die bestätigte Sicherung und Besitzerfreigabe sind berücksichtigt. **Elf zusätzliche PowerShell-Prüfungen bestanden**; die drei Skripte und ein eigener Windows-CI-Job sind integriert. Gerätebindung, Fixtures und Detailberichte bleiben unter `private/ssd`. `Apply` ist bedingungslos gesperrt; ein Formatierungs-, BCD- oder Firmwareänderungspfad ist nicht implementiert.

Eigener Code und Änderungen: **GPL-3.0-only**. Die abgeleitete Sample-Konfiguration behält die OpenCore-Bedingungen aus [NOTICE](NOTICE) und [licenses/OpenCore-BSD-3-Clause.txt](licenses/OpenCore-BSD-3-Clause.txt). Persönliche Konfigurationen, Schlüssel, Vault-Dateien, Berichte und interne Arbeitslisten bleiben lokal.

Der bisher erfolgreiche Online-Prüflauf und sein exakter Quellstand sind in [docs/CI_VALIDATION.json](docs/CI_VALIDATION.json) festgehalten. Die später ergänzte Offline-Assembly wird dadurch noch nicht online bestätigt; dafür ist ein neuer Lauf am veröffentlichten Quellstand erforderlich. Kein CI-Lauf ist ein Gerätefunktionstest auf dem Samsung.
