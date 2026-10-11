# Konkrete Offline-Vorbereitung

`tools/prepare_offline.py` erzeugt einen neuen privaten Dateistand aus dem gepinnten Originalarchiv, einer ausdrücklich gewählten Konfiguration und optional deren aktivierten Hardwaremodulen und dem Recovery-Paar. Das Verzeichnis liegt ausschließlich unter `private/assembly/<name>`. Es wird nicht auf eine EFI-Systempartition, einen Datenträger oder in die Firmware installiert. Die unveränderten Originaldateien und persönliche Konfigurationswerte werden nicht als Git-Dateien aufgenommen.

Vor dem Anlegen des neuen Dateistands prüft das Werkzeug Archivgröße und SHA-256, die Konfigurationsrichtlinie, das echte originale `ocvalidate` 1.0.8, die ausgewählten x64-PE-Dateien und alle aktivierten Moduldateien. Es übernimmt nur `BOOTx64.efi`, `OpenCore.efi` und die ausdrücklich aktivierten Treiber aus dem Release. Das Release liefert `OpenHfsPlus.efi`; ein ausgewähltes, im Paket fehlendes `HfsPlus.efi` führt zu einem Fehler. Vorhandene Ordner werden nicht überschrieben. Link-, Junction-, Pfad-, Paket-, Größen- und Namensprüfungen begrenzen die Vorbereitung.

Die bewusst unvollständige öffentliche Konfiguration ist nur mit `--inspection-only` erlaubt. Die Ausnahme für einen negativen `ocvalidate`-Lauf gilt ausschließlich für deren exakt unveränderte Bytes. Eine andere ungültige Konfiguration wird auch mit diesem Schalter abgelehnt. Die Vorlage bleibt ohne persönliche Kennungen und ohne ausgewählte Mac-Identität; sie ist keine für Lunar Lake qualifizierte Bootkonfiguration. Die Vorlage aktiviert keine Hardware-Kexts und enthält keine erfundenen CPUID- oder ACPI-Anpassungen.

Einzelne Hardwaretreiber werden nur anhand vorhandener, aktivierter `Kernel/Add`-Einträge gelesen. Dieses eingeschränkte Profil übernimmt separate oberste `.kext`-Pakete mit `Contents/Info.plist`, passendem `CFBundleIdentifier`, Pakettyp und x64-`MH_KEXT_BUNDLE`-Executable. Codeless-Kexts sind möglich. Verschachtelte Kexts benötigen eine eigene Prüfung und werden hier abgelehnt. Das ist eine Grenze dieses Vorbereiters, keine allgemeine OpenCore-Grenze. Kext-Metadaten, Mach-O-Struktur oder vorhandene Signaturdaten ersetzen keine native Ladezulassung.

Aus dem Repository-Verzeichnis, mit bereits vorhandenem Originalarchiv und Recovery:

```powershell
python tools/prepare_offline.py assemble --archive ../macos-vorbereitung/downloads/OpenCore-1.0.8-RELEASE.zip --config examples/inspection-template.plist --stage-name external-ssd-review-001 --recovery-dir ../macos-vorbereitung/media/Tahoe-recovery/com.apple.recovery.boot --inspection-only
python tools/prepare_offline.py preflight --stage-name external-ssd-review-001 --ocvalidate ../macos-vorbereitung/tools/OpenCore-1.0.8-RELEASE/Utilities/ocvalidate/ocvalidate.exe --declarations examples/prerequisite-declarations.json
```

Der zweite Befehl kann stattdessen eine private, geprüfte Voraussetzungsliste lesen. Die öffentliche Liste bleibt für andere Nutzer auf `false`. Exitcode 0 von `assemble` bedeutet ausschließlich eine erfolgreich erzeugte Vorbereitung. `preflight` liefert weiterhin Exitcode 2 für die nicht abgeschlossene native Vertrauenskette; ungültige Eingaben führen zu Exitcode 3. Beide Ergebnisse lassen `ready_for_boot=false`.

Die erzeugte Dateistruktur lautet:

```text
private/assembly/external-ssd-review-001/
  assembly-manifest.json
  EFI/
    BOOT/BOOTx64.efi
    OC/
      OpenCore.efi
      config.plist
      Drivers/OpenRuntime.efi
      Drivers/OpenHfsPlus.efi
  com.apple.recovery.boot/
    BaseSystem.dmg
    BaseSystem.chunklist
```

In diesem konkreten Dateistand wurden sieben Dateien mit insgesamt 961.265.615 Bytes vorbereitet. Das Recovery-Abbild umfasst 960.530.321 Bytes. Die Prüfung hat Apples feste RSA-2048/SHA-256-Chunklist-Signatur und alle 92 Bild-Chunks bestätigt. Abbild-SHA-256: `edddd0d5869caaa12e29e6996a04f11590280580976a119dbd42c24fa62fe18e`. Chunklist-SHA-256: `06f7c498f856341f467ba1faedf2717fb2c172ae0aff4658a1467cbf46b711f9`. Die Prüfung authentifiziert die Bildbytes; sie bestimmt weder die enthaltene macOS-Version noch beweist sie einen gestarteten Recovery- oder Apple-Secure-Boot-Pfad. Das Format und der feste öffentliche Prüfmodulus stammen aus dem [gepinnten originalen macrecovery-Werkzeug](https://github.com/acidanthera/OpenCorePkg/blob/6fe4d15cb66596d99d8cfedce69d8fc6dad71886/Utilities/macrecovery/macrecovery.py). Hash-only-Chunklisten und zusätzliche Bildbytes werden abgelehnt. Die Prüfung verwendet explizite Fehlerbedingungen; sie bleibt bei deaktivierten Python-Assertions wirksam.

Eine zusätzliche lesende Untersuchung des vorhandenen Images bestätigt **macOS Tahoe Recovery 26.6.2, Build 25G83** direkt aus `System/Library/CoreServices/SystemVersion.plist`. Zwei unabhängige Parser liefern dieselbe 603-Byte-Datei mit SHA-256 `6151cb883e5b48d43a33d4d41956405a1cd502e0c8622319388d943e2cb804a1`. Original und Stage bleiben unverändert. [RECOVERY_VERSION.json](RECOVERY_VERSION.json) bindet den Befund an die tatsächlichen Imagebytes. Die spätere installierte macOS-Payload-Version und ein nativer Start bleiben ungeprüft. Dieser zusätzliche Versionsbefund ändert das historische Assembly-Manifest nicht.


`assembly-manifest.json` enthält relative Pfade, Größen, Dateihashes und Rollen. Es enthält keine absoluten Benutzerpfade oder SMBIOS-Kennungen. `preflight` liest die aktuelle Dateiliste erneut und erkennt Änderungen, fehlende und hinzugefügte Dateien, Links und Namenskollisionen. Ein Dateimanifest ist selbst kein authentifizierter Vertrauensanker. Sein Inhalt darf keine gültige EFI-Signatur, Firmware-Vertrauen oder einen erfolgreichen Geräte-Boot vortäuschen. Bei Abweichungen wird die weitere Qualifikation ausgesetzt und die betroffene Signierungsabhängigkeit benannt. Nach einer geplanten Signierung verändert sich die ursprüngliche unsignierte Vorlage erwartungsgemäß; sie muss als alte Quellversion erhalten bleiben. Die endgültige signierte Kopie wird danach separat mit `qualify_opencore.py audit` und den tatsächlichen kryptografischen und physischen Nachweisen geprüft. Der Generator setzt keine Manifest-Historie stillschweigend zurück.

Für die endgültige Vertrauenskette gilt diese Reihenfolge:

1. Die konkrete Mac-Identität, CPU-/XNU-Anpassungen, ACPI-Darwin-Guards, USB-Abbildung und jedes einzelne Hardwaremodul qualifizieren. Keine Diagnose-Kext automatisch aktivieren.
2. Die endgültigen Kext-Dateien signieren und ihre Zulassung unter der gewählten Apple-Secure-Boot-/SIP-Richtlinie auf dem Zielgerät nachweisen.
3. Die endgültigen EFI-Treiber und eventuell separat erlaubten Werkzeuge authentisch signieren. Dieses Profil bietet keine administrativen Firmware-Werkzeuge im Picker an.
4. Den Vault über die endgültige Konfiguration, die bereits signierten EFI-Treiber und die endgültigen Moduldateien erstellen und seine RSA-Signatur prüfen. `OpenCore.efi`, `vault.*` und `EFI/BOOT` sind keine gewöhnlichen Vault-Dateihashes.
5. Den passenden öffentlichen Vault-Schlüssel in die richtige `OpenCore.efi`-Kopie einbetten. Dieser Schritt verändert den Lader.
6. Die endgültige `OpenCore.efi` und `BOOTx64.efi` signieren und deren Authenticode-Ketten und konkrete Dateiversion prüfen.
7. Die Firmware-Vertrauens- und Sperrlisten mit erhaltenem Microsoft-/OEM-Windows-Vertrauen einschließlich passender 2023-Zertifikate prüfen. Erst die konkrete Firmware-Annahme ist ein Nachweis für diesen Samsung.
8. Mit tatsächlich aktivem Firmware Secure Boot Windows über den Picker, macOS extern und Windows ohne angeschlossene externe SSD testen.

Die Zuordnung von Änderungen ist präzise:

| Änderung | Zu wiederholende Prüfung |
| --- | --- |
| `config.plist` oder erfasste ACPI-/Ressourcendatei | Vault-Hashes, Vault-Signatur/Einbettung und finale OpenCore-Signatur |
| EFI-Treiber | Eigene Treibersignatur, Vault und finale OpenCore-Signatur |
| Kext-Datei | Modulsignatur/Ladezulassung, Vault und finale OpenCore-Signatur |
| Eingebetteter Schlüssel oder andere `OpenCore.efi`-Bytes | Finale OpenCore-Signatur; `OpenCore.efi` liegt außerhalb der normalen Vault-Dateihashes |
| `BOOTx64.efi` | Bootstrap-Signatur; sein Pfad liegt außerhalb des OC-Vaults |
| Recovery-Abbild oder Chunklist | Vollständige erneute Paar-/Signaturprüfung; beide liegen außerhalb des OC-Vaults |

Das originale `Utilities/CreateVault/sign.command` ist hier keine Windows-Signierungsfunktion. Es verlangt eine Unix-Umgebung und das mitgelieferte `RsaTool`. Dessen `-sign`-Modus erzeugt einen neuen RSA-Schlüssel im Speicher, signiert den Vault und exportiert den öffentlichen Schlüssel; das Skript patcht anschließend 528 Bytes in `OpenCore.efi`. Wegen dieser tatsächlichen Schlüsselgenerierung wurde es nicht ausgeführt. Der [gepinnten RsaTool-Quelle](https://github.com/acidanthera/OpenCorePkg/blob/6fe4d15cb66596d99d8cfedce69d8fc6dad71886/Utilities/RsaTool/RsaTool.c) und [sign.command](https://github.com/acidanthera/OpenCorePkg/blob/6fe4d15cb66596d99d8cfedce69d8fc6dad71886/Utilities/CreateVault/sign.command) lassen sich diese Schritte direkt entnehmen. Eine wiederholte Ausführung erzeugt einen neuen Schlüssel und verändert erneut die Laderdatei; vorhandene finale Authenticode-Nachweise werden dadurch veraltet. Der allgemeine [OpenCore-Konfigurationsbeleg](https://github.com/acidanthera/OpenCorePkg/blob/6fe4d15cb66596d99d8cfedce69d8fc6dad71886/Docs/Configuration.tex) beschreibt Vault, Apple Secure Boot und Firmware Secure Boot getrennt.

Die externe SSD soll später selbst das USB-C-Startmedium tragen: eine ausreichend große FAT32-EFI-/Recovery-Partition und ein separates APFS-Installationsziel. Im geplanten gemeinsamen FAT32-Bereich liegen `EFI` und `com.apple.recovery.boot` direkt nebeneinander. Ein zusätzlicher USB-Stick ist damit für die Dateianordnung nicht nötig. Recovery installiert anschließend weitere macOS-Daten; dafür fehlt bislang ein bestätigter Netzwerkweg auf dem Gerät. Der abgebrochene große Installer-Download wird nicht gestartet. Interne Windows-Dateien werden nicht dupliziert, gelöscht oder ersetzt.

Noch physisch oder mit zusätzlichen Rechten erforderlich sind ein erhöhter Windows-Prozess für die spätere, exakt abgegrenzte externe GPT-/Partitionsaktion, die Live-Abfrage des Firmwarezustands, Zugriff auf das Samsung-BIOS zur Prüfung eines zusätzlichen Vertrauensankers ohne OEM-Schlüsselreset, ein verfügbarer BitLocker-Rückweg oder belegte Nichtverwendung sowie der tatsächliche native CPU-/ACPI-/USB-/Kext- und Boot-Test. Die Datensicherung der gesamten Lexar-SSD ist vom Besitzer bestätigt; diese Bestätigung ersetzt keinen der weiteren Nachweise. Die Auswahl muss unmittelbar vor einer Datenträgeraktion anhand des USB-Laufwerks selbst überprüft werden; Datenträgernummern können sich ändern. Die interne Samsung-Systemplatte gehört nicht zum Zielbereich. Wie Microsoft-Vertrauen erhalten werden muss, beschreibt die [Herstellerrichtlinie](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-secure-boot-key-creation-and-management-guidance?view=windows-11).

Die bisher erfolgreiche Online-CI ist in `CI_VALIDATION.json` an ihren damaligen Commit gebunden. Neue Werkzeuge und Tests werden erst durch einen neuen Lauf am neu veröffentlichten Quellstand online bestätigt. Der Workflow prüft nun zusätzlich die echte Offline-Paketprüfung mit dem gepinnten Originalarchiv; er besitzt weiterhin keine Firmware- oder Samsung-Hardware.
