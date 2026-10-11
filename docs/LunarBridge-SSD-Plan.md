# Externe SSD: geprüfter Plan und weiterhin gesperrte Ausführung

Die vollständige Sicherung der externen Lexar-USB-SSD wurde vom Besitzer bestätigt und geprüft. Die gesamte externe Platte ist als Ziel autorisiert. Der neue lesende Preflight hat die zuvor privat gebundene externe SSD erneut erkannt. Die interne Samsung-Windows-Platte und virtuelle Datenträger bleiben ausgeschlossen. Dieser Stand ist eine überprüfte Vorbereitung; es wurde kein funktionsfähiger macOS-Installer eingerichtet und keine Partition verändert.

Für die aktuelle native Grafikentwicklung ist jetzt `-Profile temporary-native-test` ausdrücklich auswählbar. Dieses Profil benötigt keine Firmware-Vertrauenskette, hält ihren Status aber weiterhin unbestätigt. Der deaktivierte Testzustand und die native Bootqualifikation bleiben nachzuweisen. Standard ist das erhaltene `strict-secure-boot`; die Unterschiede und Befehle stehen in [TEST_PROFILES.md](TEST_PROFILES.md). Der beigefügte ursprüngliche Preflight-Bericht dokumentiert den damaligen strengen Stand.

Die drei integrierten PowerShell-Dateien sind `tools/Prepare-ExternalSsd.ps1`, `tools/SsdPreparation.Core.psm1` und `tests/Test-SsdPreparation.ps1`. Sie bestimmen das Repository aus ihrem eigenen Speicherort, nicht aus einem festen Workspace-Pfad. `--stage-name` des Python-Vorbereiters entspricht dem PowerShell-Parameter `-StageName`; standardmäßig wird `private/assembly/external-ssd-review-001/assembly-manifest.json` gelesen. Persönliche Gerätebindung, Test-Fixtures und Detailberichte werden ausschließlich unter dem ignorierten `private/ssd` gespeichert. Es gibt keinen Fallback allein nach Seriennummer oder Laufwerksbuchstaben. Die private Gerätekennung und der physische Gerätepfad werden nicht veröffentlicht.

Für die bestätigte externe Kapazität von 512.110.190.592 Bytes gilt folgender Plan. Die Grenzen werden mit 1 MiB ausgerichtet und müssen unmittelbar vor einer künftigen Datenträgeraktion anhand der tatsächlichen freien Extents erneut geprüft werden.

| Bereich | Geplanter Inhalt | Größe / Anordnung |
| --- | --- | --- |
| GPT-Anfangsreserve | Partitionstabelle und Ausrichtung | Erste Partition beginnt bei 1 MiB |
| Erste Partition: EFI System Partition | FAT32, Label `EFI`; `EFI` und `com.apple.recovery.boot` nebeneinander | Genau 2 GiB = 2.147.483.648 Bytes |
| Zweite Partition: macOS-Ziel | Unter Windows zunächst RAW und unformatiert; später nur diese Zielpartition als APFS einrichten | Gesamter verbleibender ausgerichteter Bereich, rund 475 GiB |
| Endreserve | Platz für das GPT-Ende und Ausrichtung | Mindestens 1 MiB |

Der aktuell geprüfte Dateistand umfasst sieben Dateien mit 961.265.615 Bytes. Er passt einschließlich der vorgesehenen 64-MiB-Reserve in die geplante FAT32-Partition. Das Recovery-Abbild selbst umfasst 960.530.321 Bytes und liegt unter FAT32s Einzeldateigrenze. Die vollständige Apple-RSA-/Chunk-Prüfung steht in [ASSEMBLY_VALIDATION.json](ASSEMBLY_VALIDATION.json). Der SSD-Helfer wiederholt nur Inventar-, Größen- und Dateihashprüfungen; er übernimmt die Recovery-Signaturmeldung ausdrücklich als Eingangsinformation und führt keine neue Kryptografie- oder native Bootprüfung durch.

Eine zusätzliche lesende Untersuchung des vorhandenen Images bestätigt **macOS Tahoe Recovery 26.6.2, Build 25G83** direkt aus `System/Library/CoreServices/SystemVersion.plist`. Zwei unabhängige Parser liefern dieselbe 603-Byte-Datei mit SHA-256 `6151cb883e5b48d43a33d4d41956405a1cd502e0c8622319388d943e2cb804a1`. Original und Stage bleiben unverändert. [RECOVERY_VERSION.json](RECOVERY_VERSION.json) bindet den Befund an die tatsächlichen Imagebytes. Die spätere installierte macOS-Payload-Version und ein nativer Start bleiben ungeprüft. Dieser zusätzliche Versionsbefund ändert das historische Assembly-Manifest nicht.


Die externe SSD soll später zugleich Startmedium und Installationsziel sein. Ein zusätzlicher USB-Stick ist für diese Dateianordnung nicht nötig. Bei einer Installation muss die erste FAT32-Partition erhalten bleiben. Im macOS-Festplattendienstprogramm darf ausschließlich die zweite, zuvor eindeutig bestimmte Zielpartition eingerichtet werden; das Löschen des gesamten externen Datenträgers würde das eigene Startmedium entfernen. Eine automatisch angelegte MSR-Partition wird vom Plan nicht vorausgesetzt. Die tatsächliche Windows-/GPT-Anordnung müsste vor einer Umsetzung neu geprüft werden.

Aktuell sind folgende Bedingungen offen:

- Das bereitgestellte Bundle ist `inspection_only=true`, `ready_for_boot=false` und nicht durch sein Manifest authentifiziert. Die öffentliche Vorlage besitzt bewusst keine qualifizierte Mac-Identität; das originale `ocvalidate` liefert Exitcode 1.
- Die native Lunar-Lake-/XNU-, ACPI-, externe USB- und separate Kext-Konfiguration ist nicht auf dem Samsung qualifiziert. EFI-Treiber, Vault und finale Lader benötigen die dokumentierte Signierungs- und Prüfungsfolge.
- Der aktuelle Prozess ist nicht erhöht. Die Live-Abfrage von Firmware Secure Boot ist damit nicht bestätigt; der externe Firmware-Vertrauensanker und die erhaltene Microsoft-/OEM-Windows-Vertrauenskette sind offen. `SecureBootModel` ist eine andere Ebene als Firmware Secure Boot.
- Recovery benötigt weitere Installationsdaten über einen bestätigten nativen Netzwerkweg oder einen vollständig geprüften lokalen Installer. Der frühere große Installer-Download bleibt abgebrochen.
- Windows intern, macOS extern, beide über die gewünschte Auswahl sowie Windows ohne angeschlossene externe SSD müssen mit aktiver Firmware-Sicherheit tatsächlich gestartet werden. OpenCore-Picker und Firmware-Bootreihenfolge sind unterschiedliche Einstellungen.

`Apply` bleibt deshalb bedingungslos gesperrt und liefert Exitcode 4. Es existiert in diesen Dateien kein Formatierungs-, Partitions-, BCD-, Firmwareänderungs- oder UAC-Ausführungspfad. Selbst manuell geänderte Manifest-Bools oder erfüllte Bestätigungsflags können eine Datenträgeraktion nicht freigeben. Beide Profile benötigen weiterhin native Bootqualifikation; das temporäre Profil überspringt ausschließlich die nicht erforderliche Firmware-Vertrauenskette und bestätigt deren Status nicht. Ein lesender erfolgreicher Geräteabgleich mit offenen Bedingungen liefert im direkten `pwsh -File`-Aufruf Exitcode 2; ungültige Eingaben oder fehlgeschlagene lesende Abfragen liefern Exitcode 3.

Aus dem Repository-Verzeichnis, nach tatsächlich vorhandener Sicherung und Besitzerfreigabe:

```powershell
pwsh -NoProfile -File tools/Prepare-ExternalSsd.ps1 -Mode Preflight -BackupConfirmed -EntireExternalDiskAuthorized -StageName external-ssd-review-001
pwsh -NoProfile -File tests/Test-SsdPreparation.ps1
```

Die erstmalige lokale Gerätebindung kann mit `-Mode CaptureIdentity` erfasst werden. Eine vorhandene Identitätsdatei wird nicht überschrieben. Nach einem anderen USB-Gerätepfad oder einer neuen Datenträgernummer stoppt der Abgleich und verlangt eine erneute bewusste Prüfung. Der öffentlich lesbare, anonymisierte Befund steht in [LunarBridge-SSD-Preflight.json](LunarBridge-SSD-Preflight.json); die persönliche Bindung bleibt lokal.

Die erweiterte Prüfung umfasst 16 PowerShell-Grenz- und Fehlerfälle unter PowerShell 7.6.5 sowie 145 bestandene Python-Prüfungen. Der ursprüngliche beigefügte Bericht enthält seinen damaligen Stand mit elf beziehungsweise 121 Prüfungen. Drei PowerShell-Quellen wurden ohne Parserfehler geprüft. Die Tests verwenden kleine synthetische Dateien und fragen keine echten Datenträger oder Firmware ab. Sie prüfen unter anderem interne/virtuelle Datenträger, exakte Gerätebindung, Pfade und private Testbereiche, Schema-Bools, manipulierte und hinzugefügte Dateien, Layoutgrenzen und fehlende destruktive Befehle.

Ein zusätzlicher Workflow-Job nutzt `windows-2025`, den vorhandenen auf vollständigen Commit-SHA gepinnten Checkout und PowerShell-Parser-/Grenzprüfungen. Er führt den realen Geräte-Preflight nicht auf dem Hosted Runner aus. Das Windows-Image ist ein gepflegtes Runner-Label; seine gesamte Betriebssystemversion ist dadurch nicht unveränderlich gepinnt. GitHub dokumentiert das [Windows-2025-Image](https://github.com/actions/runner-images/blob/main/images/windows/Windows2025-Readme.md) und den verwendeten [Checkout-Commit](https://github.com/actions/checkout/commit/1af3b93b6815bc44a9784bd300feb67ff0d1eeb3). Der [Online-Lauf 38112924120](https://github.com/IT-EXPRESS-Bayern/LunarBridge-OpenCore/actions/runs/38112924120) am Quellstand `adcffd6d8dc15ff8b70f11e268fb205c5550f16b` ist erfolgreich: 121 Python-Tests im Linux-Job und elf PowerShell-Grenztests sowie alle drei Parserprüfungen im Windows-Job. Das ist kein SSD-Schreib- oder Samsung-Bootnachweis.
