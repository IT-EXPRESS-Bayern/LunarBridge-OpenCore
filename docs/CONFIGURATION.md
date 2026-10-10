# Überprüfbare Konfigurationsänderungen

Der vorhandene Download enthält OpenCore 1.0.8 und sein originales Sample; eine fertig qualifizierte Samsung-Konfiguration liegt noch nicht vor. Der Generator benötigt deshalb immer eine ausdrücklich gewählte Quelle. Er speichert deren Originalbytes, eine vorgeschlagene Kopie und eine auf relevante Eigenschaften begrenzte Änderungsliste. Bestehende Treiberlisten, ACPI-Tabellen, CPUID-Masken und private SMBIOS-Werte werden dabei erhalten. Sicherheitsumgehende Bootargumente und personalisierte `ApECID`-Konfigurationen werden zur separaten Prüfung abgelehnt.

| Eigenschaft | Vorschlag und Zweck |
| --- | --- |
| `Misc/Security/ScanPolicy` | `0x002D0703`: Dateisystem- und Gerätebeschränkung bleibt aktiv; APFS, HFS, ESP sowie NVMe, USB, SATA und SCSI sind auswählbar. |
| `UEFI/APFS/JumpstartHotPlug` | `true`, damit der APFS-Lader die externe USB-SSD beim Start und im Picker berücksichtigen kann. |
| `Misc/Boot/ShowPicker`, `HideAuxiliary`, `Timeout` | Sichtbarer Picker, sichtbare Recovery und zehn Sekunden Auswahlzeit. |
| `Misc/Boot/PickerMode` | `Builtin`, ohne zusätzlichen OpenCanopy-Treiber oder Grafikbeschleunigungsannahme. |
| `Misc/Boot/LauncherOption`, `Misc/Security/AllowSetDefault` | `Disabled` und `false`; die Vorbereitung erstellt keine Firmware-Bootoption und setzt keinen neuen Standard. |
| `UEFI/Quirks/RequestBootVarRouting` | `true`; die vorhandene Bootvariable-Routing-Funktion erfordert passend aktiviertes `OpenRuntime.efi`. |
| `PlatformInfo/UpdateSMBIOSMode`, `Kernel/Quirks/CustomSMBIOSGuid` | `Custom` und `true`; macOS nutzt die eigenen SMBIOS-GUIDs, während Windows seine OEM-Tabellen behalten soll. |
| `Booter/Quirks/ProtectSecureBoot` | `true`, um Firmware-Secure-Boot-Variablen während dieser Bootkette vor Schreibzugriffen zu schützen. |
| `Misc/Security/SecureBootModel`, `Vault`, `DmgLoading` | `Default`, `Secure`, `Signed`; eine passende Apple-Richtlinie, ein echter signierter Vault und Apple-signierte Recovery müssen später qualifiziert werden. |
| `UEFI/Quirks/DisableSecurityPolicy` | Bleibt `false`. |
| `UEFI/APFS/MinDate`, `MinVersion` | Bleiben `0`, also die OpenCore-Mindeststände; `-1` für beliebig alte Treiber ist ausgeschlossen. |
| `UEFI/AppleInput/AppleEvent`, `GraphicsInputMirroring` | `Builtin` und `true`, damit die Windows-BitLocker-Oberfläche Tastatureingaben erhalten kann. |
| `Kernel/Quirks/XhciPortLimit` | Bleibt `false`; es ist keine korrekte USB-Portzuordnung für Tahoe. |
| `csr-active-config` | Explizit vier Nullbytes im Apple-NVRAM-Namensraum; kein vorgeschlagener SIP-Abbau. |
| `ExposeSensitiveData` | `0`, um die öffentliche Vorbereitung ohne sensible Bootdaten zu halten. |

Die Sample-Maske `0x010F0103` enthält keine USB-Freigabe und keine ESP-/HFS-Freigabe. Sie ist daher kein geeigneter unveränderter Ausgangswert für unsere gewünschte externe Recovery und Windows-Erkennung. `ScanPolicy=0` würde die gesamte Beschränkung entfernen; der Vorschlag verwendet stattdessen die begrenzte Maske. USB-SATA-Gehäuse können von der Firmware als SATA oder SCSI klassifiziert werden. Diese Erkennung und das tatsächliche Picker-Menü müssen am ausgewählten Gehäuse geprüft werden. Die Maske bindet keine bestimmte SSD: ein weiterer erlaubter Datenträger kann ebenfalls erscheinen.

Die öffentliche Vorlage ersetzt den im Release nicht mitgelieferten `HfsPlus.efi`-Sampleeintrag durch den vorhandenen `OpenHfsPlus.efi`. Sie aktiviert nur diesen Dateisystemtreiber und `OpenRuntime.efi`, enthält keine Hardware-Kexts und keine ACPI-Patches. SMBIOS-Identität und CPUID-Emulation bleiben bewusst leer beziehungsweise null. Ein vorgeschlagener Wert ist keine bereits in einer EFI angewendete Einstellung.

Der eigene Validator setzt eine engere, dokumentierte Projekt-Richtlinie als OpenCore selbst. Beispielsweise ist `DmgLoading=Signed` hier für die geplante Recovery erforderlich; für einen später vollständig installierten Aufbau kann ein separat überprüftes Profil ohne Recovery sinnvoll sein. Das Modul behauptet nicht, dass jeder andere dokumentierte OpenCore-Wert generell defekt sei.

Beleg: [OpenCore-Konfiguration 1.0.8](https://github.com/acidanthera/OpenCorePkg/blob/6fe4d15cb66596d99d8cfedce69d8fc6dad71886/Docs/Configuration.tex), Abschnitte ScanPolicy, APFS, Windows-Unterstützung, AppleInput und UpdateSMBIOSMode.
