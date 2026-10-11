# Samsung-BIOS: Sichtpruefung fuer Secure Boot

Die Ergaenzung eines eigenen Vertrauensankers unter Beibehaltung der Microsoft-/OEM-Schluessel ist auf dem Galaxy Book5 Pro NP960XHA-KG3DE weiterhin unbestaetigt. Die native macOS-Installation auf der externen SSD mit aktiviertem Firmware-Secure-Boot bleibt das Ziel.

## Aktueller Befund vom 11. Oktober 2026

| Pruefung | Ergebnis |
| --- | --- |
| Von Windows gemeldetes Modell | Samsung 960XHA |
| BIOS-Version | P11AMA.220.260526.02 |
| BIOS-Datum | 26. Mai 2026 |
| Windows-Register `UEFISecureBootEnabled` | 0, Hinweis auf deaktiviertes Secure Boot |
| Direkte Abfrage `Confirm-SecureBootUEFI` | Zugriff mangels Administratorrechten verweigert; Status unbestaetigt |
| Custom-Modus, Zertifikatsimport und Erhalt vorhandener Schluessel | Noch nicht am BIOS geprueft |
| Externe OpenCore-Bootkette auf diesem Samsung | Noch nicht angenommen oder gestartet |

Ein Registerwert ersetzt keine erfolgreiche Firmware-Abfrage. Ein administrativer, rein lesender Aufruf von `Confirm-SecureBootUEFI` kann den aktuellen Aktivierungszustand klaeren, jedoch keine Importfunktion im BIOS nachweisen.

## Sichtpruefung beim naechsten selbst gewaehlten Neustart

1. Vor dem Samsung-Logo mehrfach **F2** druecken.
2. Die Menues **Boot** und **Security** aufrufen und die Secure-Boot-Eintraege samt aktuellen Werten ablesen.
3. Falls angezeigt, Untermenues zur Schluesselverwaltung ansehen. Gesuchte Funktionen sind ein Custom-Modus oder das Hinzufuegen eines Zertifikats zur erlaubten Signaturdatenbank `db`. Die genauen Bezeichnungen und die Verfuegbarkeit auf diesem BIOS sind unbekannt.
4. Die sichtbaren Menues fotografieren oder die Optionen wortgetreu notieren. Ein reiner Ein-/Aus-Schalter oder die Auswahl vorgegebener Zertifikatssaetze bestaetigt noch keinen eigenen Zertifikatsimport. Auch eine Importfunktion alleine beweist noch nicht, dass vorhandene Eintraege erhalten bleiben.
5. Fuer diese Sichtpruefung keine Werte, Passwoerter oder Schluessel veraendern. Das deutsche Handbuch beschreibt **Exit -> OK** als Beenden ohne Speichern. Keine Default-/Reset-/Clear-Key-Aktion ausfuehren.

Das deutsche Samsung-Handbuch bestaetigt F2 und die Menuegruppen auf Seiten 46-47 sowie das Verlassen ohne Speichern auf Seite 49. Die englische Fassung beschreibt dasselbe auf Seiten 45-46 und 48. Beide nennen moegliche Unterschiede je nach BIOS-Version; ein Custom-Key-Import ist in diesen Abschnitten nicht dokumentiert. Das ist kein Nachweis fehlender Hardwareunterstuetzung.

## Primaerquellen und weitere Abgrenzung

- [Samsung-Support fuer NP960XHA-KG3DE](https://www.samsung.com/de/support/model/NP960XHA-KG3DE/) mit den offiziellen Handbuchdownloads.
- [Deutsches Originalhandbuch, Rev. 3.0](https://downloadcenter.samsung.com/content/UM/202603/20260309141255245/94xXHA_96xXHA_Win11_UG_GER_Rev.3.0_260211.pdf), SHA-256 `2d91b5eb837ef41dad2fe636c17f59b7634c5992764c757ff31689a020e649bf`.
- [Englisches Originalhandbuch, Rev. 3.1](https://downloadcenter.samsung.com/content/UM/202609/20260904134634044/94xXHA_96xXHA_Win11_UG_EU_ENG_Rev.3.1_260803.pdf), SHA-256 `31423b6255b3bc7b58238038ecf4fd98befd8501ed41574650232bb0f41e14b8`.
- [Microsoft: Secure-Boot-Schluesselverwaltung](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-secure-boot-key-creation-and-management-guidance?view=windows-11).
- [Samsung: BIOS-Verwaltung mit oeffentlichen Schluesseln](https://docs.samsungknox.com/admin/fundamentals/whitepaper/samsung-knox-for-pc/secure-manageability/) betrifft die Authentifizierung fuer BIOS-Verwaltung. Diese Schluessel sind kein Nachweis eines eigenen UEFI-Bootzertifikats in `db`.

Nach bestaetigter Importmoeglichkeit muessen die fertigen EFI-Komponenten passend signiert, Windows-Vertrauensanker erhalten und die externe Bootkette auf dem Zielgeraet geprueft werden. [Die getrennten Sicherheitspruefungen](SECURE_BOOT.md) bleiben erforderlich. Diese Recherche hat keine Firmware-, Boot-, Partitions- oder Sicherheitseinstellung veraendert; die SSD-Vorbereitung bleibt vor einer echten Installation unvollstaendig.
