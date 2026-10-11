# Beiträge

Eigener Code erhält `SPDX-License-Identifier: GPL-3.0-only`. Upstream-Dateien und abgeleitete Konfigurationen behalten ihre ursprünglichen Lizenzhinweise. Private SMBIOS-Kennungen, NVRAM-Abbilder, Schlüssel, persönliche Konfigurationen, Vault-Dateien und interne Pläne oder Arbeitslisten werden nicht versioniert.

Änderungen an der Sicherheitsrichtlinie benötigen einen konkreten fachlichen Beleg und passende Regressionstests. Ein Build, eine Signaturtabelle, eine Deklaration oder ein Schema-Test darf nicht als erfolgreiche Firmware- oder Gerätequalifikation beschrieben werden. Der Generator muss ausdrücklich ausgewählte Quellen erhalten und ausschließlich neue Konfigurationskopien im privaten Arbeitsbereich erzeugen.

Vor dem Einreichen werden `python -m unittest discover -s tests -p "test_*.py" -v` und die originale gepinnte OpenCore-Referenzprüfung ausgeführt. Die aktuelle Quell- und Referenzbindung steht in `reference-lock.json`.

Änderungen an den SSD-Helfern werden zusätzlich mit `pwsh -NoProfile -File tests/Test-SsdPreparation.ps1` geprüft. Diese Tests benötigen keine Datenträger-/Firmwareabfrage. Persönliche Gerätebindungen und Testberichte entstehen ausschließlich unter `private/ssd`; öffentliche SSD-Berichte dürfen keine Geräte-UniqueId, physischen Pfade oder Benutzerpfade enthalten. Der derzeitige Preflight implementiert keinen destruktiven Ausführungspfad.
