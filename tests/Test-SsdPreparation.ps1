# SPDX-License-Identifier: GPL-3.0-only
# Pure-input/failure tests. Fixtures/reports stay private; no real device queries.
#requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RepositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$SsdToolsRoot = Join-Path $RepositoryRoot 'tools'
Import-Module (Join-Path $SsdToolsRoot 'SsdPreparation.Core.psm1') -Force
$SsdPrivateRoot = Initialize-SsdPrivateDirectory $RepositoryRoot
$SsdTestResults = [Collections.Generic.List[object]]::new()
$SsdFixtureRoot = Initialize-SsdPrivateDirectory $RepositoryRoot ('fixtures/test-' + [guid]::NewGuid().ToString('N'))

function Assert-SsdReview {
    param([bool] $Condition, [string] $Code = 'ASSERTION_FAILED')
    if (-not $Condition) { throw $Code }
}
function Assert-SsdRefusal {
    param([scriptblock] $Action)
    $Refused = $false
    try { & $Action | Out-Null } catch { $Refused = $true }
    Assert-SsdReview $Refused
}
function Invoke-SsdReviewCase {
    param([string] $Name, [scriptblock] $Action)
    try {
        & $Action | Out-Null
        $SsdTestResults.Add([ordered]@{ case = $Name; passed = $true })
    } catch {
        $SsdTestResults.Add([ordered]@{ case = $Name; passed = $false; code = 'CHECK_FAILED' })
    }
}
function New-FakeSsd {
    return [pscustomobject]@{ Number = 1; BusType = 'USB'; Size = [uint64]512110190592;
        IsBoot = $false; IsSystem = $false; IsOffline = $false; IsReadOnly = $false;
        PartitionStyle = 'GPT'; UniqueId = 'test-external-unique'; Path = 'test-external-path';
        FriendlyName = 'Test external USB SSD'; SerialNumber = '000000000000' }
}

Invoke-SsdReviewCase 'internal-virtual-system-and-offline-targets-refused' {
    foreach ($Pair in @(@('Number', 0), @('Number', 2), @('BusType', 'NVMe'),
        @('IsBoot', $true), @('IsSystem', $true), @('IsOffline', $true),
        @('IsReadOnly', $true), @('Size', [uint64]512110190080), @('PartitionStyle', 'RAW'))) {
        $Disk = New-FakeSsd
        $Disk.($Pair[0]) = $Pair[1]
        Assert-SsdReview (-not (Test-SsdTarget $Disk))
    }
}
Invoke-SsdReviewCase 'exact-device-selected-no-serial-or-number-fallback' {
    $Disk = New-FakeSsd
    $Binding = New-SsdPrivateIdentity $Disk
    Assert-SsdReview $Binding.serial_is_not_unique
    Assert-SsdReview ((Resolve-SsdIdentity $Binding @($Disk)).Number -eq 1)
    $Disk.Path = 'different-usb-port-path'
    Assert-SsdRefusal { Resolve-SsdIdentity $Binding @($Disk) }
    $Disk = New-FakeSsd
    $Disk.UniqueId = 'different-unique-id'
    Assert-SsdRefusal { Resolve-SsdIdentity $Binding @($Disk) }
}
Invoke-SsdReviewCase 'ambiguous-or-reassigned-identity-refused' {
    $Disk = New-FakeSsd
    $Binding = New-SsdPrivateIdentity $Disk
    $Other = New-FakeSsd
    $Other.Number = 2
    Assert-SsdRefusal { Resolve-SsdIdentity $Binding @($Disk, $Other) }
    $Disk.Number = 0
    Assert-SsdRefusal { Resolve-SsdIdentity $Binding @($Disk) }
    $Binding.unique_id = ''
    Assert-SsdRefusal { Resolve-SsdIdentity $Binding @((New-FakeSsd)) }
}
Invoke-SsdReviewCase 'truthy-strings-cannot-certify-non-system-device' {
    $Disk = New-FakeSsd
    $Disk.IsSystem = 'false'
    Assert-SsdReview (-not (Test-SsdTarget $Disk))
}
Invoke-SsdReviewCase 'manifest-path-traversal-rooted-path-and-directory-refused' {
    foreach ($BadPath in @('../outside.json', '/outside.json', 'EFI/../config.plist',
        'EFI//config.plist', 'C:/outside.json', 'EFI\config.plist', '.')) {
        Assert-SsdRefusal { Assert-SsdLocalRegularPath $SsdFixtureRoot $BadPath }
    }
    [void][IO.Directory]::CreateDirectory((Join-Path $SsdFixtureRoot 'directory-input'))
    Assert-SsdRefusal { Assert-SsdLocalRegularPath $SsdFixtureRoot 'directory-input' }
    Assert-SsdRefusal { Initialize-SsdPrivateDirectory $RepositoryRoot '../outside' }
    Assert-SsdRefusal { Initialize-SsdPrivateDirectory $RepositoryRoot 'CON' }
    Assert-SsdReview ([IO.Path]::GetRelativePath($RepositoryRoot, $SsdFixtureRoot).Replace('\', '/').StartsWith('private/ssd/fixtures/'))
    $EfiRoot = Join-Path $SsdFixtureRoot 'EFI'
    [void][IO.Directory]::CreateDirectory($EfiRoot)
    Assert-SsdRefusal { Initialize-SsdPrivateDirectory $EfiRoot }
}

$FixturePaths = @('EFI/BOOT/BOOTx64.efi', 'EFI/OC/OpenCore.efi', 'EFI/OC/config.plist',
    'EFI/OC/Drivers/OpenRuntime.efi', 'EFI/OC/Drivers/OpenHfsPlus.efi',
    'com.apple.recovery.boot/BaseSystem.dmg', 'com.apple.recovery.boot/BaseSystem.chunklist')
$FixtureEntries = @($FixturePaths | ForEach-Object {
    $FilePath = Join-Path $SsdFixtureRoot $_
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($FilePath))
    [IO.File]::WriteAllBytes($FilePath, [Text.Encoding]::ASCII.GetBytes('small-fixture-not-an-efi-or-apple-image'))
    @{ path = $_; bytes = [long]([IO.FileInfo]$FilePath).Length;
        sha256 = (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256).Hash.ToLowerInvariant() }
})
$FixtureManifest = @{ schema_version = 1; kind = 'private_unsigned_offline_snapshot';
    inspection_only = $true; ready_for_boot = $false; manifest_is_authenticated = $false;
    files = $FixtureEntries; upstream_validator = @{ schema_passed = $false };
    recovery = @{ chunklist_rsa_sha256_verified = $false; image_chunks_verified = $false;
        os_version_verified = $false } }

Invoke-SsdReviewCase 'inventory-hashes-never-certify-boot-or-secure-chain' {
    $Review = Test-SsdStagedSnapshot $SsdFixtureRoot $FixtureManifest
    Assert-SsdReview ($Review.hash_integrity_verified -and $Review.files_verified -eq 7)
    Assert-SsdReview (-not $Review.qualified_boot_bundle -and -not $Review.secure_chain_verified)
    Assert-SsdReview (-not $Review.recovery_signature_reported_verified)
}
Invoke-SsdReviewCase 'manually-edited-qualification-booleans-and-strings-refused' {
    foreach ($Field in @('ready_for_boot', 'manifest_is_authenticated')) {
        $Original = $FixtureManifest[$Field]
        foreach ($Invalid in @($true, 'false', 0)) {
            $FixtureManifest[$Field] = $Invalid
            $Review = Test-SsdStagedSnapshot $SsdFixtureRoot $FixtureManifest
            Assert-SsdReview (-not $Review.hash_integrity_verified -and -not $Review.qualified_boot_bundle)
        }
        $FixtureManifest[$Field] = $Original
    }
    $FixtureManifest.schema_version = $true
    Assert-SsdReview (-not (Test-SsdStagedSnapshot $SsdFixtureRoot $FixtureManifest).hash_integrity_verified)
    $FixtureManifest.schema_version = 1
}
Invoke-SsdReviewCase 'changed-file-content-and-duplicate-inventory-refused' {
    $Path = Join-Path $SsdFixtureRoot $FixtureEntries[0].path
    $Before = [IO.File]::ReadAllBytes($Path)
    $Changed = $Before.Clone()
    $Changed[0] = 88
    [IO.File]::WriteAllBytes($Path, $Changed)
    Assert-SsdReview (-not (Test-SsdStagedSnapshot $SsdFixtureRoot $FixtureManifest).hash_integrity_verified)
    [IO.File]::WriteAllBytes($Path, $Before)
    $Previous = $FixtureManifest.files
    $FixtureManifest.files = @($FixtureEntries[0], $FixtureEntries[0]) + @($FixtureEntries[2..6])
    Assert-SsdReview (-not (Test-SsdStagedSnapshot $SsdFixtureRoot $FixtureManifest).hash_integrity_verified)
    $FixtureManifest.files = $Previous
    $Unlisted = Join-Path $SsdFixtureRoot 'unlisted.bin'
    [IO.File]::WriteAllBytes($Unlisted, [byte[]]@(1))
    Assert-SsdReview (-not (Test-SsdStagedSnapshot $SsdFixtureRoot $FixtureManifest).hash_integrity_verified)
    [IO.File]::Delete($Unlisted)
}
Invoke-SsdReviewCase '2gib-esp-recovery-capacity-and-fat32-limits-enforced' {
    $Plan = Get-SsdLayoutPlan 512110190592 961265615
    Assert-SsdReview ($Plan.first_partition.size_bytes -eq 2GB -and
        $Plan.first_partition.offset_bytes -eq 1MB -and
        $Plan.second_partition.windows_file_system -ceq 'RAW-unformatted' -and
        $Plan.second_partition.estimated_size_bytes -gt 400GB -and
        $Plan.installation_preserves_first_partition)
    Assert-SsdRefusal { Get-SsdLayoutPlan 512110190592 (2GB - 64MB + 1) }
    Assert-SsdRefusal { Get-SsdLayoutPlan 1GB 961265615 }
}
Invoke-SsdReviewCase 'oversized-and-malformed-manifests-refused-before-use' {
    $Path = Join-Path $SsdFixtureRoot 'manifest-test.json'
    [IO.File]::WriteAllBytes($Path, [byte[]]::new(262145))
    Assert-SsdRefusal { Read-SsdBoundedJson $Path }
    [IO.File]::WriteAllText($Path, '{invalid')
    Assert-SsdRefusal { Read-SsdBoundedJson $Path }
}
Invoke-SsdReviewCase 'preflight-ast-has-no-destructive-command-or-elevation-path' {
    $Forbidden = @('Clear-Disk', 'Initialize-Disk', 'New-Partition', 'Remove-Partition',
        'Set-Partition', 'Set-Disk', 'Format-Volume', 'Add-PartitionAccessPath',
        'Mount-DiskImage', 'Dismount-DiskImage', 'Start-Process', 'Invoke-Expression',
        'Set-SecureBootUEFI', 'Set-ExecutionPolicy', 'mountvol', 'bcdedit', 'diskpart')
    foreach ($Source in @('SsdPreparation.Core.psm1', 'Prepare-ExternalSsd.ps1')) {
        $Tokens = $null; $ParseErrors = $null
        $Ast = [Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $SsdToolsRoot $Source), [ref]$Tokens, [ref]$ParseErrors)
        Assert-SsdReview ($ParseErrors.Count -eq 0)
        $Commands = $Ast.FindAll({ param($Node) $Node -is [Management.Automation.Language.CommandAst] }, $true)
        foreach ($Command in $Commands) {
            $Name = $Command.GetCommandName()
            Assert-SsdReview ($null -ne $Name -and $Name -notin $Forbidden)
        }
    }
}

$Failed = @($SsdTestResults | Where-Object { -not $_.passed }).Count
$Result = [ordered]@{ test_type = 'private-boundary-and-failure-tests-no-real-disk-queries';
    tests_run = $SsdTestResults.Count; failures = $Failed; successful = ($Failed -eq 0);
    disk_writes = 0; target_boot_tests = 0; cases = $SsdTestResults }
[IO.File]::WriteAllText((Join-Path $SsdPrivateRoot 'tests.private.json'),
    (ConvertTo-Json $Result -Depth 8) + "`n", [Text.UTF8Encoding]::new($false))
[Console]::WriteLine(('SSD boundary tests: {0}/{1} passed; no real device changed.' -f ($SsdTestResults.Count - $Failed), $SsdTestResults.Count))
if ($Failed) { exit 1 }
exit 0
