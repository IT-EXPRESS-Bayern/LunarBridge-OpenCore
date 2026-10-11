# SPDX-License-Identifier: GPL-3.0-only
# Read-only review/preflight. No disk, EFI, BCD, firmware or policy changes.
#requires -Version 7.0
[CmdletBinding()]
param(
    [ValidateSet('CaptureIdentity', 'Plan', 'Preflight', 'Apply')]
    [string] $Mode = 'Preflight',
    [switch] $BackupConfirmed,
    [switch] $EntireExternalDiskAuthorized,
    [ValidateSet('strict-secure-boot', 'temporary-native-test')]
    [string] $Profile = 'strict-secure-boot',
    [ValidatePattern('^[a-z0-9][a-z0-9-]{0,63}$')]
    [string] $StageName = 'external-ssd-review-001'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'SsdPreparation.Core.psm1') -Force

function Write-SsdPrivateJson {
    param([string] $Name, $Value, [switch] $CreateNew)
    $Path = Assert-SsdLocalRegularPath -Root $SsdPrivateRoot -RelativePath $Name -AllowMissingLeaf
    $Data = [Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $Value -Depth 16) + "`n")
    if ($CreateNew) {
        $Stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $Stream.Write($Data, 0, $Data.Length); $Stream.Flush($true) } finally { $Stream.Dispose() }
        return
    }
    $TemporaryName = 'private-write-' + [guid]::NewGuid().ToString('N') + '.tmp'
    $TemporaryPath = Assert-SsdLocalRegularPath -Root $SsdPrivateRoot -RelativePath $TemporaryName -AllowMissingLeaf
    try {
        $Stream = [IO.File]::Open($TemporaryPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $Stream.Write($Data, 0, $Data.Length); $Stream.Flush($true) } finally { $Stream.Dispose() }
        [IO.File]::Move($TemporaryPath, $Path, $true)
    } finally {
        if ([IO.File]::Exists($TemporaryPath)) { [IO.File]::Delete($TemporaryPath) }
    }
}

try {
    # Apply is intentionally unavailable: OpenCore currently defines no trusted
    # qualification contract. Flipping manifest booleans cannot enable erasure.
    if ($Mode -eq 'Apply') {
        [Console]::Error.WriteLine('SSD_APPLY_BLOCKED: native boot qualification required; no destructive execution path exists.')
        exit 4
    }
    [void](Get-SsdFirmwareProfileReview -Profile $Profile)
    if (-not $IsWindows) { throw 'WINDOWS_REQUIRED' }
    $RepositoryRoot = Assert-SsdOrdinaryRoot ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')))
    $SsdPrivateRoot = Initialize-SsdPrivateDirectory $RepositoryRoot
    $Disks = @(Get-Disk -ErrorAction Stop)
    $IdentityName = 'target-identity.private.json'
    if ($Mode -eq 'CaptureIdentity') {
        $Candidates = @($Disks | Where-Object { $_.Number -eq 1 })
        if ($Candidates.Count -ne 1) { throw 'EXACT_EXTERNAL_DEVICE_NOT_CONFIRMED' }
        $Identity = New-SsdPrivateIdentity -Disk $Candidates[0]
        Write-SsdPrivateJson -Name $IdentityName -Value $Identity -CreateNew
        [Console]::WriteLine('Private external-SSD identity captured; no device changed.')
        exit 0
    }
    $IdentityPath = Assert-SsdLocalRegularPath -Root $SsdPrivateRoot -RelativePath $IdentityName
    $Identity = Read-SsdBoundedJson -Path $IdentityPath -MaximumBytes 16384
    $Target = Resolve-SsdIdentity -Identity $Identity -Disks $Disks
    $Partitions = @(Get-Partition -DiskNumber $Target.Number -ErrorAction Stop)
    $PartitionSummary = @($Partitions | ForEach-Object {
        [ordered]@{ number = [int]$_.PartitionNumber; offset_bytes = [uint64]$_.Offset;
            size_bytes = [uint64]$_.Size; gpt_type = [string]$_.GptType }
    })
    $IsAdministrator = ([Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    $Firmware = [ordered]@{ state = 'requires-administrator'; enabled = $null; external_chain_verified = $false }
    if ($IsAdministrator) {
        try {
            $Firmware.enabled = [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
            $Firmware.state = if ($Firmware.enabled) { 'enabled' } else { 'disabled' }
        } catch { $Firmware.state = 'unverified-query-unavailable' }
    }
    $FirmwareProfile = Get-SsdFirmwareProfileReview -Profile $Profile -FirmwareEnabled $Firmware.enabled
    $AssemblyRelative = 'private/assembly/' + $StageName + '/assembly-manifest.json'
    $ManifestPath = Assert-SsdLocalRegularPath -Root $RepositoryRoot -RelativePath $AssemblyRelative
    $Manifest = Read-SsdBoundedJson -Path $ManifestPath
    $Staging = Test-SsdStagedSnapshot -Root ([IO.Path]::GetDirectoryName($ManifestPath)) -Manifest $Manifest
    $Layout = Get-SsdLayoutPlan -DiskBytes $Target.Size -StagedBytes $Staging.bytes_verified
    $Gates = @(
        [ordered]@{ code = 'BACKUP_USER_CONFIRMED'; satisfied = [bool]$BackupConfirmed }
        [ordered]@{ code = 'ENTIRE_EXTERNAL_DISK_AUTHORIZED'; satisfied = [bool]$EntireExternalDiskAuthorized }
        [ordered]@{ code = 'EXACT_EXTERNAL_USB_IDENTITY_BOUND'; satisfied = $true }
        [ordered]@{ code = 'INTERNAL_AND_VIRTUAL_DISKS_EXCLUDED'; satisfied = $true }
        [ordered]@{ code = 'ADMINISTRATOR'; satisfied = $IsAdministrator }
        [ordered]@{ code = 'STAGING_INVENTORY_HASHES_AND_ESP_CAPACITY'; satisfied = $Staging.hash_integrity_verified }
        [ordered]@{ code = 'QUALIFIED_BOOT_BUNDLE'; satisfied = $false }
        [ordered]@{ code = 'WINDOWS_MACOS_BOOT_CHOICE_CONFIGURED'; satisfied = $false }
    ) + @($FirmwareProfile.gates)
    foreach ($Gate in $Gates) {
        if (-not $Gate.Contains('required')) { $Gate.required = $true }
    }
    $Report = [ordered]@{
        schema_version = 1
        mode = $Mode.ToLowerInvariant()
        state = $(if ($FirmwareProfile.firmware_secure_boot_required) {
            'blocked-awaiting-qualified-boot-bundle-and-secure-chain'
        } else { 'blocked-awaiting-native-test-qualification' })
        profile_policy = $FirmwareProfile
        execution_supported = $false
        disk_writes_performed = 0
        firmware_or_bcd_changes_performed = 0
        administrator_elevation_attempted = $false
        target = [ordered]@{ number = [int]$Target.Number; bus_type = 'USB'; size_bytes = [uint64]$Target.Size;
            is_boot = $false; is_system = $false; current_partitions = $PartitionSummary }
        identity = [ordered]@{ exact_private_path_and_unique_id_match = $true;
            serial_not_accepted_as_identity = $true; identifiers_omitted = $true }
        backup = [ordered]@{ user_confirmation_supplied = [bool]$BackupConfirmed;
            current_process_backup_scan_performed = $false }
        administrator = $IsAdministrator
        firmware_secure_boot = $Firmware
        existing_staging = $Staging
        proposed_layout = $Layout
        gates = $Gates
        unmet_gates = @($Gates | Where-Object { $_.required -and -not $_.satisfied } | ForEach-Object { $_.code })
        constraints = @('NO_QUALIFICATION_SCHEMA_CAN_AUTHORIZE_ERASURE_YET',
            'RECOVERY_NEEDS_KNOWN_WORKING_NATIVE_NETWORK',
            'EXTERNAL_USB_PORT_MAPPING_AND_CPU_BOOT_CONFIG_PENDING',
            'ONLY_RAW_TARGET_PARTITION_MAY_BE_ERASED_FROM_RECOVERY',
            'OPENCORE_PICKER_AND_FIRMWARE_BOOT_ORDER_ARE_DISTINCT',
            'APPLE_SECUREBOOTMODEL_IS_NOT_FIRMWARE_SECURE_BOOT')
    }
    Write-SsdPrivateJson -Name 'preflight-report.private.json' -Value $Report
    [Console]::WriteLine('SSD plan checked: exact external device matched; no device changed.')
    [Console]::WriteLine('Execution blocked: native qualification and the selected firmware condition remain pending.')
    exit 2
} catch {
    [Console]::Error.WriteLine('SSD_PREFLIGHT_FAILED: invalid input, unavailable read-only query or private report write failure.')
    exit 3
}
