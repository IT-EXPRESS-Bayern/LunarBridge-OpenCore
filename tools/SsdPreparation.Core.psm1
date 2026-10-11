# SPDX-License-Identifier: GPL-3.0-only
# Read-only SSD review helper. No partition, boot-entry or firmware writes.
#requires -Version 7.0
Set-StrictMode -Version Latest

function Assert-SsdOrdinaryRoot {
    param([Parameter(Mandatory)] [string] $Root)
    $RootFull = [IO.Path]::GetFullPath($Root)
    $Current = [IO.DirectoryInfo]::new($RootFull)
    while ($null -ne $Current) {
        $Entry = Get-Item -LiteralPath $Current.FullName -Force -ErrorAction Stop
        if (-not $Entry.PSIsContainer -or
            ($Entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'ROOT_PATH_REFUSED' }
        $Current = $Current.Parent
    }
    return $RootFull
}

function Initialize-SsdPrivateDirectory {
    param([Parameter(Mandatory)] [string] $RepositoryRoot, [string] $Subdirectory = '')
    $Current = Assert-SsdOrdinaryRoot $RepositoryRoot
    $Ancestor = [IO.DirectoryInfo]::new($Current)
    while ($null -ne $Ancestor) {
        if ($Ancestor.Name -in @('EFI', 'BOOT', 'com.apple.recovery.boot')) { throw 'PRIVATE_WORKSPACE_REFUSED' }
        $Ancestor = $Ancestor.Parent
    }
    if ($Subdirectory -and ($Subdirectory.Length -gt 128 -or
        $Subdirectory -notmatch '^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$')) { throw 'PRIVATE_PATH_REFUSED' }
    $Parts = @('private', 'ssd')
    if ($Subdirectory) { $Parts += $Subdirectory.Split('/') }
    foreach ($Part in $Parts) {
        if ($Part -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') { throw 'PRIVATE_PATH_REFUSED' }
        $Current = Join-Path $Current $Part
        if (-not (Test-Path -LiteralPath $Current)) { [void][IO.Directory]::CreateDirectory($Current) }
        $Entry = Get-Item -LiteralPath $Current -Force -ErrorAction Stop
        if (-not $Entry.PSIsContainer -or
            ($Entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'PRIVATE_PATH_REFUSED' }
    }
    return $Current
}

function Test-SsdTarget {
    param([Parameter(Mandatory)] $Disk)
    try {
        return ([int]$Disk.Number -eq 1 -and [string]$Disk.BusType -ceq 'USB' -and
            [uint64]$Disk.Size -eq 512110190592 -and
            $Disk.IsBoot -is [bool] -and -not $Disk.IsBoot -and
            $Disk.IsSystem -is [bool] -and -not $Disk.IsSystem -and
            $Disk.IsOffline -is [bool] -and -not $Disk.IsOffline -and
            $Disk.IsReadOnly -is [bool] -and -not $Disk.IsReadOnly -and
            [string]$Disk.PartitionStyle -ceq 'GPT' -and
            -not [string]::IsNullOrWhiteSpace([string]$Disk.UniqueId) -and
            -not [string]::IsNullOrWhiteSpace([string]$Disk.Path))
    } catch { return $false }
}

function New-SsdPrivateIdentity {
    param([Parameter(Mandatory)] $Disk)
    if (-not (Test-SsdTarget $Disk)) { throw 'TARGET_IDENTITY_CAPTURE_REFUSED' }
    return [ordered]@{
        schema_version = 1
        privacy = 'local-only-do-not-publish'
        captured_utc = [datetime]::UtcNow.ToString('o')
        number = [int]$Disk.Number
        bus_type = [string]$Disk.BusType
        size = [uint64]$Disk.Size
        friendly_name = [string]$Disk.FriendlyName
        unique_id = [string]$Disk.UniqueId
        path = [string]$Disk.Path
        serial_is_not_unique = ([string]$Disk.SerialNumber).Trim() -match '^0+$'
    }
}

function Resolve-SsdIdentity {
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Identity,
          [Parameter(Mandatory)] [object[]] $Disks)
    if ($Disks.Count -gt 32 -or $Identity['schema_version'] -ne 1 -or
        $Identity['number'] -ne 1 -or $Identity['bus_type'] -cne 'USB' -or
        $Identity['size'] -ne 512110190592 -or
        [string]::IsNullOrWhiteSpace([string]$Identity['unique_id']) -or
        [string]::IsNullOrWhiteSpace([string]$Identity['path'])) {
        throw 'IDENTITY_BINDING_INVALID'
    }
    $Matches = @($Disks | Where-Object {
        [string]::Equals([string]$_.UniqueId, [string]$Identity['unique_id'],
                         [StringComparison]::OrdinalIgnoreCase) -and
        [string]::Equals([string]$_.Path, [string]$Identity['path'],
                         [StringComparison]::OrdinalIgnoreCase)
    })
    if ($Matches.Count -ne 1 -or -not (Test-SsdTarget $Matches[0]) -or
        -not [string]::Equals([string]$Matches[0].FriendlyName,
            [string]$Identity['friendly_name'], [StringComparison]::OrdinalIgnoreCase)) {
        throw 'EXACT_EXTERNAL_DEVICE_NOT_CONFIRMED'
    }
    return $Matches[0]
}

function Assert-SsdLocalRegularPath {
    param([Parameter(Mandatory)] [string] $Root,
          [Parameter(Mandatory)] [string] $RelativePath,
          [switch] $AllowMissingLeaf)
    if ($RelativePath.Length -gt 240 -or $RelativePath -notmatch '^[A-Za-z0-9_.\-/]+$' -or
        $RelativePath.Contains('\') -or [IO.Path]::IsPathRooted($RelativePath)) {
        throw 'STAGING_PATH_REFUSED'
    }
    $Parts = $RelativePath.Split('/')
    if (@($Parts | Where-Object { $_ -in @('', '.', '..') -or $_.EndsWith('.') -or
        $_ -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])($|\.)' }).Count) { throw 'STAGING_PATH_REFUSED' }
    $RootFull = Assert-SsdOrdinaryRoot $Root
    $RootEntry = Get-Item -LiteralPath $RootFull -Force -ErrorAction Stop
    if (-not $RootEntry.PSIsContainer -or
        ($RootEntry.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'STAGING_PATH_REFUSED' }
    $Current = $RootFull
    for ($Index = 0; $Index -lt $Parts.Count; ++$Index) {
        $Current = Join-Path $Current $Parts[$Index]
        if ($AllowMissingLeaf -and $Index -eq $Parts.Count - 1 -and
            -not (Test-Path -LiteralPath $Current)) { return $Current }
        $Entry = Get-Item -LiteralPath $Current -Force -ErrorAction Stop
        if ($Entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'STAGING_PATH_REFUSED' }
        if ($Index -lt $Parts.Count - 1 -and -not $Entry.PSIsContainer) { throw 'STAGING_PATH_REFUSED' }
        if ($Index -eq $Parts.Count - 1 -and $Entry.PSIsContainer) { throw 'NOT_REGULAR_FILE' }
    }
    return $Current
}

function Read-SsdBoundedJson {
    param([Parameter(Mandatory)] [string] $Path, [int] $MaximumBytes = 262144)
    $Stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($Stream.Length -le 0 -or $Stream.Length -gt $MaximumBytes) { throw 'JSON_SIZE_REFUSED' }
        $Reader = [IO.StreamReader]::new($Stream, [Text.UTF8Encoding]::new($false, $true), $true, 4096, $true)
        try { $Text = $Reader.ReadToEnd() } finally { $Reader.Dispose() }
        $Value = ConvertFrom-Json -InputObject $Text -AsHashtable -Depth 16 -ErrorAction Stop
        if ($Value -isnot [System.Collections.IDictionary]) { throw 'JSON_SCHEMA_REFUSED' }
        return $Value
    } finally { $Stream.Dispose() }
}

function Get-SsdLayoutPlan {
    param([uint64] $DiskBytes, [uint64] $StagedBytes)
    $Alignment = [uint64]1MB
    $EspBytes = [uint64]2GB
    $SafetyHeadroom = [uint64]64MB
    if ($DiskBytes -le ($EspBytes + 3 * $Alignment) -or
        $StagedBytes -gt ($EspBytes - $SafetyHeadroom)) { throw 'LAYOUT_CAPACITY_REFUSED' }
    $RawOffset = $Alignment + $EspBytes
    $EndBoundary = $DiskBytes - ($DiskBytes % $Alignment) - $Alignment
    return [ordered]@{
        partition_style = 'GPT'
        excluded_disk_numbers = @(0, 2)
        partition_creation_executed = $false
        first_partition = [ordered]@{
            role = 'external-efi-and-recovery'
            gpt_type = '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
            offset_bytes = $Alignment
            size_bytes = $EspBytes
            file_system = 'FAT32'
            planned_label = 'EFI'
            root_directories = @('EFI', 'com.apple.recovery.boot')
            staged_bytes = $StagedBytes
            reserved_headroom_bytes = $SafetyHeadroom
        }
        second_partition = [ordered]@{
            role = 'macos-install-target'
            initial_gpt_type = '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}'
            offset_bytes = $RawOffset
            estimated_size_bytes = ($EndBoundary - $RawOffset)
            windows_file_system = 'RAW-unformatted'
            future_file_system = 'APFS-created-by-macos-installer'
            actual_size_requires_post_initialize_extent_check = $true
        }
        installation_preserves_first_partition = $true
        tail_reserve_minimum_bytes = $Alignment
        automatic_msr_creation_not_assumed = $true
    }
}

function Test-SsdStagedSnapshot {
    param([Parameter(Mandatory)] [string] $Root,
          [Parameter(Mandatory)] [System.Collections.IDictionary] $Manifest)
    $Refusal = [ordered]@{
        state = 'unverified'
        code = 'STAGING_INVALID_OR_UNSUPPORTED'
        files_verified = 0
        bytes_verified = [uint64]0
        hash_integrity_verified = $false
        qualified_boot_bundle = $false
        secure_chain_verified = $false
    }
    try {
        if (($Manifest['schema_version'] -isnot [int] -and $Manifest['schema_version'] -isnot [long]) -or
            $Manifest['schema_version'] -ne 1 -or
            $Manifest['kind'] -cne 'private_unsigned_offline_snapshot' -or
            $Manifest['inspection_only'] -isnot [bool] -or -not $Manifest['inspection_only'] -or
            $Manifest['ready_for_boot'] -isnot [bool] -or $Manifest['ready_for_boot'] -or
            $Manifest['manifest_is_authenticated'] -isnot [bool] -or $Manifest['manifest_is_authenticated']) {
            $Refusal.code = 'UNSUPPORTED_BOOT_QUALIFICATION_CLAIM'
            return $Refusal
        }
        $RequiredPaths = @('EFI/BOOT/BOOTx64.efi', 'EFI/OC/OpenCore.efi', 'EFI/OC/config.plist',
            'EFI/OC/Drivers/OpenRuntime.efi', 'EFI/OC/Drivers/OpenHfsPlus.efi',
            'com.apple.recovery.boot/BaseSystem.dmg', 'com.apple.recovery.boot/BaseSystem.chunklist')
        $Entries = @($Manifest['files'])
        if ($Entries.Count -ne $RequiredPaths.Count) { throw 'STAGING_INVENTORY_REFUSED' }
        $Seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $BytesVerified = [uint64]0
        foreach ($Entry in $Entries) {
            if ($Entry -isnot [System.Collections.IDictionary]) { throw 'STAGING_INVENTORY_REFUSED' }
            $Relative = [string]$Entry['path']
            if ($Relative -cnotin $RequiredPaths -or -not $Seen.Add($Relative) -or
                $Entry['sha256'] -notmatch '^[a-f0-9]{64}$' -or
                $Entry['bytes'] -isnot [long] -and $Entry['bytes'] -isnot [int]) {
                throw 'STAGING_INVENTORY_REFUSED'
            }
            $ExpectedBytes = [long]$Entry['bytes']
            if ($ExpectedBytes -le 0 -or $ExpectedBytes -gt (2GB - 64MB) -or
                $BytesVerified -gt (2GB - 64MB - $ExpectedBytes)) { throw 'STAGING_SIZE_REFUSED' }
            $Path = Assert-SsdLocalRegularPath -Root $Root -RelativePath $Relative
            $Stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
            try {
                if ($Stream.Length -ne $ExpectedBytes) { throw 'STAGING_LENGTH_MISMATCH' }
                $Digest = (Get-FileHash -InputStream $Stream -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
                if ($Digest -cne [string]$Entry['sha256']) { throw 'STAGING_HASH_MISMATCH' }
            } finally { $Stream.Dispose() }
            $BytesVerified += [uint64]$ExpectedBytes
        }
        # A matching list is insufficient if unlisted files or reparse points
        # have appeared elsewhere in the selected private snapshot.
        $Directories = [Collections.Generic.Stack[string]]::new()
        $Directories.Push((Assert-SsdOrdinaryRoot $Root))
        $DirectoryCount = 0
        $FileCount = 0
        while ($Directories.Count) {
            $Folder = $Directories.Pop()
            if (++$DirectoryCount -gt 256) { throw 'STAGING_INVENTORY_REFUSED' }
            foreach ($Child in @(Get-ChildItem -LiteralPath $Folder -Force -ErrorAction Stop)) {
                if ($Child.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'STAGING_PATH_REFUSED' }
                if ($Child.PSIsContainer) { $Directories.Push($Child.FullName); continue }
                $Relative = [IO.Path]::GetRelativePath($Root, $Child.FullName).Replace('\', '/')
                if ($Relative -ceq 'assembly-manifest.json') { continue }
                if (++$FileCount -gt 7 -or $Relative -cnotin $RequiredPaths) { throw 'STAGING_INVENTORY_REFUSED' }
            }
        }
        if ($FileCount -ne 7) { throw 'STAGING_INVENTORY_REFUSED' }
        $Recovery = $Manifest['recovery']
        return [ordered]@{
            state = 'hash-checked-private-inspection-snapshot'
            code = 'QUALIFIED_BOOT_BUNDLE_AND_SECURE_CHAIN_MISSING'
            files_verified = $Entries.Count
            bytes_verified = $BytesVerified
            hash_integrity_verified = $true
            manifest_is_authenticated = $false
            qualified_boot_bundle = $false
            secure_chain_verified = $false
            upstream_schema_passed = ($Manifest['upstream_validator']['schema_passed'] -eq $true)
            apple_chunklist_signature = 'not-repeated-manifest-report-only'
            recovery_signature_reported_verified = ($Recovery['chunklist_rsa_sha256_verified'] -eq $true)
            recovery_image_chunks_reported_verified = ($Recovery['image_chunks_verified'] -eq $true)
            recovery_native_boot_verified = $false
            recovery_os_version_reported_verified = ($Recovery['os_version_verified'] -eq $true)
            recovery_os_version_verified = $false
        }
    } catch { return $Refusal }
}

Export-ModuleMember -Function Test-SsdTarget, New-SsdPrivateIdentity, Resolve-SsdIdentity,
    Assert-SsdLocalRegularPath, Read-SsdBoundedJson, Get-SsdLayoutPlan, Test-SsdStagedSnapshot,
    Assert-SsdOrdinaryRoot, Initialize-SsdPrivateDirectory
