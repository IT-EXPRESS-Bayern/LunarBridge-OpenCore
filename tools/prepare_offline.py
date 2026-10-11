#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare and inspect an explicitly selected, private offline OpenCore bundle.

No key generation, signing, firmware enrollment, boot-entry or disk operations.
Recovery chunklist format/public verification key: pinned OpenCore macrecovery;
see NOTICE and docs/OFFLINE_ASSEMBLY.md for retained upstream terms.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import stat
import struct
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('assembly_qualification', ROOT / 'tools' / 'qualify_opencore.py')
Q = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(Q)
MAX_PAYLOAD = 256 * 1024 * 1024
MAX_RECOVERY = 3 * 1024 * 1024 * 1024
MAX_FILES = 4096
MANIFEST = 'assembly-manifest.json'
ROLES = {'config', 'bootstrap', 'opencore', 'efi_driver', 'acpi', 'kext', 'recovery_image', 'recovery_chunklist'}
CHUNK_HEADER = struct.Struct('<4sIBBBxQQQ')
CHUNK = struct.Struct('<I32s')
SHA256_DIGEST_INFO = bytes.fromhex('3031300d060960864801650304020105000420')
# Public, fixed Apple EFI ROM verification modulus; this is not a private key.
APPLE_RECOVERY_MODULUS = int(
    'C3E748CAD9CD384329E10E25A91E43E1A762FF529ADE578C935BDDF9B13F2179D'
    '4855E6FC89E9E29CA12517D17DFA1EDCE0BEBF0EA7B461FFE61D94E2BDF72C1'
    '96F89ACD3536B644064014DAE25A15DB6BB0852ECBD120916318D1CCDEA3C84C92'
    'ED743FC176D0BACA920D3FCF3158AFF731F88CE0623182A8ED67E650515F757459'
    '09F07D415F55FC15A35654D118C55A462D37A3ACDA08612F3F3F6571761EFCCB'
    'CC299AEE99B3A4FD6212CCFFF5EF37A2C334E871191F7E1C31960E010A54E86FA'
    '3F62E6D6905E1CD57732410A3EB0C6B4DEFDABE9F59BF1618758C751CD56CEF851'
    'D1C0EAA1C558E37AC108DA9089863D20E2E7E4BF475EC66FE6B3EFDCF', 16)


def ordinary_path(path: Path, *, directory=False, missing=False) -> Path:
    """Reject links in every ancestor, including junctions on Windows."""
    for part in (path, *path.parents):
        if part.is_symlink() or part.is_junction():
            raise Q.ReviewError('The selected path must not contain links or junctions.')
    if not missing and not (path.is_dir() if directory else path.is_file()):
        raise Q.ReviewError('The selected input is missing or has the wrong file type.')
    return path.resolve(strict=not missing)


def portable_relative(name: str) -> str:
    parts = Q.relative_path(name).parts
    if len(name) > 220:
        raise Q.ReviewError('A payload path exceeds the portable path bound.')
    for part in parts:
        if (part[-1] in {'.', ' '} or any(char in '<>"|?*' for char in part) or
                re.fullmatch(r'CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]', part.split('.')[0], re.I)):
            raise Q.ReviewError('A payload path is not portable to the Windows/FAT preparation layout.')
    return '/'.join(parts)


def load_lock() -> dict:
    return json.loads(Q.read_bounded(ROOT / 'reference-lock.json', 64 * 1024))


def private_parent() -> Path:
    parent = ROOT / 'private' / 'assembly'
    if any(part.casefold() in {'efi', 'boot', 'com.apple.recovery.boot'} for part in parent.parts):
        raise Q.ReviewError('Assembly cannot run inside a real EFI or recovery directory.')
    ordinary_path(parent, missing=True)
    return parent


def stage_path(name: str, *, existing=False) -> Path:
    if not isinstance(name, str) or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', name):
        raise Q.ReviewError('Select a simple lowercase private stage name.')
    portable_relative(name)
    parent = private_parent()
    target = parent / name
    ordinary_path(target, directory=True, missing=not existing)
    if not existing and target.exists():
        raise Q.ReviewError('Existing stages are never overwritten.')
    if not target.resolve(strict=False).is_relative_to(parent.resolve(strict=False)):
        raise Q.ReviewError('Assembly target escapes the private stage root.')
    return target


def archived_files(archive_raw: bytes, names: set[str]) -> dict[str, bytes]:
    files = {}
    with zipfile.ZipFile(io.BytesIO(archive_raw)) as source:
        entries = source.infolist()
        for name in sorted(names):
            portable_relative(name)
            selected = [item for item in entries if item.filename.casefold() == name.casefold()]
            if len(selected) != 1 or selected[0].filename != name:
                raise Q.ReviewError('An original release input is missing, duplicated or case-ambiguous.')
            entry = selected[0]
            mode = entry.external_attr >> 16
            if entry.is_dir() or stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in {0, stat.S_IFREG}):
                raise Q.ReviewError('An archive input is not a regular file.')
            if entry.file_size <= 0 or entry.file_size > Q.MAX_BINARY:
                raise Q.ReviewError('An archive input exceeds the bounded file profile.')
            raw = source.read(entry)
            if len(raw) != entry.file_size:
                raise Q.ReviewError('An archive input is truncated.')
            files[name] = raw
    return files


def inspect_acpi(raw: bytes) -> dict:
    if (len(raw) < 36 or raw[:4] not in {b'SSDT', b'DSDT'} or
            struct.unpack_from('<I', raw, 4)[0] != len(raw) or sum(raw) % 256):
        raise Q.ReviewError('ACPI input needs a complete SSDT/DSDT header and matching length/checksum.')
    return {'header_and_checksum_valid': True, 'darwin_guard_verified': False,
            'windows_effect_verified': False}


def collect_kext(source_oc: Path, entry: dict) -> dict[str, bytes]:
    name = portable_relative(entry.get('BundlePath'))
    if '/' in name or not name.endswith('.kext'):
        raise Q.ReviewError('Use one separate top-level kext bundle for each hardware module.')
    bundle = ordinary_path(source_oc / 'Kexts' / name, directory=True)
    files, pending, total, directories = {}, [(bundle, 0)], 0, 0
    while pending:
        folder, depth = pending.pop()
        directories += 1
        if depth > 16 or directories > 4096:
            raise Q.ReviewError('Kext package nesting exceeds the local bound.')
        for child in sorted(folder.iterdir()):
            if child.is_symlink() or child.is_junction():
                raise Q.ReviewError('Kext packages must not contain links or junctions.')
            if child.is_dir():
                if child.name.casefold().endswith('.kext'):
                    raise Q.ReviewError('Nested kexts need separate explicit module qualification.')
                pending.append((child, depth + 1))
                continue
            relative = portable_relative(child.relative_to(bundle).as_posix())
            raw = Q.read_bounded(child, 32 * 1024 * 1024)
            total += len(raw)
            if total > 128 * 1024 * 1024 or len(files) >= 2048:
                raise Q.ReviewError('Kext package exceeds the bounded package profile.')
            if relative.casefold() in {key.casefold() for key in files}:
                raise Q.ReviewError('Kext package paths collide case-insensitively.')
            files[relative] = raw
    metadata_path = portable_relative(entry.get('PlistPath'))
    if metadata_path != 'Contents/Info.plist' or metadata_path not in files:
        raise Q.ReviewError('This single-module profile requires Contents/Info.plist.')
    if len(files[metadata_path]) > Q.MAX_CONFIG:
        raise Q.ReviewError('Kext metadata exceeds its own bounded plist profile.')
    metadata = Q.load_xml_dictionary(files[metadata_path])
    identifier = metadata.get('CFBundleIdentifier')
    if (metadata.get('CFBundlePackageType') != 'KEXT' or not isinstance(identifier, str) or
            not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{1,254}', identifier) or '.' not in identifier):
        raise Q.ReviewError('Kext metadata needs a valid identifier and KEXT package type.')
    executable = entry.get('ExecutablePath')
    if not isinstance(executable, str):
        raise Q.ReviewError('A kext entry needs a string ExecutablePath.')
    if executable:
        executable = portable_relative(executable)
        binary_name = metadata.get('CFBundleExecutable')
        if (not isinstance(binary_name, str) or '/' in binary_name or
                portable_relative(binary_name) != binary_name or
                executable != 'Contents/MacOS/' + binary_name or executable not in files):
            raise Q.ReviewError('Kext metadata and selected executable must name the same package file.')
        Q.inspect_kext(files[executable])
    elif 'CFBundleExecutable' in metadata:
        raise Q.ReviewError('A codeless kext cannot declare an omitted executable.')
    return {'EFI/OC/Kexts/' + name + '/' + path: raw for path, raw in files.items()}


def validate_chunklist(raw: bytes) -> list[tuple[int, bytes]]:
    if len(raw) < CHUNK_HEADER.size + CHUNK.size + 256 or len(raw) > 4 * 1024 * 1024:
        raise Q.ReviewError('Recovery chunklist is truncated or exceeds its byte bound.')
    magic, size, version, method, signature_method, count, offset, signature_offset = CHUNK_HEADER.unpack_from(raw)
    if (magic != b'CNKL' or size != 36 or version != 1 or method != 1 or signature_method != 1 or
            not 0 < count <= 65536 or offset != 36 or signature_offset != 36 + 36 * count or
            len(raw) != signature_offset + 256):
        raise Q.ReviewError('A complete RSA-signed Apple chunklist is required; hash-only lists are rejected.')
    signature = int.from_bytes(raw[signature_offset:], 'little')
    digest = hashlib.sha256(raw[:signature_offset]).digest()
    expected = b'\x00\x01' + b'\xff' * 202 + b'\x00' + SHA256_DIGEST_INFO + digest
    if (not 0 < signature < APPLE_RECOVERY_MODULUS or
            pow(signature, 65537, APPLE_RECOVERY_MODULUS) != int.from_bytes(expected, 'big')):
        raise Q.ReviewError('The Apple recovery chunklist RSA/SHA-256 signature is invalid.')
    chunks = [CHUNK.unpack_from(raw, offset + index * 36) for index in range(count)]
    if any(not 0 < chunk_size <= Q.MAX_BINARY for chunk_size, _ in chunks) or sum(x[0] for x in chunks) > MAX_RECOVERY:
        raise Q.ReviewError('Recovery chunks exceed the bounded image profile.')
    return chunks


def hash_stream(path: Path, limit: int) -> tuple[str, int]:
    ordinary_path(path)
    if path.stat().st_size > limit:
        raise Q.ReviewError('A selected payload file exceeds its size bound.')
    digest, total = hashlib.sha256(), 0
    with path.open('rb') as handle:
        while block := handle.read(1024 * 1024):
            total += len(block)
            if total > limit:
                raise Q.ReviewError('A selected payload grew beyond its size bound.')
            digest.update(block)
    return digest.hexdigest(), total


def verify_recovery(image: Path, chunklist: Path) -> dict:
    ordinary_path(image)
    ordinary_path(chunklist)
    raw = Q.read_bounded(chunklist, 4 * 1024 * 1024)
    chunks = validate_chunklist(raw)
    expected_size = sum(size for size, _ in chunks)
    if image.stat().st_size != expected_size:
        raise Q.ReviewError('Recovery image size differs from its authenticated chunklist.')
    image_hash = hashlib.sha256()
    with image.open('rb') as handle:
        for chunk_size, expected_hash in chunks:
            digest, remaining = hashlib.sha256(), chunk_size
            while remaining:
                block = handle.read(min(remaining, 1024 * 1024))
                if not block:
                    raise Q.ReviewError('Recovery image is truncated.')
                digest.update(block)
                image_hash.update(block)
                remaining -= len(block)
            if digest.digest() != expected_hash:
                raise Q.ReviewError('A recovery image chunk does not match its authenticated hash.')
        if handle.read(1):
            raise Q.ReviewError('Recovery image has unauthenticated trailing data.')
    return {'chunklist_rsa_sha256_verified': True, 'image_chunks_verified': True,
            'chunks': len(chunks), 'image_bytes': expected_size,
            'image_sha256': image_hash.hexdigest(), 'chunklist_sha256': Q.sha256(raw),
            'os_version_verified': False, 'native_recovery_boot_verified': False}


def validated_payload(archive: Path, config_path: Path, *, source_oc: Path | None = None,
                      inspection_only=False, profile: str = Q.DEFAULT_PROFILE) -> tuple[dict, dict]:
    Q.profile_policy(profile)
    ordinary_path(archive)
    ordinary_path(config_path)
    config, config_raw = Q.load_config(config_path)
    lock = load_lock()
    archive_raw = Q.read_bounded(archive, 16 * 1024 * 1024)
    if len(archive_raw) != lock['release_archive_bytes'] or Q.sha256(archive_raw) != lock['release_archive_sha256']:
        raise Q.ReviewError('Assembly requires the exact pinned original OpenCore 1.0.8 archive.')
    findings = Q.policy_findings(config, profile)
    if any(item['severity'] == 'error' for item in findings):
        raise Q.ReviewError('The selected configuration violates the required secure offline policy.')
    if not inspection_only and any(item['id'] == 'TahoeSMBIOS' for item in findings):
        raise Q.ReviewError('A supported, independently qualified identity is missing; use inspection-only for the public blank template.')
    validator_name = 'ocvalidate.exe' if sys.platform == 'win32' else 'ocvalidate' if sys.platform == 'darwin' else 'ocvalidate.linux'
    validator_entry = 'Utilities/ocvalidate/' + validator_name
    wanted = {'X64/EFI/BOOT/BOOTx64.efi', 'X64/EFI/OC/OpenCore.efi', validator_entry}
    drivers = []
    for entry in config['UEFI']['Drivers']:
        if entry['Enabled']:
            name = portable_relative(entry.get('Path'))
            if '/' in name or not name.endswith('.efi'):
                raise Q.ReviewError('The pinned-release profile accepts only top-level EFI drivers.')
            drivers.append(name)
            wanted.add('X64/EFI/OC/Drivers/' + name)
    if len({name.casefold() for name in drivers}) != len(drivers):
        raise Q.ReviewError('Enabled EFI drivers contain duplicate paths.')
    files = archived_files(archive_raw, wanted)
    if Q.sha256(files[validator_entry]) != lock['ocvalidate_sha256'][validator_name]:
        raise Q.ReviewError('The original validator does not match its pinned executable hash.')
    parent = private_parent()
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='schema-', dir=parent) as temporary:
        temporary_path = Path(temporary)
        validator = temporary_path / validator_name
        validator.write_bytes(files[validator_entry])
        if sys.platform != 'win32':
            validator.chmod(0o755)
        selected = temporary_path / 'selected.plist'
        selected.write_bytes(config_raw)
        upstream = Q.validate_upstream(selected, validator, lock)
    if not upstream['schema_passed']:
        blank = Q.read_bounded(ROOT / 'examples' / 'inspection-template.plist', Q.MAX_CONFIG)
        if not inspection_only or config_raw != blank:
            raise Q.ReviewError('Original ocvalidate rejected the selected configuration.')
    payload = {'EFI/OC/config.plist': {'raw': config_raw, 'role': 'config'}}
    for name, raw in files.items():
        if name == validator_entry:
            continue
        target = name.removeprefix('X64/')
        role = 'bootstrap' if target.startswith('EFI/BOOT/') else 'opencore' if target.endswith('/OpenCore.efi') else 'efi_driver'
        Q.inspect_pe(raw)
        payload[target] = {'raw': raw, 'role': role}
    active_kexts = [entry for entry in config['Kernel']['Add'] if entry['Enabled']]
    active_acpi = [entry for entry in config['ACPI']['Add'] if entry['Enabled']]
    if active_kexts or active_acpi:
        if source_oc is None or source_oc.name.casefold() != 'oc':
            raise Q.ReviewError('Activated hardware inputs require an explicitly selected offline OC source.')
        source_oc = ordinary_path(source_oc, directory=True)
    bundles, identifiers = set(), set()
    for entry in active_kexts:
        files = collect_kext(source_oc, entry)
        bundle = portable_relative(entry['BundlePath'])
        identifier = Q.load_xml_dictionary(files['EFI/OC/Kexts/' + bundle + '/Contents/Info.plist'])['CFBundleIdentifier']
        if bundle.casefold() in bundles or identifier in identifiers:
            raise Q.ReviewError('Hardware module paths or identifiers are duplicated.')
        bundles.add(bundle.casefold())
        identifiers.add(identifier)
        payload.update({name: {'raw': raw, 'role': 'kext'} for name, raw in files.items()})
        if len(payload) > MAX_FILES or sum(len(item['raw']) for item in payload.values()) > MAX_PAYLOAD:
            raise Q.ReviewError('The combined hardware modules exceed the assembly profile.')
    for entry in active_acpi:
        name = portable_relative(entry.get('Path'))
        path, raw = Q.bounded_file(source_oc, 'ACPI/' + name)
        inspect_acpi(raw)
        target = 'EFI/OC/ACPI/' + name
        if target in payload:
            raise Q.ReviewError('An ACPI input is duplicated.')
        payload[target] = {'raw': raw, 'role': 'acpi'}
    names = [portable_relative(name).casefold() for name in payload]
    if len(names) != len(set(names)) or len(payload) > MAX_FILES or sum(len(item['raw']) for item in payload.values()) > MAX_PAYLOAD:
        raise Q.ReviewError('Assembly payload paths collide or exceed the bounded profile.')
    return payload, {'release_version': Q.VERSION, 'release_archive_sha256': Q.sha256(archive_raw),
                     'profile': profile,
                     'configuration_sha256': Q.sha256(config_raw), 'upstream_validator': upstream,
                     'inspection_only': inspection_only, 'enabled_separate_kext_bundles': len(bundles),
                     'platform_and_windows_acpi_verified': False}


def assemble(archive: Path, config_path: Path, name: str, *, source_oc: Path | None = None,
             recovery_dir: Path | None = None, inspection_only=False,
             profile: str = Q.DEFAULT_PROFILE) -> dict:
    policy = Q.profile_policy(profile)
    destination = stage_path(name)
    payload, proof = validated_payload(archive, config_path, source_oc=source_oc,
                                       inspection_only=inspection_only, profile=profile)
    recovery = None
    if recovery_dir is not None:
        ordinary_path(recovery_dir, directory=True)
        if recovery_dir.name != 'com.apple.recovery.boot':
            raise Q.ReviewError('Select the explicit com.apple.recovery.boot source directory.')
        recovery = verify_recovery(recovery_dir / 'BaseSystem.dmg', recovery_dir / 'BaseSystem.chunklist')
    # All selected inputs have passed preflight before the new stage is created.
    destination.mkdir(parents=True, exist_ok=False)
    records = []
    for name, item in sorted(payload.items()):
        target = destination.joinpath(*portable_relative(name).split('/'))
        target.parent.mkdir(parents=True, exist_ok=True)
        ordinary_path(target, missing=True)
        with target.open('xb') as handle:
            handle.write(item['raw'])
        records.append({'path': name, 'bytes': len(item['raw']), 'sha256': Q.sha256(item['raw']), 'role': item['role']})
    if recovery is not None:
        for filename, role, expected in [('BaseSystem.dmg', 'recovery_image', recovery['image_sha256']),
                                         ('BaseSystem.chunklist', 'recovery_chunklist', recovery['chunklist_sha256'])]:
            source = recovery_dir / filename
            ordinary_path(source)
            target = destination / 'com.apple.recovery.boot' / filename
            target.parent.mkdir(exist_ok=True)
            digest, total = hashlib.sha256(), 0
            with source.open('rb') as input_file, target.open('xb') as output_file:
                while block := input_file.read(1024 * 1024):
                    total += len(block)
                    if total > MAX_RECOVERY:
                        raise Q.ReviewError('Recovery grew during the exclusive offline copy.')
                    digest.update(block)
                    output_file.write(block)
            if digest.hexdigest() != expected:
                raise Q.ReviewError('Recovery changed during copy; the incomplete stage has no successful manifest.')
            records.append({'path': 'com.apple.recovery.boot/' + filename, 'bytes': total,
                            'sha256': expected, 'role': role})
    manifest = {'schema_version': 1, 'kind': 'private_unsigned_offline_snapshot', **proof,
                'files': sorted(records, key=lambda item: item['path']), 'recovery': recovery,
                'manifest_is_authenticated': False, 'ready_for_boot': False,
                'keys_generated_or_enrolled': False, 'real_efi_or_disk_modified': False}
    with (destination / MANIFEST).open('x', encoding='utf-8', newline='\n') as handle:
        json.dump(manifest, handle, indent=2)
        handle.write('\n')
    return {'stage_created': True, 'file_count': len(records), 'payload_bytes': sum(item['bytes'] for item in records),
            'profile_policy': policy,
            'configuration_sha256': proof['configuration_sha256'], 'upstream_validator': proof['upstream_validator'],
            'recovery': recovery, 'inspection_only': inspection_only, 'ready_for_boot': False,
            'real_efi_or_disk_modified': False, 'keys_generated_or_enrolled': False}


def load_manifest(stage: Path) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Q.ReviewError('Manifest dictionary keys are duplicated.')
            result[key] = value
        return result
    manifest = json.loads(Q.read_bounded(stage / MANIFEST, 2 * 1024 * 1024), object_pairs_hook=unique)
    if not isinstance(manifest, dict) or type(manifest.get('schema_version')) is not int or manifest['schema_version'] != 1:
        raise Q.ReviewError('Assembly manifest schema is invalid.')
    Q.profile_policy(manifest.get('profile', Q.DEFAULT_PROFILE))
    lock = load_lock()
    if (manifest.get('kind') != 'private_unsigned_offline_snapshot' or manifest.get('release_version') != Q.VERSION or
            manifest.get('release_archive_sha256') != lock['release_archive_sha256'] or
            type(manifest.get('inspection_only')) is not bool or manifest.get('ready_for_boot') is not False or
            manifest.get('manifest_is_authenticated') is not False):
        raise Q.ReviewError('Assembly manifest provenance or preparation-only state is invalid.')
    files = manifest.get('files')
    if not isinstance(files, list) or not 0 < len(files) <= MAX_FILES:
        raise Q.ReviewError('Assembly manifest file count is invalid.')
    names, total, non_recovery = set(), 0, 0
    for item in files:
        if not isinstance(item, dict) or set(item) != {'path', 'bytes', 'sha256', 'role'}:
            raise Q.ReviewError('Assembly manifest file records are malformed.')
        name = portable_relative(item['path'])
        role = item['role']
        limit = MAX_RECOVERY if role == 'recovery_image' else 4 * 1024 * 1024 if role == 'recovery_chunklist' else Q.MAX_BINARY
        if (not isinstance(role, str) or role not in ROLES or type(item['bytes']) is not int or not 0 <= item['bytes'] <= limit or
                not isinstance(item['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', item['sha256']) or
                name.casefold() in names or not name.startswith(('EFI/', 'com.apple.recovery.boot/'))):
            raise Q.ReviewError('Assembly manifest contains an invalid file record.')
        valid_role = ('config' if name == 'EFI/OC/config.plist' else
                      'opencore' if name == 'EFI/OC/OpenCore.efi' else
                      'bootstrap' if name == 'EFI/BOOT/BOOTx64.efi' else
                      'efi_driver' if name.startswith('EFI/OC/Drivers/') and name.endswith('.efi') else
                      'acpi' if name.startswith('EFI/OC/ACPI/') else
                      'kext' if name.startswith('EFI/OC/Kexts/') else
                      'recovery_image' if name == 'com.apple.recovery.boot/BaseSystem.dmg' else
                      'recovery_chunklist' if name == 'com.apple.recovery.boot/BaseSystem.chunklist' else None)
        if role != valid_role:
            raise Q.ReviewError('Assembly manifest role does not match its payload namespace.')
        names.add(name.casefold())
        total += item['bytes']
        non_recovery += 0 if role.startswith('recovery_') else item['bytes']
    required = {'efi/oc/config.plist', 'efi/oc/opencore.efi', 'efi/boot/bootx64.efi'}
    if not required <= names or total > MAX_PAYLOAD + MAX_RECOVERY + 4 * 1024 * 1024 or non_recovery > MAX_PAYLOAD:
        raise Q.ReviewError('Assembly manifest omits core inputs or exceeds the byte bound.')
    return manifest


def current_inventory(stage: Path) -> dict[str, tuple[str, int]]:
    files, pending, total, directories = {}, [(stage, 0)], 0, 0
    while pending:
        folder, depth = pending.pop()
        directories += 1
        if depth > 20 or directories > 8192:
            raise Q.ReviewError('Assembly nesting exceeds the inventory bound.')
        for child in sorted(folder.iterdir()):
            if child.is_symlink() or child.is_junction():
                raise Q.ReviewError('Assembly contains an unexpected link or junction.')
            if child.is_dir():
                pending.append((child, depth + 1))
                continue
            name = portable_relative(child.relative_to(stage).as_posix())
            if name == MANIFEST:
                continue
            limit = MAX_RECOVERY if name == 'com.apple.recovery.boot/BaseSystem.dmg' else Q.MAX_BINARY
            digest, size = hash_stream(child, limit)
            total += size
            if total > MAX_PAYLOAD + MAX_RECOVERY + 4 * 1024 * 1024 or len(files) >= MAX_FILES or name.casefold() in {key.casefold() for key in files}:
                raise Q.ReviewError('Assembly inventory exceeds its bound or contains colliding paths.')
            files[name] = digest, size
    return files


def preflight(name: str, *, validator_path: Path | None = None, declaration_path: Path | None = None,
              profile: str = Q.DEFAULT_PROFILE) -> dict:
    policy = Q.profile_policy(profile)
    stage = stage_path(name, existing=True)
    manifest = load_manifest(stage)
    expected = {item['path']: (item['sha256'], item['bytes']) for item in manifest['files']}
    current = current_inventory(stage)
    changed = sorted(path for path in expected.keys() & current.keys() if expected[path] != current[path])
    missing, added = sorted(expected.keys() - current.keys()), sorted(current.keys() - expected.keys())
    roles = {item['path']: item['role'] for item in manifest['files']}
    touched = set(changed + missing + added)
    vault_stale = any(path.startswith('EFI/OC/') and path != 'EFI/OC/OpenCore.efi' for path in touched)
    drivers_stale = any(roles.get(path) == 'efi_driver' or path.startswith('EFI/OC/Drivers/') for path in touched)
    modules_stale = any(path.startswith('EFI/OC/Kexts/') for path in touched)
    recovery_stale = any(path.startswith('com.apple.recovery.boot/') for path in touched)
    report = {'schema_version': 1, 'snapshot_matches': not touched,
              'profile_policy': policy, 'snapshot_profile': manifest.get('profile', Q.DEFAULT_PROFILE),
              'profile_selection_matches_snapshot': profile == manifest.get('profile', Q.DEFAULT_PROFILE),
              'profile_selection_does_not_rewrite_snapshot': True,
              'manifest_is_authenticated': False, 'changed_paths': changed, 'missing_paths': missing, 'added_paths': added,
              'signing_dependencies_invalidated': {
                  'module_approval_and_signature': modules_stale,
                  'efi_driver_signatures': drivers_stale,
                  'vault_inventory_signature_and_embedded_key': vault_stale,
                  'final_opencore_authenticode': vault_stale or 'EFI/OC/OpenCore.efi' in touched,
                  'bootstrap_authenticode': 'EFI/BOOT/BOOTx64.efi' in touched,
                  'recovery_chunklist_and_image_pair': recovery_stale,
              }, 'ready_for_boot': False, 'device_boot_verified': False,
              'firmware_state_verified': False, 'keys_generated_or_enrolled': False,
              'real_efi_or_disk_modified': False,
              'trust_order': ['qualify_config_acpi_and_separate_modules', 'approve_and_sign_native_kexts',
                              'sign_final_efi_drivers', 'create_and_sign_final_vault',
                              'embed_vault_public_key_into_opencore', 'sign_final_opencore_and_bootstrap',
                              'verify_firmware_db_dbx_and_preserved_windows_trust', 'prove_both_native_boots_and_windows_fallback']
              if policy['firmware_secure_boot_required'] else [
                  'qualify_config_acpi_usb_and_separate_modules',
                  'verify_apple_boot_sip_and_native_kext_acceptance_separately',
                  'honour_the_explicit_vault_mode_and_pinned_efi_provenance',
                  'confirm_firmware_disabled_for_explicit_test_without_key_changes',
                  'prove_both_native_boots_and_windows_fallback']}
    if touched:
        report['qualification'] = None
        report['blocker'] = 'Snapshot changed; freeze a new reviewed version before repeating dependent signing steps.'
        return report
    report['qualification'] = Q.audit(stage / 'EFI' / 'OC' / 'config.plist', oc_root=stage / 'EFI' / 'OC',
                                       validator_path=validator_path, declaration_path=declaration_path,
                                       profile=profile)
    image = stage / 'com.apple.recovery.boot' / 'BaseSystem.dmg'
    report['recovery'] = verify_recovery(image, image.with_suffix('.chunklist')) if image.exists() else None
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    prepare = commands.add_parser('assemble', help='Create a new private unsigned snapshot; never write a target EFI.')
    prepare.add_argument('--archive', required=True, type=Path)
    prepare.add_argument('--config', required=True, type=Path)
    prepare.add_argument('--stage-name', required=True)
    prepare.add_argument('--source-oc', type=Path)
    prepare.add_argument('--recovery-dir', type=Path)
    prepare.add_argument('--inspection-only', action='store_true', help='Permit only the deliberately incomplete public schema template.')
    inspect = commands.add_parser('preflight', help='Detect changes and report every unresolved trust/device condition.')
    inspect.add_argument('--stage-name', required=True)
    inspect.add_argument('--ocvalidate', type=Path)
    inspect.add_argument('--declarations', type=Path)
    for command_parser in (prepare, inspect):
        command_parser.add_argument('--profile', choices=Q.PROFILES, default=Q.DEFAULT_PROFILE,
                                    help='Strict by default; explicitly select temporary-native-test for a firmware-disabled test.')
    arguments = parser.parse_args()
    if arguments.command == 'assemble':
        result = assemble(arguments.archive, arguments.config, arguments.stage_name,
                          source_oc=arguments.source_oc, recovery_dir=arguments.recovery_dir,
                          inspection_only=arguments.inspection_only, profile=arguments.profile)
        status = 0  # Preparation succeeded; ready_for_boot is still false.
    else:
        result = preflight(arguments.stage_name, validator_path=arguments.ocvalidate,
                           declaration_path=arguments.declarations, profile=arguments.profile)
        status = 2  # This offline module cannot verify a finished native boot chain.
    print(json.dumps(result, indent=2))
    return status


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (Q.ReviewError, OSError, ValueError, TypeError, KeyError, zipfile.BadZipFile):
        print(json.dumps({'error': 'Offline assembly/preflight failed safely.', 'ready_for_boot': False,
                          'keys_generated_or_enrolled': False, 'real_efi_or_disk_modified': False}), file=sys.stderr)
        raise SystemExit(3)
