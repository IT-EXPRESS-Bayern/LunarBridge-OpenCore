#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Offline OpenCore review. No EFI installation, signing or firmware mutation."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import plistlib
import re
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
VERSION = '1.0.8'
MAX_CONFIG = 2 * 1024 * 1024
MAX_BINARY = 64 * 1024 * 1024
APPLE_GUID = '7C436110-AB2A-4BBB-A880-FE41995C9F82'
# Known-filesystem/device locks + APFS/HFS/ESP + SATA/SCSI/NVMe/USB.
# USB-SATA enclosures can be classified as SATA/SCSI: verify on the device.
SCAN_POLICY = 0x002D0703
TAHOE_INTEL_MODELS = frozenset({
    'MacBookPro16,1', 'MacBookPro16,2', 'MacBookPro16,4',
    'iMac20,1', 'iMac20,2', 'MacPro7,1',
})
TAHOE_BOOT_MODEL = {
    'MacBookPro16,1': 'j152f', 'MacBookPro16,2': 'j214k', 'MacBookPro16,4': 'j215',
    'iMac20,1': 'j185', 'iMac20,2': 'j185f', 'MacPro7,1': 'j160',
}
APPLE_BOOT_MODELS = frozenset({
    'Default', 'j137', 'j680', 'j132', 'j174', 'j140k', 'j780',
    'j213', 'j140a', 'j152f', 'j160', 'j230k', 'j214k', 'j223',
    'j215', 'j185', 'j185f', 'x86legacy',
})
UNSAFE_ARGS = ('amfi_get_out_of_my_way', 'amfi_allow_any_signature',
               'amfi_unrestrict_task_for_pid', 'cs_enforcement_disable',
               'amfi=', '-amfipass', '-no_compat_check')
PRIVATE_KEYS = frozenset({'SystemSerialNumber', 'MLB', 'SystemUUID', 'ROM',
                          'BoardSerialNumber', 'ChassisSerialNumber', 'ApECID',
                          'PasswordHash', 'PasswordSalt'})
DECLARATIONS = (
    'backup_checked', 'bitlocker_recovery_available_or_not_used',
    'firmware_secure_boot_live', 'firmware_custom_trust_available',
    'windows_trust_preserved', 'efi_authenticode_verified',
    'vault_signature_verified', 'native_platform_qualified',
    'usb_storage_map_qualified', 'native_kext_acceptance_verified',
    'windows_boot_without_external_verified',
)


class ReviewError(ValueError):
    """Message must never contain input paths, values or private identifiers."""


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_bounded(path: Path, limit: int) -> bytes:
    if path.is_symlink() or path.is_junction():
        raise ReviewError('Symbolic links and junctions are not accepted.')
    if not path.is_file() or path.stat().st_size > limit:
        raise ReviewError('Input is missing, not a regular file, or too large.')
    with path.open('rb') as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ReviewError('Input exceeds its size limit.')
    return data


def load_xml_dictionary(raw: bytes) -> dict:
    if raw.startswith(b'bplist') or b'<!ENTITY' in raw.upper():
        raise ReviewError('Only XML plists without entity declarations are accepted.')
    try:
        tree = ET.fromstring(raw)
    except ET.ParseError:
        raise ReviewError('Configuration XML is malformed.') from None
    if tree.tag != 'plist' or len(tree) != 1 or tree[0].tag != 'dict':
        raise ReviewError('The plist must contain one root dictionary.')
    pending, nodes = [(tree, 0)], 0
    allowed = {'plist', 'dict', 'array', 'key', 'string', 'data', 'integer', 'true', 'false'}
    while pending:
        node, depth = pending.pop()
        nodes += 1
        if depth > 32 or nodes > 32768 or node.tag not in allowed:
            raise ReviewError('Configuration exceeds the supported XML limits or types.')
        if node.tag == 'dict':
            children = list(node)
            if len(children) % 2 or any(child.tag != 'key' for child in children[::2]):
                raise ReviewError('Dictionary entries are malformed.')
            keys = [(child.text or '') for child in children[::2]]
            if len(set(keys)) != len(keys):
                raise ReviewError('Duplicate dictionary keys are not accepted.')
        if node.tag in {'string', 'key'}:
            value = node.text or ''
            if any(ord(character) < 32 or ord(character) > 126 for character in value):
                raise ReviewError('OpenCore strings and keys must be printable ASCII.')
        pending.extend((child, depth + 1) for child in node)
    try:
        config = plistlib.loads(raw)
    except (ValueError, TypeError, OverflowError):
        raise ReviewError('Configuration plist values are malformed.') from None
    return config


def load_config(path: Path) -> tuple[dict, bytes]:
    raw = read_bounded(path, MAX_CONFIG)
    config = load_xml_dictionary(raw)
    required = {'ACPI', 'Booter', 'DeviceProperties', 'Kernel', 'Misc', 'NVRAM', 'PlatformInfo', 'UEFI'}
    if not isinstance(config, dict) or not required <= config.keys():
        raise ReviewError('The complete OpenCore root sections are required.')
    if any(not isinstance(config[key], dict) for key in required):
        raise ReviewError('OpenCore root sections must be dictionaries.')
    return config, raw


def value_at(config: dict, path: str):
    node = config
    for key in path.split('/'):
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    return node


def set_at(config: dict, path: str, value) -> None:
    node = config
    parts = path.split('/')
    for key in parts[:-1]:
        if not isinstance(node.get(key), dict):
            raise ReviewError('A required configuration subsection is missing.')
        node = node[key]
    if parts[-1] not in node:
        raise ReviewError('A required configuration property is missing.')
    node[parts[-1]] = value


def relative_path(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or '\\' in value or ':' in value:
        raise ReviewError('A relative OpenCore path is invalid.')
    if any(ord(character) < 32 or ord(character) > 126 for character in value):
        raise ReviewError('A relative OpenCore path is invalid.')
    parts = value.split('/')
    if value.startswith('/') or any(part in {'', '.', '..'} for part in parts):
        raise ReviewError('Absolute paths and path traversal are not accepted.')
    return PurePosixPath(value)


def bounded_file(root: Path, name: str, limit: int = MAX_BINARY) -> tuple[Path, bytes]:
    relative = relative_path(name)
    if root.is_symlink() or root.is_junction():
        raise ReviewError('An OpenCore root must not be a symbolic link or junction.')
    base = root.resolve(strict=True)
    candidate = base.joinpath(*relative.parts)
    for parent in (candidate, *candidate.parents):
        if parent == base:
            break
        if parent.is_symlink() or parent.is_junction():
            raise ReviewError('OpenCore path contains a symbolic link or junction.')
    if not candidate.resolve(strict=True).is_relative_to(base):
        raise ReviewError('OpenCore path escapes its selected root.')
    return candidate, read_bounded(candidate, limit)


def inspect_pe(raw: bytes) -> dict:
    if len(raw) < 256 or raw[:2] != b'MZ':
        raise ReviewError('EFI file has no valid PE image header.')
    pe = struct.unpack_from('<I', raw, 60)[0]
    if pe < 64 or pe + 24 > len(raw) or raw[pe:pe + 4] != b'PE\0\0':
        raise ReviewError('EFI PE header is out of bounds or malformed.')
    machine, optional_size = struct.unpack_from('<H', raw, pe + 4)[0], struct.unpack_from('<H', raw, pe + 20)[0]
    optional = pe + 24
    if machine != 0x8664 or optional_size < 152 or optional + optional_size > len(raw):
        raise ReviewError('EFI image must have a complete x64 PE32+ header.')
    if struct.unpack_from('<H', raw, optional)[0] != 0x20B:
        raise ReviewError('EFI image must use PE32+.')
    subsystem = struct.unpack_from('<H', raw, optional + 68)[0]
    if subsystem not in {10, 11, 12}:
        raise ReviewError('PE image is not an EFI application or driver.')
    count = struct.unpack_from('<I', raw, optional + 108)[0]
    certificate = False
    if count >= 5:
        offset, size = struct.unpack_from('<II', raw, optional + 144)
        if offset or size:
            if offset % 8 or size < 8 or offset + size > len(raw):
                raise ReviewError('EFI certificate table is out of bounds.')
            length, revision, kind = struct.unpack_from('<IHH', raw, offset)
            if length < 8 or length > size or revision != 0x200 or kind != 2:
                raise ReviewError('EFI certificate table has an unsupported structure.')
            certificate = True
    return {'x64': True, 'subsystem': subsystem, 'certificate_table_present': certificate,
            'authenticode_trust_verified': False, 'sha256': sha256(raw)}


def inspect_kext(raw: bytes) -> dict:
    if len(raw) < 32 or struct.unpack_from('<I', raw)[0] != 0xFEEDFACF:
        raise ReviewError('Kext executable is not a thin Mach-O64 image.')
    cpu, filetype, commands, command_bytes = struct.unpack_from('<I4xIII', raw, 4)
    if cpu != 0x01000007 or filetype != 11 or commands > 4096 or 32 + command_bytes > len(raw):
        raise ReviewError('Kext executable is not a bounded x64 MH_KEXT_BUNDLE.')
    position, signature = 32, False
    for _ in range(commands):
        if position + 8 > 32 + command_bytes:
            raise ReviewError('Mach-O load command is truncated.')
        command, size = struct.unpack_from('<II', raw, position)
        if size < 8 or size % 8 or position + size > 32 + command_bytes:
            raise ReviewError('Mach-O load command is out of bounds.')
        if command == 0x1D:
            if size != 16:
                raise ReviewError('Mach-O code signature command is malformed.')
            offset, length = struct.unpack_from('<II', raw, position + 8)
            if length < 8 or offset + length > len(raw):
                raise ReviewError('Mach-O code signature is out of bounds.')
            signature = True
        position += size
    if position != 32 + command_bytes:
        raise ReviewError('Mach-O command size does not match its header.')
    return {'x64': True, 'filetype': 11, 'code_signature_present': signature,
            'signature_trust_verified': False, 'sha256': sha256(raw)}


def policy_findings(config: dict) -> list[dict]:
    findings = []
    def require(path, expected, message):
        actual = value_at(config, path)
        if type(actual) is not type(expected) or actual != expected:
            findings.append({'id': path, 'severity': 'error', 'message': message})
    require('UEFI/Quirks/DisableSecurityPolicy', False, 'Firmware security policy must remain enabled.')
    require('Booter/Quirks/ProtectSecureBoot', True, 'Protect firmware Secure Boot variables during the boot chain.')
    require('Misc/Security/Vault', 'Secure', 'The finished trusted chain requires a signed OpenCore vault.')
    require('Misc/Security/DmgLoading', 'Signed', 'The recovery profile must load only Apple-signed disk images.')
    require('Misc/Security/ExposeSensitiveData', 0, 'Public preparation must not expose sensitive boot information.')
    require('Misc/Security/AllowSetDefault', False, 'The review profile must not offer firmware default changes.')
    require('Misc/Boot/ShowPicker', True, 'The Windows/macOS choice needs a visible picker.')
    require('Misc/Boot/HideAuxiliary', False, 'The installation profile must display recovery entries.')
    require('Misc/Boot/PickerMode', 'Builtin', 'The review profile uses the built-in picker without extra graphics drivers.')
    require('Misc/Boot/LauncherOption', 'Disabled', 'The review profile must not create or reprioritise firmware boot entries.')
    require('UEFI/Quirks/RequestBootVarRouting', True, 'OpenCore boot variable routing needs OpenRuntime and a device test.')
    require('UEFI/AppleInput/AppleEvent', 'Builtin', 'Use the upstream input implementation on non-Apple hardware.')
    require('UEFI/AppleInput/GraphicsInputMirroring', True, 'Preserve keyboard input for the Windows BitLocker graphics interface.')
    require('UEFI/APFS/MinDate', 0, 'Keep the upstream minimum APFS driver date instead of allowing all old drivers.')
    require('UEFI/APFS/MinVersion', 0, 'Keep the upstream minimum APFS driver version instead of allowing all old drivers.')
    require('UEFI/APFS/EnableJumpstart', True, 'An installed APFS system requires the qualified APFS loader.')
    require('UEFI/APFS/JumpstartHotPlug', True, 'Allow APFS probing on the intended external USB system device.')
    require('Kernel/Quirks/XhciPortLimit', False, 'Do not use the broken recent-macOS XHCI port-limit workaround.')
    require('Kernel/Quirks/CustomSMBIOSGuid', True, 'Pair custom SMBIOS mode with the macOS GUID patch.')
    require('PlatformInfo/UpdateSMBIOSMode', 'Custom', 'Keep macOS SMBIOS updates separate from the Windows OEM tables.')
    model = value_at(config, 'Misc/Security/SecureBootModel')
    if not isinstance(model, str) or model not in APPLE_BOOT_MODELS:
        findings.append({'id': 'AppleSecureBoot', 'severity': 'error',
                         'message': 'A documented enabled Apple Secure Boot model is required; Disabled is not accepted.'})
    scan = value_at(config, 'Misc/Security/ScanPolicy')
    if type(scan) is not int or scan != SCAN_POLICY:
        findings.append({'id': 'ScanPolicy', 'severity': 'error',
                         'message': 'Use the restricted APFS/HFS/ESP and SATA/SCSI/NVMe/USB review mask 0x002D0703.'})
    product = value_at(config, 'PlatformInfo/Generic/SystemProductName')
    if not isinstance(product, str) or product not in TAHOE_INTEL_MODELS:
        findings.append({'id': 'TahoeSMBIOS', 'severity': 'blocker',
                         'message': 'A Tahoe-supported Intel Mac identity must be selected and qualified; no default identity is invented.'})
    elif isinstance(model, str) and model != 'Default' and model != TAHOE_BOOT_MODEL[product]:
        findings.append({'id': 'AppleModelMatch', 'severity': 'error',
                         'message': 'On current macOS, the fixed Apple Secure Boot model must match the selected SMBIOS.'})
    if value_at(config, 'Misc/Security/ApECID') != 0 and model == 'Default':
        findings.append({'id': 'ApECID', 'severity': 'error',
                         'message': 'A personalised Apple boot policy needs a fixed, matching model and OS personalisation.'})
    timeout = value_at(config, 'Misc/Boot/Timeout')
    if type(timeout) is not int or timeout < 5:
        findings.append({'id': 'PickerTimeout', 'severity': 'error', 'message': 'Allow at least five seconds to select a system.'})
    nvram = value_at(config, 'NVRAM/Add')
    csr = nvram.get(APPLE_GUID, {}).get('csr-active-config') if isinstance(nvram, dict) and isinstance(nvram.get(APPLE_GUID, {}), dict) else None
    if not isinstance(csr, bytes) or csr != b'\0' * 4:
        findings.append({'id': 'ExplicitSIP', 'severity': 'error',
                         'message': 'The Apple NVRAM namespace must explicitly request the unchanged full SIP policy.'})
    if isinstance(nvram, dict):
        for namespace in nvram.values():
            if not isinstance(namespace, dict):
                continue
            csr = namespace.get('csr-active-config')
            if csr is not None and (not isinstance(csr, bytes) or len(csr) != 4 or any(csr)):
                findings.append({'id': 'SIP', 'severity': 'error', 'message': 'SIP must not be weakened in this profile.'})
            arguments = namespace.get('boot-args', '')
            if not isinstance(arguments, str) or any(flag in arguments.lower() for flag in UNSAFE_ARGS):
                findings.append({'id': 'BootArguments', 'severity': 'error', 'message': 'Security or platform-check bypass arguments need removal and review.'})
    for section in ('ACPI/Add', 'ACPI/Patch', 'Kernel/Add', 'Kernel/Force', 'Kernel/Patch', 'Misc/Tools', 'UEFI/Drivers'):
        entries = value_at(config, section)
        if not isinstance(entries, list):
            findings.append({'id': section, 'severity': 'error', 'message': 'A complete typed entry array is required.'})
            continue
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict) or type(entry.get('Enabled')) is not bool:
                findings.append({'id': f'{section}/{index}', 'severity': 'error', 'message': 'Entry must contain a Boolean Enabled property.'})
                continue
            if not entry['Enabled']:
                continue
            field = 'BundlePath' if section.startswith('Kernel/') and section.endswith(('Add', 'Force')) else 'Path'
            if field in entry:
                try:
                    relative_path(entry[field])
                except ReviewError:
                    findings.append({'id': f'{section}/{index}', 'severity': 'error', 'message': 'Enabled entry has an unsafe relative path.'})
            if section in {'ACPI/Add', 'ACPI/Patch'}:
                findings.append({'id': f'{section}/{index}/Windows', 'severity': 'blocker',
                                 'message': 'ACPI changes can affect Windows too; a Darwin guard and native device review are required.'})
            if section == 'Kernel/Force':
                findings.append({'id': f'{section}/{index}/Force', 'severity': 'error',
                                 'message': 'Forced system kernel extensions are outside this trusted review profile.'})
            if section == 'Misc/Tools' or section == 'UEFI/Drivers' and any(
                token in str(entry.get('Path', '')).lower() for token in ('openshell', 'resetnvram', 'togglesip', 'opencontrol')
            ):
                findings.append({'id': f'{section}/{index}/AdministrativeTool', 'severity': 'error',
                                 'message': 'Administrative UEFI tools are excluded from the signed boot menu.'})
    drivers = value_at(config, 'UEFI/Drivers')
    if not isinstance(drivers, list) or not any(isinstance(entry, dict) and entry.get('Enabled') is True
                                               and entry.get('Path') == 'OpenRuntime.efi' for entry in drivers):
        findings.append({'id': 'OpenRuntime', 'severity': 'error', 'message': 'Boot variable routing requires an enabled OpenRuntime.efi entry.'})
    return findings


def validate_upstream(config_path: Path, validator_path: Path, reference: dict) -> dict:
    raw = read_bounded(validator_path, MAX_BINARY)
    digest = sha256(raw)
    hashes = reference['ocvalidate_sha256']
    if digest not in hashes.values():
        raise ReviewError('ocvalidate does not match an original pinned OpenCore 1.0.8 executable.')
    try:
        process = subprocess.run([str(validator_path.resolve()), str(config_path.resolve())],
                                 capture_output=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ReviewError('The selected original ocvalidate executable could not complete.') from None
    output = (process.stdout + process.stderr).decode('utf-8', errors='replace')
    banner = re.search(r'OpenCore\s+version\s+(\d+\.\d+\.\d+)', output)
    if not banner or banner.group(1) != VERSION:
        raise ReviewError('ocvalidate did not confirm the pinned OpenCore version.')
    return {'version': VERSION, 'executable_sha256': digest, 'exit_code': process.returncode,
            'schema_passed': process.returncode == 0, 'raw_output_retained': False}


def inspect_vault(oc_root: Path, required: set[str]) -> dict:
    _, raw = bounded_file(oc_root, 'vault.plist', MAX_CONFIG)
    _, signature = bounded_file(oc_root, 'vault.sig', 256)
    if len(signature) != 256:
        raise ReviewError('The vault signature must have the documented RSA-2048 size.')
    vault = load_xml_dictionary(raw)
    if type(vault.get('Version')) is not int or vault['Version'] != 1 or not isinstance(vault.get('Files'), dict):
        raise ReviewError('The vault schema must contain Version 1 and a Files dictionary.')
    files = vault['Files']
    if not files or len(files) > 4096:
        raise ReviewError('The vault file table is empty or exceeds the local bound.')
    total, listed, insensitive = 0, set(), set()
    for name, digest in files.items():
        if not isinstance(name, str) or '/' in name or not isinstance(digest, bytes) or len(digest) != 32:
            raise ReviewError('The vault file table contains an invalid path or hash.')
        normal = str(relative_path(name.replace('\\', '/')))
        if normal.casefold() in insensitive:
            raise ReviewError('The vault contains duplicate case-insensitive file paths.')
        insensitive.add(normal.casefold())
        listed.add(normal)
        _, data = bounded_file(oc_root, normal)
        total += len(data)
        if total > 256 * 1024 * 1024 or hashlib.sha256(data).digest() != digest:
            raise ReviewError('A vault file hash differs or the vault exceeds the local byte bound.')
    if not required <= listed:
        raise ReviewError('The vault does not cover every enabled OpenCore input file.')
    return {'version': 1, 'listed_files': len(files), 'hashed_bytes': total,
            'listed_hashes_match': True, 'required_inputs_covered': True,
            'rsa_signature_bytes': len(signature), 'rsa_signature_verified': False,
            'embedded_key_verified': False, 'sha256': sha256(raw)}


def file_findings(config: dict, oc_root: Path | None, config_raw: bytes) -> tuple[list[dict], list[dict]]:
    findings, images = [], []
    if oc_root is None:
        return [{'id': 'SelectedEFI', 'severity': 'blocker', 'message': 'No explicit offline OC directory was selected for file inspection.'}], []
    if oc_root.name.lower() != 'oc' or oc_root.is_symlink() or oc_root.is_junction():
        return [{'id': 'SelectedEFI', 'severity': 'error', 'message': 'Select an ordinary offline directory named OC.'}], []
    reference = json.loads((ROOT / 'reference-lock.json').read_text(encoding='utf-8'))
    candidates = [(oc_root, 'OpenCore.efi', 'OpenCore', 'pe'),
                  (oc_root.parent, 'BOOT/BOOTx64.efi', 'Bootstrap', 'pe')]
    try:
        _, selected_config = bounded_file(oc_root, 'config.plist', MAX_CONFIG)
        if sha256(selected_config) != sha256(config_raw):
            raise ReviewError('Selected source differs from the configuration stored in the offline OC directory.')
    except (OSError, ReviewError):
        findings.append({'id': 'SelectedConfigBinding', 'severity': 'error',
                         'message': 'The explicitly selected configuration must match the offline OC/config.plist bytes.'})
    required_vault = {'config.plist'}
    for section, folder in (('UEFI/Drivers', 'Drivers'), ('ACPI/Add', 'ACPI'), ('Kernel/Add', 'Kexts')):
        entries = value_at(config, section)
        if not isinstance(entries, list):
            continue
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict) or entry.get('Enabled') is not True:
                continue
            label = f'{section}/{index}'
            if section == 'Kernel/Add':
                bundle, executable, plist = entry.get('BundlePath'), entry.get('ExecutablePath'), entry.get('PlistPath')
                try:
                    for part in (bundle, plist):
                        relative_path(part)
                    if len(relative_path(bundle).parts) != 1 or not bundle.lower().endswith('.kext'):
                        raise ReviewError('Hardware module bundles must remain separate top-level kexts.')
                    if executable:
                        relative_path(executable)
                except ReviewError:
                    findings.append({'id': label, 'severity': 'error', 'message': 'Kext bundle has an unsafe relative path.'})
                    continue
                candidates.append((oc_root, f'{folder}/{bundle}/{plist}', label + '/Metadata', 'plist'))
                required_vault.add(f'{folder}/{bundle}/{plist}')
                if executable:
                    candidates.append((oc_root, f'{folder}/{bundle}/{executable}', label + '/Executable', 'kext'))
                    required_vault.add(f'{folder}/{bundle}/{executable}')
                findings.append({'id': label + '/Acceptance', 'severity': 'blocker',
                                 'message': 'Native kext approval under the selected Apple boot, SIP and signing policy is unverified.'})
            else:
                path = entry.get('Path')
                if not isinstance(path, str):
                    continue
                candidates.append((oc_root, f'{folder}/{path}', label, 'pe' if section == 'UEFI/Drivers' else 'acpi'))
                required_vault.add(f'{folder}/{path}')
    for root, path, label, kind in candidates:
        try:
            _, raw = bounded_file(root, path)
            if kind == 'pe':
                result = inspect_pe(raw)
                upstream_label = label
                if label.startswith('UEFI/Drivers/'):
                    upstream_label = {'OpenRuntime.efi': 'OpenRuntime', 'OpenHfsPlus.efi': 'OpenHfsPlus'}.get(Path(path).name)
                expected = reference['original_efi_sha256'].get(upstream_label)
                result['matches_original_release'] = expected == result['sha256'] if expected else False
                if expected and not result['matches_original_release']:
                    findings.append({'id': label + '/Provenance', 'severity': 'blocker',
                                     'message': 'Binary differs from the pinned original release; signing or mixed-version provenance requires review.'})
                if not result['certificate_table_present']:
                    findings.append({'id': label + '/Signature', 'severity': 'error',
                                     'message': 'EFI binary has no Authenticode certificate table; the project signed-loader profile is incomplete.'})
                else:
                    findings.append({'id': label + '/Trust', 'severity': 'blocker',
                                     'message': 'Certificate presence does not prove signature validity, firmware trust or revocation status.'})
            elif kind == 'kext':
                result = inspect_kext(raw)
                if not result['code_signature_present']:
                    findings.append({'id': label + '/Signing', 'severity': 'blocker',
                                     'message': 'The kext has no embedded code signature; OpenCore injection alone does not prove policy acceptance.'})
            elif kind == 'plist':
                metadata = plistlib.loads(raw)
                if not isinstance(metadata, dict) or not isinstance(metadata.get('CFBundleIdentifier'), str):
                    raise ReviewError('Kext metadata has no bundle identifier.')
                result = {'sha256': sha256(raw), 'metadata_present': True}
            else:
                result = {'sha256': sha256(raw), 'device_qualified': False}
            images.append({'entry': label, 'kind': kind, **result})
        except (ReviewError, OSError, ValueError, struct.error):
            findings.append({'id': label + '/File', 'severity': 'error', 'message': 'Selected file is missing, unsafe or malformed.'})
    try:
        vault = inspect_vault(oc_root, required_vault)
        images.append({'entry': 'Vault', 'kind': 'vault', **vault})
        findings.append({'id': 'VaultTrust', 'severity': 'blocker',
                         'message': 'Matching vault hashes and signature size do not prove the RSA signature or embedded OpenCore key.'})
    except (OSError, ReviewError, ValueError):
        findings.append({'id': 'VaultFiles', 'severity': 'error',
                         'message': 'The signed vault is missing, malformed, incomplete or has changed input hashes.'})
    return findings, images


def audit(config_path: Path, *, oc_root: Path | None = None,
          validator_path: Path | None = None, declaration_path: Path | None = None) -> dict:
    config, raw = load_config(config_path)
    findings = policy_findings(config)
    reference = json.loads((ROOT / 'reference-lock.json').read_text(encoding='utf-8'))
    upstream = {'schema_passed': False, 'version': None, 'executed': False}
    if validator_path is None:
        findings.append({'id': 'UpstreamSchema', 'severity': 'blocker', 'message': 'Matching original ocvalidate has not been run for this explicit configuration.'})
    else:
        upstream = {'executed': True, **validate_upstream(config_path, validator_path, reference)}
        if not upstream['schema_passed']:
            findings.append({'id': 'UpstreamSchema', 'severity': 'error', 'message': 'Original ocvalidate rejected the configuration.'})
    file_issues, images = file_findings(config, oc_root, raw)
    findings.extend(file_issues)
    declarations = {}
    if declaration_path is not None:
        try:
            declarations = json.loads(read_bounded(declaration_path, 64 * 1024))
        except (ValueError, TypeError):
            raise ReviewError('Prerequisite declarations are malformed.') from None
        if not isinstance(declarations, dict) or declarations.get('schema_version') != 1:
            raise ReviewError('Prerequisite declarations need schema_version 1.')
        if any(key not in {'schema_version', *DECLARATIONS} for key in declarations):
            raise ReviewError('Unknown declaration fields are not accepted; keep private identifiers out of this file.')
        if any(key in declarations and type(declarations[key]) is not bool for key in DECLARATIONS):
            raise ReviewError('Prerequisite declarations must use Boolean values.')
    declared = {key: declarations.get(key) is True for key in DECLARATIONS}
    for key, complete in declared.items():
        if not complete:
            findings.append({'id': 'Prerequisite/' + key, 'severity': 'blocker',
                             'message': 'The corresponding device prerequisite is not declared complete.'})
    # Declarations are input, not evidence verified by this offline program.
    findings.append({'id': 'DeviceQualification', 'severity': 'blocker',
                     'message': 'Actual firmware trust, vault signature, native CPU/USB/driver acceptance and both boots require device evidence.'})
    return {'schema_version': 1, 'target': 'Samsung Galaxy Book5 Pro16 NP960XHA-KG3DE',
            'opencore_version': VERSION, 'configuration_sha256': sha256(raw),
            'offline_policy_passed': not any(issue['severity'] == 'error' for issue in findings),
            'ready_for_boot': False, 'device_boot_verified': False, 'firmware_state_verified': False,
            'declarations_are_verified_evidence': False, 'declared_prerequisites': declared,
            'upstream_validator': upstream, 'images': images, 'findings': findings,
            'writes_to_efi_firmware_or_disks': False, 'private_identifiers_in_report': False}


POLICY_CHANGES = {
    'UEFI/Quirks/DisableSecurityPolicy': False,
    'Booter/Quirks/ProtectSecureBoot': True,
    'Misc/Security/SecureBootModel': 'Default',
    'Misc/Security/ApECID': 0,
    'Misc/Security/Vault': 'Secure',
    'Misc/Security/DmgLoading': 'Signed',
    'Misc/Security/ScanPolicy': SCAN_POLICY,
    'Misc/Security/ExposeSensitiveData': 0,
    'Misc/Security/AllowSetDefault': False,
    'Misc/Boot/ShowPicker': True,
    'Misc/Boot/HideAuxiliary': False,
    'Misc/Boot/PickerMode': 'Builtin',
    'Misc/Boot/LauncherOption': 'Disabled',
    'Misc/Boot/Timeout': 10,
    'UEFI/Quirks/RequestBootVarRouting': True,
    'UEFI/AppleInput/AppleEvent': 'Builtin',
    'UEFI/AppleInput/GraphicsInputMirroring': True,
    'UEFI/APFS/MinDate': 0,
    'UEFI/APFS/MinVersion': 0,
    'UEFI/APFS/EnableJumpstart': True,
    'UEFI/APFS/JumpstartHotPlug': True,
    'Kernel/Quirks/XhciPortLimit': False,
    'Kernel/Quirks/CustomSMBIOSGuid': True,
    'PlatformInfo/UpdateSMBIOSMode': 'Custom',
}


def proposal(config: dict) -> tuple[dict, list[dict]]:
    proposed, changes = copy.deepcopy(config), []
    if value_at(config, 'Misc/Security/ApECID') != 0:
        raise ReviewError('A personalised Apple boot configuration requires a separate explicit review; no reset is proposed.')
    for path, replacement in POLICY_CHANGES.items():
        current = value_at(proposed, path)
        if type(current) is not type(replacement) or current != replacement:
            set_at(proposed, path, replacement)
            # Never copy an untrusted old value into a public change report.
            changes.append({'property': path, 'old_value_retained': False, 'proposed_value': replacement})
    nvram = value_at(proposed, 'NVRAM/Add')
    if not isinstance(nvram, dict):
        raise ReviewError('The original NVRAM Add dictionary is required.')
    for namespace in nvram.values():
        if not isinstance(namespace, dict):
            raise ReviewError('NVRAM namespaces must be dictionaries.')
        arguments = namespace.get('boot-args', '')
        if not isinstance(arguments, str) or any(flag in arguments.lower() for flag in UNSAFE_ARGS):
            raise ReviewError('Security bypass arguments require a separate explicit review; no blind argument rewrite is proposed.')
        if 'csr-active-config' in namespace and namespace['csr-active-config'] != b'\0' * 4:
            namespace['csr-active-config'] = b'\0' * 4
            changes.append({'property': 'NVRAM/Add/csr-active-config', 'old_value_retained': False,
                            'proposed_value': '00000000'})
    apple_nvram = nvram.setdefault(APPLE_GUID, {})
    if not isinstance(apple_nvram, dict):
        raise ReviewError('The Apple NVRAM namespace must be a dictionary.')
    if apple_nvram.get('csr-active-config') != b'\0' * 4:
        apple_nvram['csr-active-config'] = b'\0' * 4
        changes.append({'property': 'NVRAM/Add/csr-active-config', 'old_value_retained': False,
                        'proposed_value': '00000000'})
    return proposed, changes


def write_proposal(config_path: Path, destination: Path, allowed_root: Path) -> dict:
    config, original = load_config(config_path)
    proposed, changes = proposal(config)
    root, selected = allowed_root.resolve(), destination.resolve()
    if not selected.is_relative_to(root) or selected == root or selected.exists():
        raise ReviewError('A new, unused directory inside the private staging root is required.')
    if any(part.lower() in {'efi', 'boot', 'com.apple.recovery.boot'} for part in selected.parts):
        raise ReviewError('Configuration proposals cannot be written to EFI or boot directories.')
    for parent in (destination, *destination.parents):
        if parent.is_symlink() or parent.is_junction():
            raise ReviewError('Staging paths must not contain symbolic links or junctions.')
    output = plistlib.dumps(proposed, sort_keys=False)
    report = {'schema_version': 1, 'source_sha256': sha256(original), 'proposed_sha256': sha256(output),
              'changes': changes, 'source_overwritten': False, 'deployed': False,
              'contains_private_original_copy': True,
              'rollback': 'Discard this private stage; the selected source is unchanged.',
              'remaining_policy_findings': policy_findings(proposed)}
    selected.mkdir(parents=True, exist_ok=False)
    # Exclusive writes prevent replacing an existing configuration or report.
    for name, raw in [('source.plist', original), ('proposed.plist', output),
                      ('changes.json', (json.dumps(report, indent=2) + '\n').encode('utf-8'))]:
        with (selected / name).open('xb') as handle:
            handle.write(raw)
    return report


def public_template(sample_path: Path) -> dict:
    config, raw = load_config(sample_path)
    reference = json.loads((ROOT / 'reference-lock.json').read_text(encoding='utf-8'))
    if sha256(raw) != reference['sample_sha256']:
        raise ReviewError('Public templates must derive from the exact pinned upstream Sample.plist.')
    for section, fields in [('ACPI', ('Add', 'Delete', 'Patch')), ('Kernel', ('Add', 'Block', 'Force', 'Patch')),
                            ('Misc', ('Entries', 'Tools'))]:
        for field in fields:
            config[section][field] = []
    config['DeviceProperties'] = {'Add': {}, 'Delete': {}}
    config['Booter']['Patch'] = []
    config['NVRAM']['Add'] = {APPLE_GUID: {'boot-args': '', 'csr-active-config': b'\0' * 4}}
    config['NVRAM']['Delete'] = {}
    config['PlatformInfo']['Generic']['SystemProductName'] = ''
    def clear_identifiers(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key in PRIVATE_KEYS:
                    node[key] = bytes(len(value)) if isinstance(value, bytes) else 0 if type(value) is int else ''
                else:
                    clear_identifiers(value)
        elif isinstance(node, list):
            for value in node:
                clear_identifiers(value)
    clear_identifiers(config)
    config['Kernel']['Emulate']['Cpuid1Data'] = bytes(16)
    config['Kernel']['Emulate']['Cpuid1Mask'] = bytes(16)
    config['UEFI']['Drivers'] = [
        {'Arguments': '', 'Comment': '', 'Enabled': True, 'HideVerbose': False, 'LoadEarly': False, 'Path': driver}
        for driver in ('OpenRuntime.efi', 'OpenHfsPlus.efi')
    ]
    config, _ = proposal(config)
    config['#LunarBridgeReview'] = 'Incomplete offline template. No SMBIOS identity, hardware kexts, ACPI, signatures or vault. Do not boot.'
    return config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    audit_parser = sub.add_parser('audit', help='Read an explicitly selected configuration and return a sanitised JSON report.')
    audit_parser.add_argument('--config', required=True, type=Path)
    audit_parser.add_argument('--oc-root', type=Path)
    audit_parser.add_argument('--ocvalidate', type=Path)
    audit_parser.add_argument('--declarations', type=Path)
    propose_parser = sub.add_parser('propose', help='Write one unchanged source and proposed copy inside private/staging only.')
    propose_parser.add_argument('--config', required=True, type=Path)
    propose_parser.add_argument('--stage-name', required=True)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == 'audit':
            report = audit(arguments.config, oc_root=arguments.oc_root, validator_path=arguments.ocvalidate,
                           declaration_path=arguments.declarations)
            print(json.dumps(report, indent=2))
            return 2 if any(issue['severity'] in {'error', 'blocker'} for issue in report['findings']) else 0
        if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', arguments.stage_name):
            raise ReviewError('Stage name must contain only lowercase letters, numbers and hyphens.')
        allowed_root = ROOT / 'private' / 'staging'
        report = write_proposal(arguments.config, allowed_root / arguments.stage_name, allowed_root)
        print(json.dumps(report, indent=2))
        return 0
    except (ReviewError, OSError, ValueError, TypeError, KeyError, struct.error):
        # Exception text, tool output and input values may contain private paths.
        print(json.dumps({'error': 'OpenCore review failed: invalid, incomplete or unsafe input.',
                          'source_overwritten': False, 'deployed': False}), file=sys.stderr)
        return 3


if __name__ == '__main__':
    raise SystemExit(main())
