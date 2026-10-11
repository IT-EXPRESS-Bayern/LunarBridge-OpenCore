# SPDX-License-Identifier: GPL-3.0-only
"""Offline snapshot/security tests; synthetic fixtures are not device evidence."""

import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import plistlib
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('offline_assembly_tests', ROOT / 'tools' / 'prepare_offline.py')
A = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(A)


def pe_fixture():
    raw = bytearray(512)
    raw[:2] = b'MZ'
    struct.pack_into('<I', raw, 60, 64)
    raw[64:68] = b'PE\0\0'
    struct.pack_into('<H', raw, 68, 0x8664)
    struct.pack_into('<H', raw, 84, 240)
    struct.pack_into('<H', raw, 88, 0x20B)
    struct.pack_into('<H', raw, 88 + 68, 10)
    struct.pack_into('<I', raw, 88 + 108, 16)
    return bytes(raw)


def kext_fixture(filetype=11):
    return struct.pack('<IIIIIIII', 0xFEEDFACF, 0x01000007, 3, filetype, 0, 0, 0, 0)


def chunk_fixture(image=b'recovery fixture', *, method=1, size=None):
    size = len(image) if size is None else size
    body = A.CHUNK_HEADER.pack(b'CNKL', 36, 1, 1, method, 1, 36, 72)
    body += A.CHUNK.pack(size, hashlib.sha256(image).digest())
    return body + (b'\x01' + bytes(255) if method == 1 else hashlib.sha256(body).digest())


def expected_rsa(raw):
    encoded = b'\0\x01' + b'\xff' * 202 + b'\0' + A.SHA256_DIGEST_INFO + hashlib.sha256(raw[:-256]).digest()
    return int.from_bytes(encoded, 'big')


class OfflineAssemblyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='lunarbridge-assembly-test-')
        self.root = Path(self.temporary.name)
        self.original_blank = (ROOT / 'examples' / 'inspection-template.plist').read_bytes()
        (self.root / 'examples').mkdir()
        (self.root / 'examples' / 'inspection-template.plist').write_bytes(self.original_blank)
        self.config = plistlib.loads(self.original_blank)
        self.config['PlatformInfo']['Generic']['SystemProductName'] = 'MacBookPro16,1'
        self.config_path = self.root / 'selected.plist'
        self.write_config()
        self.validator_name = 'ocvalidate.exe' if sys.platform == 'win32' else 'ocvalidate' if sys.platform == 'darwin' else 'ocvalidate.linux'
        self.members = {'X64/EFI/BOOT/BOOTx64.efi': pe_fixture(),
                        'X64/EFI/OC/OpenCore.efi': pe_fixture(),
                        'X64/EFI/OC/Drivers/OpenRuntime.efi': pe_fixture(),
                        'X64/EFI/OC/Drivers/OpenHfsPlus.efi': pe_fixture(),
                        'Utilities/ocvalidate/' + self.validator_name: b'synthetic-validator'}
        self.archive = self.root / 'source.zip'
        self.make_archive()
        self.lock = {'release_archive_bytes': self.archive.stat().st_size,
                     'release_archive_sha256': A.Q.sha256(self.archive.read_bytes()),
                     'ocvalidate_sha256': {self.validator_name: A.Q.sha256(b'synthetic-validator')}}
        self.patches = [patch.object(A, 'ROOT', self.root), patch.object(A, 'load_lock', return_value=self.lock),
                        patch.object(A.Q, 'validate_upstream', return_value={
                            'version': '1.0.8', 'schema_passed': True, 'executable_sha256': self.lock['ocvalidate_sha256'][self.validator_name],
                            'raw_output_retained': False, 'exit_code': 0})]
        for item in self.patches:
            item.start()
        self.source_oc = self.root / 'module-source' / 'OC'
        self.source_oc.mkdir(parents=True)

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temporary.cleanup()

    def write_config(self):
        self.config_path.write_bytes(plistlib.dumps(self.config, sort_keys=False))

    def make_archive(self, extra=None):
        with zipfile.ZipFile(self.archive, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for name, raw in self.members.items():
                archive.writestr(name, raw)
            if extra is not None:
                archive.writestr(extra[0], extra[1])
        if hasattr(self, 'lock'):
            self.lock.update(release_archive_bytes=self.archive.stat().st_size,
                             release_archive_sha256=A.Q.sha256(self.archive.read_bytes()))

    def assemble(self, name='review-one', **kwargs):
        return A.assemble(self.archive, self.config_path, name, **kwargs)

    def test_explicit_temporary_profile_allows_optional_vault_unsigned_snapshot(self):
        self.config['Misc']['Security']['Vault'] = 'Optional'
        self.write_config()
        result = self.assemble(profile=A.Q.TEST_PROFILE)
        manifest = A.load_manifest(self.stage())
        self.assertEqual(manifest['profile'], A.Q.TEST_PROFILE)
        self.assertTrue(result['profile_policy']['unsigned_pinned_original_efi_allowed'])
        self.assertFalse(result['ready_for_boot'])
        self.assertFalse(result['keys_generated_or_enrolled'])

    def test_default_profile_rejects_optional_vault_before_stage_creation(self):
        self.config['Misc']['Security']['Vault'] = 'Optional'
        self.write_config()
        with self.assertRaises(A.Q.ReviewError):
            self.assemble()
        self.assertFalse(self.stage().exists())

    def test_unknown_profile_is_refused_before_snapshot_creation(self):
        with self.assertRaises(A.Q.ReviewError):
            self.assemble(profile='unknown')
        self.assertFalse(self.stage().exists())

    def test_manifest_unknown_profile_does_not_fall_back_to_strict(self):
        self.assemble()
        path = self.stage() / A.MANIFEST
        manifest = json.loads(path.read_text())
        manifest['profile'] = True
        path.write_text(json.dumps(manifest))
        with self.assertRaises(A.Q.ReviewError):
            A.preflight('review-one', profile=A.Q.TEST_PROFILE)

    def test_explicit_test_preflight_does_not_rewrite_strict_snapshot(self):
        self.assemble()
        path = self.stage() / A.MANIFEST
        before = path.read_bytes()
        result = A.preflight('review-one', profile=A.Q.TEST_PROFILE)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(result['snapshot_profile'], A.Q.DEFAULT_PROFILE)
        self.assertFalse(result['profile_selection_matches_snapshot'])
        self.assertFalse(result['ready_for_boot'])
        self.assertFalse(result['qualification']['firmware_state_verified'])

    def stage(self, name='review-one'):
        return self.root / 'private' / 'assembly' / name

    def add_kext(self, name='SeparateGPU.kext', identifier='de.lunarbridge.separategpu', binary=None, codeless=False):
        bundle = self.source_oc / 'Kexts' / name / 'Contents'
        bundle.mkdir(parents=True, exist_ok=True)
        metadata = {'CFBundleIdentifier': identifier, 'CFBundlePackageType': 'KEXT', 'CFBundleVersion': '0.1.0'}
        executable = ''
        if not codeless:
            metadata['CFBundleExecutable'] = 'Separate'
            (bundle / 'MacOS').mkdir(exist_ok=True)
            (bundle / 'MacOS' / 'Separate').write_bytes(kext_fixture() if binary is None else binary)
            executable = 'Contents/MacOS/Separate'
        (bundle / 'Info.plist').write_bytes(plistlib.dumps(metadata))
        entry = {'Enabled': True, 'BundlePath': name, 'PlistPath': 'Contents/Info.plist', 'ExecutablePath': executable}
        self.config['Kernel']['Add'].append(entry)
        self.write_config()
        return entry

    def test_assembly_creates_only_a_new_private_unsigned_snapshot(self):
        result = self.assemble()
        self.assertEqual(result['file_count'], 5)
        self.assertTrue(result['stage_created'])
        self.assertFalse(result['ready_for_boot'])
        self.assertFalse(result['keys_generated_or_enrolled'])
        self.assertFalse(result['real_efi_or_disk_modified'])
        self.assertEqual((self.stage() / 'EFI/OC/config.plist').read_bytes(), self.config_path.read_bytes())
        self.assertFalse((self.stage() / 'EFI/OC/vault.sig').exists())

    def test_source_config_and_archive_are_preserved(self):
        before = self.config_path.read_bytes(), self.archive.read_bytes()
        self.assemble()
        self.assertEqual(before, (self.config_path.read_bytes(), self.archive.read_bytes()))

    def test_existing_stage_is_never_overwritten(self):
        self.assemble()
        before = (self.stage() / A.MANIFEST).read_bytes()
        with self.assertRaises(A.Q.ReviewError):
            self.assemble()
        self.assertEqual(before, (self.stage() / A.MANIFEST).read_bytes())

    def test_stage_traversal_absolute_and_reserved_names_are_rejected(self):
        for name in ('../outside', '/absolute', 'C:outside', '', 'UPPERCASE', 'bad/name', 'con', 'nul'):
            with self.subTest(name=name), self.assertRaises(A.Q.ReviewError):
                self.assemble(name)

    def test_assembly_cannot_run_beneath_a_real_efi_directory(self):
        with patch.object(A, 'ROOT', self.root / 'EFI' / 'OC'), self.assertRaises(A.Q.ReviewError):
            A.stage_path('review-one')

    def test_junction_in_private_parent_is_rejected(self):
        with patch.object(Path, 'is_junction', return_value=True), self.assertRaises(A.Q.ReviewError):
            self.assemble()

    def test_archive_hash_mismatch_prevents_stage_creation(self):
        self.archive.write_bytes(self.archive.read_bytes() + b'changed')
        with self.assertRaises(A.Q.ReviewError):
            self.assemble()
        self.assertFalse(self.stage().exists())

    def test_missing_active_driver_is_rejected_before_stage_creation(self):
        del self.members['X64/EFI/OC/Drivers/OpenHfsPlus.efi']
        self.make_archive()
        with self.assertRaises(A.Q.ReviewError):
            self.assemble()
        self.assertFalse(self.stage().exists())

    def test_case_colliding_archive_entry_is_rejected(self):
        self.make_archive(('X64/EFI/OC/Drivers/openruntime.efi', pe_fixture()))
        with self.assertRaises(A.Q.ReviewError):
            self.assemble()

    def test_symlink_archive_entry_is_rejected(self):
        name = 'X64/EFI/OC/Drivers/OpenRuntime.efi'
        del self.members[name]
        self.make_archive()
        with zipfile.ZipFile(self.archive, 'a') as archive:
            entry = zipfile.ZipInfo(name)
            entry.create_system = 3
            entry.external_attr = 0o120777 << 16
            archive.writestr(entry, b'outside')
        self.lock.update(release_archive_bytes=self.archive.stat().st_size,
                         release_archive_sha256=A.Q.sha256(self.archive.read_bytes()))
        with self.assertRaises(A.Q.ReviewError):
            self.assemble()

    def test_wrong_efi_architecture_is_rejected(self):
        raw = bytearray(pe_fixture())
        struct.pack_into('<H', raw, 68, 0xAA64)
        self.members['X64/EFI/OC/OpenCore.efi'] = bytes(raw)
        self.make_archive()
        with self.assertRaises(A.Q.ReviewError):
            self.assemble()

    def test_validator_hash_mismatch_is_rejected_before_execution(self):
        self.members['Utilities/ocvalidate/' + self.validator_name] = b'changed-validator'
        self.make_archive()
        with self.assertRaises(A.Q.ReviewError):
            self.assemble()
        A.Q.validate_upstream.assert_not_called()

    def test_invalid_secure_boot_policy_does_not_stage_files(self):
        self.config['UEFI']['Quirks']['DisableSecurityPolicy'] = True
        self.write_config()
        with self.assertRaises(A.Q.ReviewError):
            self.assemble()
        self.assertFalse(self.stage().exists())

    def test_duplicate_driver_input_is_rejected(self):
        self.config['UEFI']['Drivers'].append(copy.deepcopy(self.config['UEFI']['Drivers'][0]))
        self.write_config()
        with self.assertRaises(A.Q.ReviewError):
            self.assemble()

    def test_blank_template_needs_explicit_inspection_flag(self):
        self.config_path.write_bytes(self.original_blank)
        with self.assertRaises(A.Q.ReviewError):
            self.assemble()
        A.Q.validate_upstream.return_value['schema_passed'] = False
        result = self.assemble(inspection_only=True)
        self.assertTrue(result['inspection_only'])
        self.assertFalse(result['upstream_validator']['schema_passed'])
        self.assertFalse(result['ready_for_boot'])

    def test_inspection_flag_does_not_accept_other_schema_failures(self):
        A.Q.validate_upstream.return_value['schema_passed'] = False
        with self.assertRaises(A.Q.ReviewError):
            self.assemble(inspection_only=True)
        self.assertFalse(self.stage().exists())

    def test_enabled_hardware_requires_an_explicit_source_oc(self):
        self.add_kext()
        with self.assertRaises(A.Q.ReviewError):
            self.assemble()

    def test_separate_kext_files_are_copied_without_enabling_other_modules(self):
        self.add_kext()
        self.assemble(source_oc=self.source_oc)
        manifest = json.loads((self.stage() / A.MANIFEST).read_text())
        self.assertEqual(manifest['enabled_separate_kext_bundles'], 1)
        self.assertEqual(len([x for x in manifest['files'] if x['role'] == 'kext']), 2)
        self.assertEqual((self.stage() / 'EFI/OC/config.plist').read_bytes(), self.config_path.read_bytes())

    def test_disabled_module_is_not_copied(self):
        self.config['Kernel']['Add'] = [{'Enabled': False, 'BundlePath': 'SeparateUnused.kext'}]
        self.write_config()
        self.assemble()
        self.assertFalse((self.stage() / 'EFI/OC/Kexts').exists())

    def test_two_hardware_modules_remain_two_distinct_bundles(self):
        self.add_kext()
        self.add_kext('SeparateCamera.kext', 'de.lunarbridge.camera')
        self.assemble(source_oc=self.source_oc)
        manifest = json.loads((self.stage() / A.MANIFEST).read_text())
        self.assertEqual(manifest['enabled_separate_kext_bundles'], 2)

    def test_duplicate_kext_identifiers_are_rejected(self):
        self.add_kext()
        self.add_kext('Other.kext')
        with self.assertRaises(A.Q.ReviewError):
            self.assemble(source_oc=self.source_oc)

    def test_duplicate_kext_bundle_paths_are_rejected(self):
        entry = self.add_kext()
        self.config['Kernel']['Add'].append(copy.deepcopy(entry))
        self.write_config()
        with self.assertRaises(A.Q.ReviewError):
            self.assemble(source_oc=self.source_oc)

    def test_macho_object_is_not_accepted_as_a_kext(self):
        self.add_kext(binary=kext_fixture(filetype=1))
        with self.assertRaises(A.Q.ReviewError):
            self.assemble(source_oc=self.source_oc)

    def test_kext_executable_path_must_match_metadata(self):
        entry = self.add_kext()
        entry['ExecutablePath'] = 'Contents/MacOS/Wrong'
        self.write_config()
        with self.assertRaises(A.Q.ReviewError):
            self.assemble(source_oc=self.source_oc)

    def test_codeless_kext_is_supported_without_faking_a_binary(self):
        self.add_kext(codeless=True)
        self.assemble(source_oc=self.source_oc)
        self.assertTrue((self.stage() / 'EFI/OC/Kexts/SeparateGPU.kext/Contents/Info.plist').exists())

    def test_nested_kext_is_outside_the_separate_module_profile(self):
        self.add_kext()
        (self.source_oc / 'Kexts/SeparateGPU.kext/Contents/Plugins/Nested.kext').mkdir(parents=True)
        with self.assertRaises(A.Q.ReviewError):
            self.assemble(source_oc=self.source_oc)

    def test_portable_paths_reject_windows_device_names_and_trailing_dots(self):
        for name in ('EFI/CON.efi', 'EFI/NUL', 'EFI/file.', 'EFI/name ', 'EFI/bad?.efi', 'EFI/../elsewhere', 'EFI/name:stream'):
            with self.subTest(name=name), self.assertRaises(A.Q.ReviewError):
                A.portable_relative(name)

    def test_acpi_requires_matching_header_length_and_checksum(self):
        raw = bytearray(36)
        raw[:4] = b'SSDT'
        struct.pack_into('<I', raw, 4, 36)
        raw[9] = (-sum(raw)) % 256
        self.assertTrue(A.inspect_acpi(bytes(raw))['header_and_checksum_valid'])
        raw[9] ^= 1
        with self.assertRaises(A.Q.ReviewError):
            A.inspect_acpi(bytes(raw))

    def test_manifest_is_not_a_firmware_trust_certificate(self):
        self.assemble()
        proof = A.preflight('review-one')
        self.assertTrue(proof['snapshot_matches'])
        self.assertFalse(proof['manifest_is_authenticated'])
        self.assertFalse(proof['ready_for_boot'])
        self.assertFalse(proof['qualification']['firmware_state_verified'])

    def test_changed_config_invalidates_vault_and_final_opencore_signing(self):
        self.assemble()
        with (self.stage() / 'EFI/OC/config.plist').open('ab') as handle:
            handle.write(b'\n')
        proof = A.preflight('review-one')
        self.assertEqual(proof['changed_paths'], ['EFI/OC/config.plist'])
        self.assertTrue(proof['signing_dependencies_invalidated']['vault_inventory_signature_and_embedded_key'])
        self.assertTrue(proof['signing_dependencies_invalidated']['final_opencore_authenticode'])
        self.assertFalse(proof['signing_dependencies_invalidated']['bootstrap_authenticode'])
        self.assertIsNone(proof['qualification'])

    def test_driver_change_invalidates_driver_signature_and_vault(self):
        self.assemble()
        (self.stage() / 'EFI/OC/Drivers/OpenRuntime.efi').write_bytes(b'changed')
        proof = A.preflight('review-one')
        self.assertTrue(proof['signing_dependencies_invalidated']['efi_driver_signatures'])
        self.assertTrue(proof['signing_dependencies_invalidated']['final_opencore_authenticode'])

    def test_bootstrap_change_does_not_invalidate_the_oc_directory_vault(self):
        self.assemble()
        (self.stage() / 'EFI/BOOT/BOOTx64.efi').write_bytes(b'changed')
        proof = A.preflight('review-one')
        self.assertTrue(proof['signing_dependencies_invalidated']['bootstrap_authenticode'])
        self.assertFalse(proof['signing_dependencies_invalidated']['vault_inventory_signature_and_embedded_key'])

    def test_opencore_embedding_change_requires_final_loader_signature(self):
        self.assemble()
        (self.stage() / 'EFI/OC/OpenCore.efi').write_bytes(b'changed')
        proof = A.preflight('review-one')
        self.assertTrue(proof['signing_dependencies_invalidated']['final_opencore_authenticode'])
        self.assertFalse(proof['signing_dependencies_invalidated']['vault_inventory_signature_and_embedded_key'])

    def test_module_change_requires_approval_vault_and_final_loader_signature(self):
        self.add_kext()
        self.assemble(source_oc=self.source_oc)
        (self.stage() / 'EFI/OC/Kexts/SeparateGPU.kext/Contents/MacOS/Separate').write_bytes(b'changed')
        proof = A.preflight('review-one')
        self.assertTrue(proof['signing_dependencies_invalidated']['module_approval_and_signature'])
        self.assertTrue(proof['signing_dependencies_invalidated']['vault_inventory_signature_and_embedded_key'])

    def test_added_or_missing_file_invalidates_snapshot(self):
        self.assemble()
        (self.stage() / 'EFI/OC/Drivers/OpenRuntime.efi').unlink()
        (self.stage() / 'EFI/OC/Drivers/Added.efi').write_bytes(b'added')
        proof = A.preflight('review-one')
        self.assertEqual(proof['missing_paths'], ['EFI/OC/Drivers/OpenRuntime.efi'])
        self.assertEqual(proof['added_paths'], ['EFI/OC/Drivers/Added.efi'])
        self.assertFalse(proof['snapshot_matches'])

    def test_manifest_rejects_traversal_even_when_its_json_is_valid(self):
        self.assemble()
        path = self.stage() / A.MANIFEST
        manifest = json.loads(path.read_text())
        manifest['files'][0]['path'] = '../private-key'
        path.write_text(json.dumps(manifest))
        with self.assertRaises(A.Q.ReviewError):
            A.preflight('review-one')

    def test_manifest_rejects_duplicate_json_keys(self):
        self.assemble()
        (self.stage() / A.MANIFEST).write_text('{"schema_version": 1, "schema_version": 1}')
        with self.assertRaises(A.Q.ReviewError):
            A.preflight('review-one')

    def test_manifest_boolean_is_not_an_integer_schema_version(self):
        self.assemble()
        path = self.stage() / A.MANIFEST
        manifest = json.loads(path.read_text())
        manifest['schema_version'] = True
        path.write_text(json.dumps(manifest))
        with self.assertRaises(A.Q.ReviewError):
            A.preflight('review-one')

    def test_manifest_role_cannot_reclassify_an_efi_driver_as_a_kext(self):
        self.assemble()
        path = self.stage() / A.MANIFEST
        manifest = json.loads(path.read_text())
        record = next(item for item in manifest['files'] if item['role'] == 'efi_driver')
        record['role'] = 'kext'
        path.write_text(json.dumps(manifest))
        with self.assertRaises(A.Q.ReviewError):
            A.preflight('review-one')

    def test_manifest_cannot_claim_it_is_authenticated_or_boot_ready(self):
        self.assemble()
        path = self.stage() / A.MANIFEST
        original = json.loads(path.read_text())
        for property_name in ('ready_for_boot', 'manifest_is_authenticated'):
            changed = copy.deepcopy(original)
            changed[property_name] = True
            path.write_text(json.dumps(changed))
            with self.subTest(property=property_name), self.assertRaises(A.Q.ReviewError):
                A.preflight('review-one')

    def test_manifest_release_hash_must_match_the_repository_pin(self):
        self.assemble()
        path = self.stage() / A.MANIFEST
        manifest = json.loads(path.read_text())
        manifest['release_archive_sha256'] = '0' * 64
        path.write_text(json.dumps(manifest))
        with self.assertRaises(A.Q.ReviewError):
            A.preflight('review-one')

    def test_true_input_declarations_do_not_verify_device_or_trust(self):
        self.assemble()
        declarations = self.root / 'declarations.json'
        declarations.write_text(json.dumps({'schema_version': 1, **{name: True for name in A.Q.DECLARATIONS}}))
        result = A.preflight('review-one', declaration_path=declarations)
        self.assertTrue(all(result['qualification']['declared_prerequisites'].values()))
        self.assertFalse(result['ready_for_boot'])
        self.assertFalse(result['device_boot_verified'])
        self.assertFalse(result['qualification']['declarations_are_verified_evidence'])

    def test_hash_stream_enforces_its_bound(self):
        source = self.root / 'small'
        source.write_bytes(b'12345')
        with self.assertRaises(A.Q.ReviewError):
            A.hash_stream(source, 4)

    def test_rsa_signature_rejects_a_forged_chunklist(self):
        with self.assertRaises(A.Q.ReviewError):
            A.validate_chunklist(chunk_fixture())

    def test_hash_only_chunklist_cannot_satisfy_signed_recovery(self):
        with self.assertRaises(A.Q.ReviewError):
            A.validate_chunklist(chunk_fixture(method=2))

    def test_chunklist_truncation_or_trailing_data_is_rejected(self):
        raw = chunk_fixture()
        for changed in (raw[:-1], raw + b'extra', b'CNKL'):
            with self.subTest(length=len(changed)), self.assertRaises(A.Q.ReviewError):
                A.validate_chunklist(changed)

    def test_rsa_verification_uses_the_fixed_apple_public_key(self):
        raw = chunk_fixture()
        with patch.object(A, 'pow', return_value=expected_rsa(raw), create=True) as verification:
            chunks = A.validate_chunklist(raw)
        verification.assert_called_once_with(1, 65537, A.APPLE_RECOVERY_MODULUS)
        self.assertEqual(chunks, [(len(b'recovery fixture'), hashlib.sha256(b'recovery fixture').digest())])

    def test_zero_or_oversized_chunk_is_rejected_after_signature_check(self):
        for size in (0, A.Q.MAX_BINARY + 1):
            raw = chunk_fixture(size=size)
            with patch.object(A, 'pow', return_value=expected_rsa(raw), create=True), self.assertRaises(A.Q.ReviewError):
                A.validate_chunklist(raw)

    def test_streamed_recovery_checks_every_authenticated_chunk(self):
        image = self.root / 'BaseSystem.dmg'
        image.write_bytes(b'recovery fixture')
        chunklist = self.root / 'BaseSystem.chunklist'
        raw = chunk_fixture()
        chunklist.write_bytes(raw)
        with patch.object(A, 'pow', return_value=expected_rsa(raw), create=True):
            proof = A.verify_recovery(image, chunklist)
        self.assertTrue(proof['image_chunks_verified'])
        self.assertFalse(proof['native_recovery_boot_verified'])
        self.assertFalse(proof['os_version_verified'])

    def test_recovery_chunk_hash_mismatch_is_rejected(self):
        image = self.root / 'BaseSystem.dmg'
        image.write_bytes(b'corruptx fixture')
        chunklist = self.root / 'BaseSystem.chunklist'
        raw = chunk_fixture()
        chunklist.write_bytes(raw)
        with patch.object(A, 'pow', return_value=expected_rsa(raw), create=True), self.assertRaises(A.Q.ReviewError):
            A.verify_recovery(image, chunklist)

    def test_recovery_image_size_mismatch_is_rejected(self):
        image = self.root / 'BaseSystem.dmg'
        image.write_bytes(b'recovery fixture extra')
        chunklist = self.root / 'BaseSystem.chunklist'
        raw = chunk_fixture()
        chunklist.write_bytes(raw)
        with patch.object(A, 'pow', return_value=expected_rsa(raw), create=True), self.assertRaises(A.Q.ReviewError):
            A.verify_recovery(image, chunklist)

    def test_recovery_snapshot_contains_only_the_two_verified_inputs(self):
        recovery_dir = self.root / 'com.apple.recovery.boot'
        recovery_dir.mkdir()
        (recovery_dir / 'BaseSystem.dmg').write_bytes(b'recovery fixture')
        raw = chunk_fixture()
        (recovery_dir / 'BaseSystem.chunklist').write_bytes(raw)
        (recovery_dir / 'ignored-download-log').write_text('private log')
        with patch.object(A, 'pow', return_value=expected_rsa(raw), create=True):
            result = self.assemble(recovery_dir=recovery_dir)
        self.assertEqual(result['file_count'], 7)
        self.assertFalse((self.stage() / 'com.apple.recovery.boot/ignored-download-log').exists())

    def test_corrupt_recovery_prevents_destination_creation(self):
        recovery_dir = self.root / 'com.apple.recovery.boot'
        recovery_dir.mkdir()
        (recovery_dir / 'BaseSystem.dmg').write_bytes(b'recovery fixture')
        (recovery_dir / 'BaseSystem.chunklist').write_bytes(chunk_fixture())
        with self.assertRaises(A.Q.ReviewError):
            self.assemble(recovery_dir=recovery_dir)
        self.assertFalse(self.stage().exists())

    def test_recovery_change_invalidates_only_its_pair(self):
        recovery_dir = self.root / 'com.apple.recovery.boot'
        recovery_dir.mkdir()
        (recovery_dir / 'BaseSystem.dmg').write_bytes(b'recovery fixture')
        raw = chunk_fixture()
        (recovery_dir / 'BaseSystem.chunklist').write_bytes(raw)
        with patch.object(A, 'pow', return_value=expected_rsa(raw), create=True):
            self.assemble(recovery_dir=recovery_dir)
        (self.stage() / 'com.apple.recovery.boot/BaseSystem.dmg').write_bytes(b'changed')
        result = A.preflight('review-one')
        self.assertTrue(result['signing_dependencies_invalidated']['recovery_chunklist_and_image_pair'])
        self.assertFalse(result['signing_dependencies_invalidated']['vault_inventory_signature_and_embedded_key'])

    def test_reports_omit_personal_values_and_absolute_input_paths(self):
        self.config['PlatformInfo']['Generic']['SystemSerialNumber'] = 'PRIVATE-SERIAL-TEST'
        self.write_config()
        self.assemble()
        text = json.dumps(A.preflight('review-one'))
        self.assertNotIn('PRIVATE-SERIAL-TEST', text)
        self.assertNotIn(str(self.root), text)


if __name__ == '__main__':
    unittest.main()
