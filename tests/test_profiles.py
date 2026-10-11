# SPDX-License-Identifier: GPL-3.0-only
"""Profile boundaries use synthetic EFI fixtures; no device or firmware calls."""
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest import mock

from test_qualification import Q, pe_image


class NativeTestProfileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='opencore-profile-')
        self.root = Path(self.temporary.name)
        self.config = plistlib.loads((Q.ROOT / 'examples/inspection-template.plist').read_bytes())
        self.config['PlatformInfo']['Generic']['SystemProductName'] = 'MacBookPro16,1'
        self.config['Misc']['Security']['Vault'] = 'Optional'
        self.selected = self.root / 'selected.plist'
        self.oc = self.root / 'EFI/OC'
        (self.oc / 'Drivers').mkdir(parents=True)
        (self.root / 'EFI/BOOT').mkdir()
        raw = pe_image()
        for relative in ('OC/OpenCore.efi', 'BOOT/BOOTx64.efi', 'OC/Drivers/OpenRuntime.efi', 'OC/Drivers/OpenHfsPlus.efi'):
            (self.root / 'EFI' / relative).write_bytes(raw)
        self.lock = {'original_efi_sha256': dict.fromkeys(('OpenCore', 'Bootstrap', 'OpenRuntime', 'OpenHfsPlus'), hashlib.sha256(raw).hexdigest())}
        (self.root / 'reference-lock.json').write_text(json.dumps(self.lock))
        self.patch = mock.patch.object(Q, 'ROOT', self.root)
        self.patch.start()
        self.write()

    def tearDown(self):
        self.patch.stop()
        self.temporary.cleanup()

    def write(self):
        raw = plistlib.dumps(self.config, sort_keys=False)
        self.selected.write_bytes(raw)
        (self.oc / 'config.plist').write_bytes(raw)

    def files(self, profile=Q.TEST_PROFILE):
        return Q.file_findings(self.config, self.oc, self.selected.read_bytes(), profile=profile)

    def test_default_remains_strict_and_rejects_optional_vault(self):
        self.assertTrue(Q.profile_policy(Q.DEFAULT_PROFILE)['firmware_secure_boot_required'])
        self.assertIn('Misc/Security/Vault', {x['id'] for x in Q.policy_findings(self.config)})

    def test_explicit_test_profile_accepts_optional_vault(self):
        self.assertEqual(Q.policy_findings(self.config, Q.TEST_PROFILE), [])
        self.assertFalse(Q.profile_policy(Q.TEST_PROFILE)['firmware_state_verified'])

    def test_unknown_or_wrong_typed_profiles_fail_before_review(self):
        for profile in ('', 'native', 'TEMPORARY-NATIVE-TEST', None, True, 1):
            with self.subTest(profile=profile), self.assertRaises(Q.ReviewError):
                Q.profile_policy(profile)

    def test_proposal_changes_vault_without_changing_apple_or_hardware_policy(self):
        self.config['Misc']['Security']['Vault'] = 'Secure'
        before = copy.deepcopy(self.config)
        proposed, changes = Q.proposal(self.config, profile=Q.TEST_PROFILE)
        self.assertEqual(proposed['Misc']['Security']['Vault'], 'Optional')
        self.assertEqual(proposed['Misc']['Security']['SecureBootModel'], before['Misc']['Security']['SecureBootModel'])
        self.assertEqual(proposed['NVRAM'], before['NVRAM'])
        self.assertEqual(proposed['Kernel'], before['Kernel'])
        self.assertEqual(proposed['ACPI'], before['ACPI'])
        self.assertEqual(self.config, before)
        self.assertIn('Misc/Security/Vault', {x['property'] for x in changes})

    def test_test_proposal_does_not_contaminate_next_strict_proposal(self):
        Q.proposal(self.config, profile=Q.TEST_PROFILE)
        strict, _ = Q.proposal(self.config)
        self.assertEqual(strict['Misc']['Security']['Vault'], 'Secure')
        self.assertEqual(Q.POLICY_CHANGES['Misc/Security/Vault'], 'Secure')

    def test_firmware_profile_does_not_disable_apple_secure_boot(self):
        self.config['Misc']['Security']['SecureBootModel'] = 'Disabled'
        self.assertIn('AppleSecureBoot', {x['id'] for x in Q.policy_findings(self.config, Q.TEST_PROFILE)})

    def test_full_sip_and_amfi_rules_still_apply_to_test_profile(self):
        self.config['NVRAM']['Add'][Q.APPLE_GUID]['csr-active-config'] = b'\x03\0\0\0'
        self.config['NVRAM']['Add'][Q.APPLE_GUID]['boot-args'] = 'amfi=0xff'
        ids = {x['id'] for x in Q.policy_findings(self.config, Q.TEST_PROFILE)}
        self.assertTrue({'ExplicitSIP', 'SIP', 'BootArguments'} <= ids)

    def test_test_profile_does_not_bypass_firmware_security_policy(self):
        self.config['UEFI']['Quirks']['DisableSecurityPolicy'] = True
        self.assertIn('UEFI/Quirks/DisableSecurityPolicy', {x['id'] for x in Q.policy_findings(self.config, Q.TEST_PROFILE)})

    def test_unsigned_pinned_originals_allowed_only_in_test_profile(self):
        issues, images = self.files()
        self.assertFalse(any(x['severity'] == 'error' for x in issues))
        efi = [x for x in images if x['kind'] == 'pe']
        self.assertEqual(len(efi), 4)
        self.assertTrue(all(x['matches_original_release'] for x in efi))
        self.assertTrue(all(not x['authenticode_trust_verified'] for x in efi))
        strict, _ = self.files(Q.DEFAULT_PROFILE)
        self.assertTrue(any(x['id'].endswith('/Signature') and x['severity'] == 'error' for x in strict))

    def test_changed_unsigned_original_is_not_permitted_as_pinned(self):
        path = self.oc / 'OpenCore.efi'
        raw = bytearray(path.read_bytes())
        raw[-1] = 1
        path.write_bytes(raw)
        issues, _ = self.files()
        self.assertTrue(any(x['id'] == 'OpenCore/Signature' and x['severity'] == 'error' for x in issues))
        self.assertIn('OpenCore/Provenance', {x['id'] for x in issues})

    def test_unknown_unsigned_efi_driver_still_requires_provenance(self):
        self.config['UEFI']['Drivers'].append({'Enabled': True, 'Path': 'ThirdParty.efi'})
        (self.oc / 'Drivers/ThirdParty.efi').write_bytes(pe_image())
        self.write()
        issues, _ = self.files()
        self.assertTrue(any(x['id'] == 'UEFI/Drivers/2/Signature' and x['severity'] == 'error' for x in issues))

    def test_explicit_secure_vault_still_requires_vault_files_during_test(self):
        self.config['Misc']['Security']['Vault'] = 'Secure'
        self.write()
        issues, _ = self.files()
        self.assertIn('VaultFiles', {x['id'] for x in issues})
        self.assertIn('vault_signature_verified', Q.required_declarations(self.config, Q.TEST_PROFILE))

    def test_present_malformed_optional_vault_is_not_silently_skipped(self):
        (self.oc / 'vault.plist').write_bytes(b'invalid')
        issues, _ = self.files()
        self.assertIn('VaultFiles', {x['id'] for x in issues})

    def test_declarations_cannot_approve_test_boot_or_manufacture_firmware_state(self):
        path = self.root / 'declared.json'
        path.write_text(json.dumps({'schema_version': 1, **dict.fromkeys(Q.required_declarations(self.config, Q.TEST_PROFILE), True)}))
        report = Q.audit(self.selected, oc_root=self.oc, declaration_path=path, profile=Q.TEST_PROFILE)
        self.assertFalse(report['ready_for_boot'])
        self.assertFalse(report['firmware_state_verified'])
        self.assertFalse(report['declarations_are_verified_evidence'])
        self.assertIn('firmware_secure_boot_disabled_for_test', report['required_prerequisites'])
        self.assertTrue({'firmware_secure_boot_live', 'firmware_custom_trust_available', 'efi_authenticode_verified', 'vault_signature_verified'} <= set(report['prerequisites_not_required_for_selected_profile']))
        self.assertIn('native_kext_acceptance_verified', report['required_prerequisites'])

    def test_boolean_declaration_schema_cannot_be_accepted_as_integer(self):
        path = self.root / 'declared.json'
        path.write_text(json.dumps({'schema_version': True}))
        with self.assertRaises(Q.ReviewError):
            Q.audit(self.selected, declaration_path=path, profile=Q.TEST_PROFILE)

    def test_audit_cli_selects_only_explicit_test_profile(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = Q.main(['audit', '--config', str(self.selected), '--profile', Q.TEST_PROFILE])
        self.assertEqual(status, 2)
        self.assertEqual(json.loads(output.getvalue())['profile_policy']['profile'], Q.TEST_PROFILE)

    def test_cli_unknown_profile_is_refused_before_stage_creation(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as failed:
            Q.main(['propose', '--config', str(self.selected), '--stage-name', 'review', '--profile', 'unknown'])
        self.assertEqual(failed.exception.code, 2)
        self.assertFalse((self.root / 'private').exists())

    def test_explicit_test_proposal_cli_preserves_source_and_protection(self):
        before = self.selected.read_bytes()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(Q.main(['propose', '--config', str(self.selected), '--stage-name', 'review', '--profile', Q.TEST_PROFILE]), 0)
        result = plistlib.loads((self.root / 'private/staging/review/proposed.plist').read_bytes())
        self.assertEqual(self.selected.read_bytes(), before)
        self.assertEqual(result['Misc']['Security']['Vault'], 'Optional')
        self.assertEqual(result['Misc']['Security']['SecureBootModel'], 'Default')
        self.assertEqual(result['NVRAM']['Add'][Q.APPLE_GUID]['csr-active-config'], bytes(4))

    def test_invalid_profile_refused_before_any_proposal_write(self):
        destination = self.root / 'private/review'
        with self.assertRaises(Q.ReviewError):
            Q.write_proposal(self.selected, destination, self.root / 'private', profile=None)
        self.assertFalse(destination.exists())
