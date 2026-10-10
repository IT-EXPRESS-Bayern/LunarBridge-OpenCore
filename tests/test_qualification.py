# SPDX-License-Identifier: GPL-3.0-only
import copy
import importlib.util
import io
import json
from pathlib import Path
import plistlib
import struct
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('qualification', ROOT / 'tools' / 'qualify_opencore.py')
Q = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(Q)


def pe_image(certificate=False):
    raw = bytearray(512)
    raw[:2] = b'MZ'
    struct.pack_into('<I', raw, 60, 128)
    raw[128:132] = b'PE\0\0'
    struct.pack_into('<H', raw, 132, 0x8664)
    struct.pack_into('<H', raw, 148, 240)
    struct.pack_into('<H', raw, 152, 0x20B)
    struct.pack_into('<H', raw, 220, 10)
    struct.pack_into('<I', raw, 260, 16)
    if certificate:
        struct.pack_into('<II', raw, 296, 496, 16)
        struct.pack_into('<IHH', raw, 496, 16, 0x200, 2)
    return bytes(raw)


def kext_image(filetype=11, signed=False):
    raw = bytearray(80)
    struct.pack_into('<IIIIIIII', raw, 0, 0xFEEDFACF, 0x01000007, 3, filetype, int(signed), 16 if signed else 0, 0, 0)
    if signed:
        struct.pack_into('<IIII', raw, 32, 0x1D, 16, 64, 16)
    return bytes(raw)


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='opencore-review-')
        self.folder = Path(self.temp.name)
        self.config = plistlib.loads((ROOT / 'examples' / 'inspection-template.plist').read_bytes())
        self.config['PlatformInfo']['Generic']['SystemProductName'] = 'MacBookPro16,1'
        self.config_path = self.folder / 'selected.plist'
        self.write()

    def tearDown(self):
        self.temp.cleanup()

    def write(self):
        self.config_path.write_bytes(plistlib.dumps(self.config, sort_keys=False))

    def issue_ids(self):
        return {issue['id'] for issue in Q.policy_findings(self.config)}

    def offline_oc(self):
        root = self.folder / 'OC'
        root.mkdir()
        (self.folder / 'BOOT').mkdir()
        (root / 'Drivers').mkdir()
        (root / 'OpenCore.efi').write_bytes(pe_image(True))
        (self.folder / 'BOOT' / 'BOOTx64.efi').write_bytes(pe_image(True))
        (root / 'config.plist').write_bytes(self.config_path.read_bytes())
        for name in ('OpenRuntime.efi', 'OpenHfsPlus.efi'):
            (root / 'Drivers' / name).write_bytes(pe_image(True))
        files = {name.replace('/', '\\'): __import__('hashlib').sha256((root / name).read_bytes()).digest()
                 for name in ('config.plist', 'Drivers/OpenRuntime.efi', 'Drivers/OpenHfsPlus.efi')}
        (root / 'vault.plist').write_bytes(plistlib.dumps({'Version': 1, 'Files': files}))
        (root / 'vault.sig').write_bytes(bytes(256))
        return root

    def test_review_policy_fixture_has_no_policy_errors(self):
        self.assertEqual(Q.policy_findings(self.config), [])

    def test_public_template_deliberately_has_no_mac_identity(self):
        template = ROOT / 'examples' / 'inspection-template.plist'
        report = Q.audit(template)
        self.assertIn('TahoeSMBIOS', {issue['id'] for issue in report['findings']})
        self.assertFalse(report['ready_for_boot'])

    def test_unsigned_firmware_policy_is_not_accepted(self):
        self.config['UEFI']['Quirks']['DisableSecurityPolicy'] = True
        self.assertIn('UEFI/Quirks/DisableSecurityPolicy', self.issue_ids())

    def test_apple_policy_disabled_is_not_accepted(self):
        self.config['Misc']['Security']['SecureBootModel'] = 'Disabled'
        self.assertIn('AppleSecureBoot', self.issue_ids())

    def test_apple_fixed_model_must_match_tahoe_smbios(self):
        self.config['Misc']['Security']['SecureBootModel'] = 'j137'
        self.assertIn('AppleModelMatch', self.issue_ids())
        self.config['Misc']['Security']['SecureBootModel'] = 'j152f'
        self.assertNotIn('AppleModelMatch', self.issue_ids())

    def test_proposal_preserves_cpuid_acpi_and_hardware_driver_arrays(self):
        self.config['Kernel']['Emulate']['Cpuid1Data'] = bytes(range(16))
        self.config['Kernel']['Emulate']['Cpuid1Mask'] = b'\xff' * 4 + bytes(12)
        self.config['Kernel']['Add'] = [{'Enabled': False, 'BundlePath': 'Separate.kext'}]
        self.config['ACPI']['Add'] = [{'Enabled': False, 'Path': 'SSDT-OWN.aml'}]
        before = copy.deepcopy(self.config)
        proposed, _ = Q.proposal(self.config)
        for section, entry in [('Kernel', 'Emulate'), ('Kernel', 'Add'), ('ACPI', 'Add')]:
            self.assertEqual(proposed[section][entry], before[section][entry])

    def test_optional_vault_is_not_accepted(self):
        self.config['Misc']['Security']['Vault'] = 'Optional'
        self.assertIn('Misc/Security/Vault', self.issue_ids())

    def test_any_disk_image_is_not_accepted(self):
        self.config['Misc']['Security']['DmgLoading'] = 'Any'
        self.assertIn('Misc/Security/DmgLoading', self.issue_ids())

    def test_signed_recovery_is_not_confused_with_disabled_recovery(self):
        self.config['Misc']['Security']['DmgLoading'] = 'Disabled'
        self.assertIn('Misc/Security/DmgLoading', self.issue_ids())

    def test_unrestricted_scan_is_not_accepted(self):
        self.config['Misc']['Security']['ScanPolicy'] = 0
        self.assertIn('ScanPolicy', self.issue_ids())

    def test_original_scan_mask_omits_our_usb_and_esp_paths(self):
        self.assertFalse(0x010F0103 & 0x00200000)
        self.assertFalse(0x010F0103 & 0x00000400)
        self.assertEqual(Q.SCAN_POLICY & 0x00280703, 0x00280703)

    def test_hidden_picker_is_not_accepted(self):
        self.config['Misc']['Boot']['ShowPicker'] = False
        self.assertIn('Misc/Boot/ShowPicker', self.issue_ids())

    def test_short_picker_timeout_is_not_accepted(self):
        self.config['Misc']['Boot']['Timeout'] = 0
        self.assertIn('PickerTimeout', self.issue_ids())

    def test_launcher_does_not_create_a_firmware_boot_entry(self):
        self.config['Misc']['Boot']['LauncherOption'] = 'Full'
        self.assertIn('Misc/Boot/LauncherOption', self.issue_ids())

    def test_windows_oem_smbios_needs_both_paired_settings(self):
        self.config['Kernel']['Quirks']['CustomSMBIOSGuid'] = False
        self.assertIn('Kernel/Quirks/CustomSMBIOSGuid', self.issue_ids())
        self.config['PlatformInfo']['UpdateSMBIOSMode'] = 'Create'
        self.assertIn('PlatformInfo/UpdateSMBIOSMode', self.issue_ids())

    def test_sip_weakened_is_not_accepted(self):
        self.config['NVRAM']['Add'][Q.APPLE_GUID]['csr-active-config'] = b'\x03\0\0\0'
        self.assertIn('SIP', self.issue_ids())

    def test_missing_explicit_sip_cannot_inherit_an_unknown_firmware_value(self):
        del self.config['NVRAM']['Add'][Q.APPLE_GUID]['csr-active-config']
        self.assertIn('ExplicitSIP', self.issue_ids())
        proposed, _ = Q.proposal(self.config)
        self.assertEqual(proposed['NVRAM']['Add'][Q.APPLE_GUID]['csr-active-config'], bytes(4))

    def test_security_bypass_arguments_are_not_accepted(self):
        self.config['NVRAM']['Add'][Q.APPLE_GUID]['boot-args'] = '-v amfi_get_out_of_my_way=1'
        self.assertIn('BootArguments', self.issue_ids())

    def test_other_amfi_masks_cannot_escape_the_bypass_check(self):
        self.config['NVRAM']['Add'][Q.APPLE_GUID]['boot-args'] = '-v amfi=0xff'
        self.assertIn('BootArguments', self.issue_ids())

    def test_broken_xhci_port_limit_is_not_accepted(self):
        self.config['Kernel']['Quirks']['XhciPortLimit'] = True
        self.assertIn('Kernel/Quirks/XhciPortLimit', self.issue_ids())

    def test_administrative_firmware_tool_is_not_accepted(self):
        self.config['Misc']['Tools'] = [{'Enabled': True, 'Path': 'OpenShell.efi'}]
        self.assertIn('Misc/Tools/0/AdministrativeTool', self.issue_ids())

    def test_enabled_acpi_remains_unqualified_for_windows(self):
        self.config['ACPI']['Add'] = [{'Enabled': True, 'Path': 'SSDT-TEST.aml'}]
        self.assertIn('ACPI/Add/0/Windows', self.issue_ids())

    def test_forced_kernel_extension_is_not_accepted(self):
        self.config['Kernel']['Force'] = [{'Enabled': True, 'BundlePath': 'Example.kext'}]
        self.assertIn('Kernel/Force/0/Force', self.issue_ids())

    def test_wrong_entry_boolean_is_rejected(self):
        self.config['UEFI']['Drivers'][0]['Enabled'] = 1
        self.assertIn('UEFI/Drivers/0', self.issue_ids())

    def test_missing_openruntime_blocks_variable_routing(self):
        self.config['UEFI']['Drivers'] = []
        self.assertIn('OpenRuntime', self.issue_ids())

    def test_bitlocker_graphical_keyboard_mirroring_is_required(self):
        self.config['UEFI']['AppleInput']['GraphicsInputMirroring'] = False
        self.assertIn('UEFI/AppleInput/GraphicsInputMirroring', self.issue_ids())

    def test_duplicate_xml_keys_are_rejected(self):
        self.config_path.write_bytes(b'<plist><dict><key>Kernel</key><dict/><key>Kernel</key><dict/></dict></plist>')
        with self.assertRaises(Q.ReviewError):
            Q.load_config(self.config_path)

    def test_binary_plist_is_rejected(self):
        self.config_path.write_bytes(plistlib.dumps(self.config, fmt=plistlib.FMT_BINARY))
        with self.assertRaises(Q.ReviewError):
            Q.load_config(self.config_path)

    def test_xml_entity_declaration_is_rejected(self):
        self.config_path.write_bytes(b'<!DOCTYPE plist [<!ENTITY x "private">]><plist><dict/></plist>')
        with self.assertRaises(Q.ReviewError):
            Q.load_config(self.config_path)

    def test_xml_real_or_date_objects_are_rejected(self):
        self.config['#unsupported'] = 1.2
        self.write()
        with self.assertRaises(Q.ReviewError):
            Q.load_config(self.config_path)

    def test_path_traversal_is_rejected(self):
        for path in ('../Windows.efi', '/BOOT.efi', 'C:/BOOT.efi', 'a\\b.efi', 'a//b', './a', 'a/../b'):
            with self.subTest(path=path), self.assertRaises(Q.ReviewError):
                Q.relative_path(path)

    def test_enabled_driver_traversal_is_rejected(self):
        self.config['UEFI']['Drivers'][0]['Path'] = '../Other.efi'
        self.assertIn('UEFI/Drivers/0', self.issue_ids())

    def test_pe_unsigned_is_detected_without_claiming_crypto_verification(self):
        result = Q.inspect_pe(pe_image())
        self.assertFalse(result['certificate_table_present'])
        self.assertFalse(result['authenticode_trust_verified'])

    def test_pe_certificate_presence_does_not_prove_trust(self):
        result = Q.inspect_pe(pe_image(True))
        self.assertTrue(result['certificate_table_present'])
        self.assertFalse(result['authenticode_trust_verified'])

    def test_pe_out_of_bounds_certificate_is_rejected(self):
        raw = bytearray(pe_image(True))
        struct.pack_into('<I', raw, 296, 0x10000)
        with self.assertRaises(Q.ReviewError):
            Q.inspect_pe(raw)

    def test_pe_non_efi_or_wrong_architecture_is_rejected(self):
        for offset, value in ((132, 0x14C), (220, 3)):
            raw = bytearray(pe_image())
            struct.pack_into('<H', raw, offset, value)
            with self.subTest(offset=offset), self.assertRaises(Q.ReviewError):
                Q.inspect_pe(raw)

    def test_macho_object_is_not_a_loadable_kext(self):
        with self.assertRaises(Q.ReviewError):
            Q.inspect_kext(kext_image(1))

    def test_macho_unsigned_kext_detected(self):
        self.assertFalse(Q.inspect_kext(kext_image())['code_signature_present'])

    def test_macho_signature_presence_is_not_load_approval(self):
        result = Q.inspect_kext(kext_image(signed=True))
        self.assertTrue(result['code_signature_present'])
        self.assertFalse(result['signature_trust_verified'])

    def test_macho_malformed_commands_are_rejected(self):
        raw = bytearray(kext_image(signed=True))
        struct.pack_into('<I', raw, 36, 0)
        with self.assertRaises(Q.ReviewError):
            Q.inspect_kext(raw)

    def test_vault_hashes_and_signature_size_do_not_manufacture_rsa_trust(self):
        root = self.offline_oc()
        result = Q.inspect_vault(root, {'config.plist', 'Drivers/OpenRuntime.efi'})
        self.assertTrue(result['listed_hashes_match'])
        self.assertTrue(result['required_inputs_covered'])
        self.assertFalse(result['rsa_signature_verified'])
        self.assertFalse(result['embedded_key_verified'])

    def test_vault_changed_file_is_rejected(self):
        root = self.offline_oc()
        (root / 'Drivers' / 'OpenRuntime.efi').write_bytes(b'changed')
        with self.assertRaises(Q.ReviewError):
            Q.inspect_vault(root, {'config.plist'})

    def test_vault_missing_required_enabled_file_is_rejected(self):
        root = self.offline_oc()
        with self.assertRaises(Q.ReviewError):
            Q.inspect_vault(root, {'config.plist', 'Kexts/Separate.kext/Contents/Info.plist'})

    def test_vault_unsafe_paths_are_rejected(self):
        root = self.offline_oc()
        (root / 'vault.plist').write_bytes(plistlib.dumps({'Version': 1, 'Files': {'..\\outside': bytes(32)}}))
        with self.assertRaises(Q.ReviewError):
            Q.inspect_vault(root, {'config.plist'})

    def test_vault_wrong_signature_size_is_rejected(self):
        root = self.offline_oc()
        (root / 'vault.sig').write_bytes(bytes(255))
        with self.assertRaises(Q.ReviewError):
            Q.inspect_vault(root, {'config.plist'})

    def test_vault_unknown_schema_version_is_rejected(self):
        root = self.offline_oc()
        data = plistlib.loads((root / 'vault.plist').read_bytes())
        data['Version'] = 2
        (root / 'vault.plist').write_bytes(plistlib.dumps(data))
        with self.assertRaises(Q.ReviewError):
            Q.inspect_vault(root, {'config.plist'})

    def test_offline_config_must_match_explicit_selected_bytes(self):
        root = self.offline_oc()
        (root / 'config.plist').write_bytes(b'different configuration')
        issues, _ = Q.file_findings(self.config, root, self.config_path.read_bytes())
        self.assertIn('SelectedConfigBinding', {issue['id'] for issue in issues})

    def test_changed_signed_binary_provenance_stays_unproven(self):
        root = self.offline_oc()
        issues, images = Q.file_findings(self.config, root, self.config_path.read_bytes())
        self.assertIn('OpenCore/Provenance', {issue['id'] for issue in issues})
        original = next(image for image in images if image['entry'] == 'OpenCore')
        self.assertFalse(original['matches_original_release'])
        self.assertFalse(original['authenticode_trust_verified'])

    def test_separate_modules_cannot_be_nested_inside_another_kext(self):
        self.config['Kernel']['Add'] = [{'Enabled': True, 'BundlePath': 'LunarBridge.kext/Contents/PlugIns/Audio.kext',
                                        'PlistPath': 'Contents/Info.plist', 'ExecutablePath': 'Contents/MacOS/Audio'}]
        self.write()
        root = self.offline_oc()
        issues, _ = Q.file_findings(self.config, root, self.config_path.read_bytes())
        self.assertIn('Kernel/Add/0', {issue['id'] for issue in issues})

    def test_complete_synthetic_offline_structure_still_cannot_approve_boot(self):
        root = self.offline_oc()
        declarations = self.folder / 'complete-declarations.json'
        declarations.write_text(json.dumps({'schema_version': 1, **dict.fromkeys(Q.DECLARATIONS, True)}))
        result = Q.audit(self.config_path, oc_root=root, declaration_path=declarations)
        self.assertTrue(result['offline_policy_passed'])
        self.assertFalse(result['ready_for_boot'])
        self.assertFalse(result['device_boot_verified'])

    def test_oc_directory_junction_is_rejected_without_accessing_targets(self):
        root = self.folder / 'OC'
        with mock.patch.object(Path, 'is_junction', return_value=True):
            issues, _ = Q.file_findings(self.config, root, self.config_path.read_bytes())
        self.assertEqual(issues[0]['severity'], 'error')

    def test_report_does_not_print_private_smbios_or_boot_arguments(self):
        secret = 'PRIVATE-IDENTITY-EXAMPLE'
        self.config['PlatformInfo']['Generic']['SystemSerialNumber'] = secret
        self.config['NVRAM']['Add'][Q.APPLE_GUID]['boot-args'] = '-v ' + secret
        self.write()
        report = json.dumps(Q.audit(self.config_path))
        self.assertNotIn(secret, report)
        self.assertNotIn(str(self.folder), report)

    def test_boolean_declarations_cannot_manufacture_device_or_boot_verification(self):
        declarations = self.folder / 'declarations.json'
        declarations.write_text(json.dumps({'schema_version': 1, **dict.fromkeys(Q.DECLARATIONS, True)}))
        result = Q.audit(self.config_path, declaration_path=declarations)
        self.assertTrue(all(result['declared_prerequisites'].values()))
        self.assertFalse(result['ready_for_boot'])
        self.assertFalse(result['firmware_state_verified'])
        self.assertFalse(result['declarations_are_verified_evidence'])

    def test_private_or_unknown_declaration_fields_are_rejected(self):
        declarations = self.folder / 'declarations.json'
        declarations.write_text(json.dumps({'schema_version': 1, 'SystemUUID': 'private'}))
        with self.assertRaises(Q.ReviewError):
            Q.audit(self.config_path, declaration_path=declarations)

    def test_non_boolean_declaration_is_rejected(self):
        declarations = self.folder / 'declarations.json'
        declarations.write_text(json.dumps({'schema_version': 1, 'backup_checked': 'yes'}))
        with self.assertRaises(Q.ReviewError):
            Q.audit(self.config_path, declaration_path=declarations)

    def test_proposal_preserves_original_and_private_identity(self):
        self.config['PlatformInfo']['Generic']['SystemSerialNumber'] = 'LOCAL-PRIVATE-TEST'
        self.config['Misc']['Security']['ScanPolicy'] = 0
        self.write()
        source = self.config_path.read_bytes()
        root = self.folder / 'staging'
        report = Q.write_proposal(self.config_path, root / 'review-1', root)
        proposed = plistlib.loads((root / 'review-1' / 'proposed.plist').read_bytes())
        self.assertEqual(self.config_path.read_bytes(), source)
        self.assertEqual((root / 'review-1' / 'source.plist').read_bytes(), source)
        self.assertEqual(proposed['PlatformInfo']['Generic']['SystemSerialNumber'], 'LOCAL-PRIVATE-TEST')
        self.assertNotIn('LOCAL-PRIVATE-TEST', json.dumps(report))
        self.assertEqual(proposed['Misc']['Security']['ScanPolicy'], Q.SCAN_POLICY)
        self.assertFalse(report['deployed'])

    def test_proposal_refuses_existing_stage_without_overwriting(self):
        root = self.folder / 'staging'
        root.mkdir()
        selected = root / 'existing'
        selected.mkdir()
        marker = selected / 'marker'
        marker.write_text('keep')
        with self.assertRaises(Q.ReviewError):
            Q.write_proposal(self.config_path, selected, root)
        self.assertEqual(marker.read_text(), 'keep')

    def test_proposal_refuses_path_outside_private_root(self):
        root = self.folder / 'staging'
        with self.assertRaises(Q.ReviewError):
            Q.write_proposal(self.config_path, self.folder / 'outside', root)
        self.assertFalse((self.folder / 'outside').exists())

    def test_proposal_refuses_efi_location_without_writes(self):
        root = self.folder / 'EFI'
        with self.assertRaises(Q.ReviewError):
            Q.write_proposal(self.config_path, root / 'stage', root)
        self.assertFalse(root.exists())

    def test_proposal_does_not_reset_personalised_apple_ecid(self):
        self.config['Misc']['Security']['ApECID'] = 42
        with self.assertRaises(Q.ReviewError):
            Q.proposal(self.config)

    def test_proposal_does_not_blindly_rewrite_bypass_arguments(self):
        self.config['NVRAM']['Add'][Q.APPLE_GUID]['boot-args'] = 'amfi=0x80'
        with self.assertRaises(Q.ReviewError):
            Q.proposal(self.config)

    def test_ocvalidate_mismatching_executable_is_not_executed(self):
        executable = self.folder / 'tool'
        executable.write_bytes(b'untrusted executable')
        reference = json.loads((ROOT / 'reference-lock.json').read_text())
        with mock.patch.object(Q.subprocess, 'run') as run, self.assertRaises(Q.ReviewError):
            Q.validate_upstream(self.config_path, executable, reference)
        run.assert_not_called()

    def test_ocvalidate_wrong_version_banner_is_rejected(self):
        executable = self.folder / 'tool'
        executable.write_bytes(b'test fixture')
        reference = {'ocvalidate_sha256': {'fixture': Q.sha256(b'test fixture')}}
        output = mock.Mock(stdout=b'OpenCore version 1.0.7', stderr=b'', returncode=0)
        with mock.patch.object(Q.subprocess, 'run', return_value=output), self.assertRaises(Q.ReviewError):
            Q.validate_upstream(self.config_path, executable, reference)

    def test_ocvalidate_raw_output_never_enters_sanitised_report(self):
        executable = self.folder / 'tool'
        executable.write_bytes(b'test fixture')
        reference = {'ocvalidate_sha256': {'fixture': Q.sha256(b'test fixture')}}
        output = mock.Mock(stdout=b'OpenCore version 1.0.8 PRIVATE-SOURCE-PATH', stderr=b'', returncode=0)
        with mock.patch.object(Q.subprocess, 'run', return_value=output):
            report = Q.validate_upstream(self.config_path, executable, reference)
        self.assertTrue(report['schema_passed'])
        self.assertNotIn('PRIVATE-SOURCE-PATH', json.dumps(report))

    def test_cli_audit_keeps_device_readiness_blocked(self):
        with mock.patch('sys.stdout', new_callable=io.StringIO) as output:
            result = Q.main(['audit', '--config', str(self.config_path)])
        self.assertEqual(result, 2)
        self.assertFalse(json.loads(output.getvalue())['ready_for_boot'])

    def test_cli_error_does_not_repeat_private_paths(self):
        with mock.patch('sys.stderr', new_callable=io.StringIO) as output:
            result = Q.main(['audit', '--config', str(self.folder / 'PRIVATE-PATH')])
        self.assertEqual(result, 3)
        self.assertNotIn('PRIVATE-PATH', output.getvalue())


if __name__ == '__main__':
    unittest.main(verbosity=2)
