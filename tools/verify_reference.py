#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check the pinned original release and ocvalidate without installing EFI files."""

import argparse
import importlib.util
import json
from pathlib import Path
import plistlib
import stat
import sys
import tempfile
from urllib.request import Request, urlopen
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('qualification', ROOT / 'tools' / 'qualify_opencore.py')
Q = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(Q)
URL = 'https://github.com/acidanthera/OpenCorePkg/releases/download/1.0.8/OpenCore-1.0.8-RELEASE.zip'


def check_reference(archive: Path, destination: Path) -> dict:
    lock = json.loads((ROOT / 'reference-lock.json').read_text(encoding='utf-8'))
    archive_raw = Q.read_bounded(archive, 16 * 1024 * 1024)
    if len(archive_raw) != lock['release_archive_bytes'] or Q.sha256(archive_raw) != lock['release_archive_sha256']:
        raise Q.ReviewError('The archive does not match the pinned original OpenCore 1.0.8 release.')
    sample_name = 'Docs/Sample.plist'
    validator = 'ocvalidate.exe' if sys.platform == 'win32' else 'ocvalidate' if sys.platform == 'darwin' else 'ocvalidate.linux'
    wanted = {sample_name: lock['sample_sha256'],
              'Utilities/ocvalidate/' + validator: lock['ocvalidate_sha256'][validator]}
    raw_files = {}
    with zipfile.ZipFile(archive) as source:
        for name, digest in wanted.items():
            entries = [entry for entry in source.infolist() if entry.filename == name]
            if len(entries) != 1:
                raise Q.ReviewError('The release contains a missing or duplicated reference file.')
            entry = entries[0]
            if stat.S_ISLNK(entry.external_attr >> 16) or entry.file_size > 8 * 1024 * 1024:
                raise Q.ReviewError('An archive reference entry is unsafe.')
            raw = source.read(entry)
            if Q.sha256(raw) != digest:
                raise Q.ReviewError('An original reference file does not match its pinned hash.')
            raw_files[name] = raw
    # Only a sample and the validator are written to a temporary working directory.
    destination.mkdir(parents=True, exist_ok=False)
    sample = destination / 'Sample.plist'
    sample.write_bytes(raw_files[sample_name])
    executable = destination / validator
    executable.write_bytes(raw_files['Utilities/ocvalidate/' + validator])
    if sys.platform != 'win32':
        executable.chmod(0o755)
    original_result = Q.validate_upstream(sample, executable, lock)
    blank = ROOT / 'examples' / 'inspection-template.plist'
    blank_result = Q.validate_upstream(blank, executable, lock)
    fixture, _ = Q.load_config(blank)
    # A supported model is selected only for this schema fixture, never for a device EFI.
    fixture['PlatformInfo']['Generic']['SystemProductName'] = 'MacBookPro16,1'
    selected = destination / 'schema-fixture.plist'
    selected.write_bytes(plistlib.dumps(fixture, sort_keys=False))
    fixture_result = Q.validate_upstream(selected, executable, lock)
    source_before = Q.sha256(sample.read_bytes())
    proposed = Q.write_proposal(sample, destination / 'private-stage' / 'sample-review', destination / 'private-stage')
    proposed_result = Q.validate_upstream(destination / 'private-stage' / 'sample-review' / 'proposed.plist', executable, lock)
    proof = {'schema_version': 1, 'release_version': Q.VERSION,
             'archive_sha256': Q.sha256(archive_raw), 'platform': sys.platform,
             'original_sample': original_result,
             'public_blank_template': blank_result,
             'schema_fixture_supported_model_only': fixture_result,
             'unchanged_upstream_sample_proposal': proposed_result,
             'proposal_changed_property_count': len(proposed['changes']),
             'source_preserved': Q.sha256(sample.read_bytes()) == source_before,
             'public_blank_is_deliberately_incomplete': not blank_result['schema_passed'],
             'native_boot_verified': False, 'firmware_or_efi_writes': False}
    if not (original_result['schema_passed'] and fixture_result['schema_passed'] and
            proposed_result['schema_passed'] and proof['source_preserved'] and
            proof['public_blank_is_deliberately_incomplete']):
        raise Q.ReviewError('Original validation or the intentional missing-identity guard did not behave as required.')
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--archive', type=Path, help='Read an already downloaded official 1.0.8 RELEASE archive.')
    choice.add_argument('--download', action='store_true', help='Download only the pinned official reference archive.')
    arguments = parser.parse_args()
    parent = ROOT / 'private' / 'reference-verification'
    if any(part.lower() in {'efi', 'boot', 'com.apple.recovery.boot'} for part in parent.parts):
        raise Q.ReviewError('Reference checks cannot run in an EFI or boot directory.')
    for part in (parent, *parent.parents):
        if part.is_symlink() or part.is_junction():
            raise Q.ReviewError('The reference working path must not contain links or junctions.')
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='reference-', dir=parent) as temp:
        working = Path(temp)
        archive = arguments.archive
        if arguments.download:
            archive = working / 'OpenCore-1.0.8-RELEASE.zip'
            with urlopen(Request(URL, headers={'User-Agent': 'LunarBridge-OpenCore'}), timeout=45) as response:
                downloaded = response.read(16 * 1024 * 1024 + 1)
            if len(downloaded) > 16 * 1024 * 1024:
                raise Q.ReviewError('Reference download exceeds its size limit.')
            archive.write_bytes(downloaded)
        proof = check_reference(archive, working / 'checked')
        print(json.dumps(proof, indent=2))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (Q.ReviewError, OSError, ValueError, zipfile.BadZipFile):
        print(json.dumps({'error': 'Pinned reference verification failed.', 'native_boot_verified': False}), file=sys.stderr)
        raise SystemExit(3)
