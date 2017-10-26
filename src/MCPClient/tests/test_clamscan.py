# -*- coding: utf8 -*-
"""Tests for the archivematicaClamscan.py client script."""

from __future__ import print_function

import os
import subprocess
import sys
from collections import OrderedDict

from clamd import ClamdNetworkSocket, ClamdUnixSocket
import pytest

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.abspath(os.path.join(THIS_DIR, '../lib/clientScripts')))

import archivematicaClamscan


@pytest.mark.parametrize("version, want", [
    (
        "ClamAV 0.99.2/23992/Fri Oct 27 05:04:12 2017",
        ("ClamAV 0.99.2", "23992/Fri Oct 27 05:04:12 2017")
    ),
    (
        "ClamAV 0.99.2",
        ("ClamAV 0.99.2", None)
    ),
    (
        "Unexpected value",
        (None, None)
    ),
])
def test_clamav_version_parts(version, want):
    got = archivematicaClamscan.clamav_version_parts(version)
    assert got == want


# ClamdScanner tests

def setup_clamdscanner(settings,
                       addr="/var/run/clamav/clamd.ctl",
                       timeout=10,
                       stream=True):
    settings.CLAMAV_SERVER = addr
    settings.CLAMAV_CLIENT_TIMEOUT = timeout
    settings.CLAMAV_PASS_BY_REFERENCE = not stream

    return archivematicaClamscan.ClamdScanner()


def test_clamdscanner_version_props(mocker, settings):
    scanner = setup_clamdscanner(settings)
    mocker.patch.object(
        scanner, '_version_attrs',
        return_value=("ClamAV 0.99.2", "23992/Fri Oct 27 05:04:12 2017"))

    assert scanner.program == "ClamAV (clamd)"
    assert scanner.version == "ClamAV 0.99.2"
    assert scanner.virus_definitions == "23992/Fri Oct 27 05:04:12 2017"


def test_clamdscanner_get_client(settings):
    scanner = setup_clamdscanner(settings, addr="/var/run/clamav/clamd.ctl")
    assert type(scanner.client) == ClamdUnixSocket

    scanner = setup_clamdscanner(settings, addr="127.0.0.1:1234", timeout=15.5)
    assert type(scanner.client) == ClamdNetworkSocket
    assert scanner.client.host == "127.0.0.1"
    assert scanner.client.port == 1234
    assert scanner.client.timeout == 15.5


def test_clamdscanner_scan(mocker, settings):
    OKAY_RET = ('OK', None)
    ERROR_RET = ('ERROR', 'Permission denied')
    FOUND_RET = ('FOUND', 'Eicar-Test-Signature')

    def patch(scanner, ret=OKAY_RET, excepts=False):
        pv = mocker.patch.object(
            scanner, 'pass_by_value',
            return_value={'stream': ret})
        pr = mocker.patch.object(
            scanner, 'pass_by_reference',
            return_value={'/file': ret})
        if excepts:
            e = Exception('Something bad happened!')
            pv.side_effect = e
            pr.side_effect = e
        return pv, pr

    scanner = setup_clamdscanner(settings, stream=True)
    pv, pr = patch(scanner, ret=OKAY_RET)
    passed, state, details = scanner.scan('/file')
    assert passed is True
    assert state == 'OK'
    assert details is None
    pv.assert_called_once()
    pr.assert_not_called()

    scanner = setup_clamdscanner(settings, stream=False)
    pv, pr = patch(scanner, ret=OKAY_RET)
    passed, state, details = scanner.scan('/file')
    assert passed is True
    assert state == 'OK'
    assert details is None
    pv.assert_not_called()
    pr.assert_called_once()

    pv, pr = patch(scanner, ret=ERROR_RET)
    passed, state, details = scanner.scan('/file')
    assert passed is False
    assert state == 'ERROR'
    assert details == 'Permission denied'

    pv, pr = patch(scanner, ret=FOUND_RET)
    passed, state, details = scanner.scan('/file')
    assert passed is False
    assert state == 'FOUND'
    assert details == 'Eicar-Test-Signature'

    pv, pr = patch(scanner, ret=FOUND_RET, excepts=True)
    passed, state, details = scanner.scan('/file')
    assert passed is False
    assert state is None
    assert details is None


# ClamScanner tests

def setup_clamscanner():
    return archivematicaClamscan.ClamScanner()


def test_clamscanner_version_props(mocker):
    scanner = setup_clamscanner()
    mocker.patch.object(
        scanner, '_version_attrs',
        return_value=("ClamAV 0.99.2", "23992/Fri Oct 27 05:04:12 2017"))

    assert scanner.program == "ClamAV (clamscan)"
    assert scanner.version == "ClamAV 0.99.2"
    assert scanner.virus_definitions == "23992/Fri Oct 27 05:04:12 2017"


def test_clamscanner_scan(mocker):
    scanner = setup_clamscanner()
    mock = mocker.patch.object(scanner, '_call', return_value='Output of clamscan')

    assert scanner.scan('/file') == (True, 'OK', None)
    mock.assert_called_once_with('/file')

    mock.side_effect = subprocess.CalledProcessError(1, 'clamscan', 'Output of clamscan')
    assert scanner.scan('/file') == (False, 'FOUND', None)

    mock.side_effect = subprocess.CalledProcessError(2, 'clamscan', 'Output of clamscan')
    assert scanner.scan('/file') == (False, 'ERROR', None)


# Other tests

def test_get_scanner_threshold(settings):
    """ Test that get_scanner returns an instance of ClamScanner when the
    threshold is exceeded or an instance of ClamdScanner otherwise. """

    # ClamdScanner expects these settings to be defined.
    settings.CLAMAV_SERVER = "/var/run/clamav/clamd.ctl"
    settings.CLAMAV_CLIENT_TIMEOUT = 10
    settings.CLAMAV_PASS_BY_REFERENCE = True

    # Exceeding the threshold.
    settings.CLAMAV_CLIENT_THRESHOLD = 0.5
    file_size = 0.6 * 1024 * 1024
    scanner = archivematicaClamscan.get_scanner(file_size)
    assert type(scanner) is archivematicaClamscan.ClamScanner

    # Not exceeding the threshold.
    settings.CLAMAV_CLIENT_THRESHOLD = 1
    file_size = 1 * 1024 * 1024
    scanner = archivematicaClamscan.get_scanner(file_size)
    assert type(scanner) is archivematicaClamscan.ClamdScanner


args = OrderedDict()
args['file_uuid'] = 'ec26199f-72a4-4fd8-a94a-29144b02ddd8'
args['path'] = '/path'
args['date'] = '2019-12-01'
args['task_uuid'] = 'c380e94e-7a7b-4ab8-aa72-ec0644cc3f5d'


class FileMock():
    def __init__(self, size):
        self.size = size


class ScannerMock(archivematicaClamscan.ScannerBase):
    def __init__(self, should_except=False, passed=False):
        self.should_except = should_except
        self.passed = passed

    @property
    def program(self):
        return "program"

    @property
    def version(self):
        return "version"

    @property
    def virus_definitions(self):
        return "virus_definitions"

    def scan(self, path):
        if self.should_except:
            raise Exception("Something really bad happened!")
        return self.passed, None, None


def test_main_with_expected_arguments(mocker):
    mocker.patch('archivematicaClamscan.scan_file')
    archivematicaClamscan.main(args.values())
    archivematicaClamscan.scan_file.assert_called_once_with(**dict(args))


def test_main_with_missing_arguments():
    with pytest.raises(SystemExit):
        archivematicaClamscan.main([])


def setup_test_scan_file_mocks(mocker,
                               file_already_scanned=False,
                               file_size=1024,
                               scanner_should_except=False,
                               scanner_passed=False):
    fs = mocker.patch(
        'archivematicaClamscan.file_already_scanned',
        return_value=file_already_scanned)
    fg = mocker.patch(
        'main.models.File.objects.get',
        return_value=FileMock(size=file_size))
    re = mocker.patch(
        'archivematicaClamscan.record_event',
        return_value=None)

    sc = ScannerMock(
        should_except=scanner_should_except,
        passed=scanner_passed)
    mocker.patch(
        'archivematicaClamscan.get_scanner',
        return_value=sc)

    return fs, fg, re, sc


def test_scan_file_already_scanned(mocker):
    fs, fg, re, sc = \
        setup_test_scan_file_mocks(
            mocker,
            file_already_scanned=True)

    exit_code = archivematicaClamscan.scan_file(**dict(args))

    assert exit_code == 0
    fs.assert_called_once_with(args['file_uuid'])


def test_scan_file_invalid_size(mocker):
    fs, fg, re, sc = \
        setup_test_scan_file_mocks(
            mocker,
            file_size=0)

    exit_code = archivematicaClamscan.scan_file(**dict(args))

    assert exit_code == 1
    re.assert_called_once_with(
        args['file_uuid'],
        args['date'],
        None,
        False)


def test_scan_file_faulty_scanner(mocker):
    fs, fg, re, sc = \
        setup_test_scan_file_mocks(
            mocker,
            scanner_should_except=True)

    exit_code = archivematicaClamscan.scan_file(**dict(args))

    assert exit_code == 1
    re.assert_called_once_with(
        args['file_uuid'],
        args['date'],
        sc,
        False)


def test_scan_file_virus_found(mocker):
    fs, fg, re, sc = \
        setup_test_scan_file_mocks(
            mocker,
            scanner_passed=False)

    exit_code = archivematicaClamscan.scan_file(**dict(args))

    assert exit_code == 1
    re.assert_called_once_with(
        args['file_uuid'],
        args['date'],
        sc,
        False)


def test_scan_file_passed(mocker):
    fs, fg, re, sc = \
        setup_test_scan_file_mocks(
            mocker,
            scanner_passed=True)

    exit_code = archivematicaClamscan.scan_file(**dict(args))

    assert exit_code == 0
    re.assert_called_once_with(
        args['file_uuid'],
        args['date'],
        sc,
        True)


def test_scan_file_not_passed(mocker):
    fs, fg, re, sc = \
        setup_test_scan_file_mocks(
            mocker,
            scanner_passed=True)

    exit_code = archivematicaClamscan.scan_file(**dict(args))

    assert exit_code == 0
    re.assert_called_once_with(
        args['file_uuid'],
        args['date'],
        sc,
        True)
