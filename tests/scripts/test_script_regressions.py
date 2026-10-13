#!/usr/bin/env python3
"""Regression tests for standalone build and measurement scripts."""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import logging
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import code_size_compare as sizes


class ScriptRegressions(unittest.TestCase):
    """Use temporary inputs without modifying the checked-out configuration."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.output = self.directory / 'output.c'

    def run_script(self, name, *arguments):
        return subprocess.run(['perl', str(ROOT / 'scripts' / name),
                               *map(str, arguments)], cwd=ROOT,
                              check=False, capture_output=True, text=True)

    def error_input(self, text):
        crypto = self.directory / 'crypto'
        tls = self.directory / 'tls'
        crypto.mkdir()
        tls.mkdir()
        (tls / 'ssl.h').write_text(text)
        (self.directory / 'error.fmt').write_text('HIGH_LEVEL_CODE_CHECKS\n')
        return crypto, tls, self.directory, self.output

    def calculator(self):
        return sizes.CodeSizeCalculator('current', [], 'make', 'size',
                                        mock.Mock())

    def test_error_quoted_description(self):
        args = self.error_input('/** The "quoted" value is invalid. */\n'
                                '#define MBEDTLS_ERR_SSL_TEST -0x7000\n')
        result = self.run_script('generate_errors.pl', *args)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(r'SSL - The \"quoted\" value is invalid', self.output.read_text())

