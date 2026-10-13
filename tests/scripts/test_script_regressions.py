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


    def test_feature_preprocessor_whitespace(self):
        (self.directory / 'mbedtls_config.h').write_text(
            '// SECTION: TLS feature selection\n'
            '#define\tMBEDTLS_SSL_TLS_C\n'
            '# define   MBEDTLS_SSL_CLI_C\n'
            '//#define MBEDTLS_SSL_SRV_C\n')
        (self.directory / 'version_features.fmt').write_text('FEATURE_DEFINES\n')
        result = self.run_script('generate_features.pl', self.directory,
                                 self.directory, self.output)
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ('SSL_TLS_C', 'SSL_CLI_C', 'SSL_SRV_C'):
            self.assertIn('"' + name + '"', self.output.read_text())


    def test_query_ignores_function_macros(self):
        config = self.directory / 'config.h'
        config.write_text('#define MBEDTLS_CALLBACK(x) (x)\n'
                          '#define MBEDTLS_CALLBACK_VALUE (1)\n')
        psa = self.directory / 'psa.h'
        psa.write_text('')
        template = self.directory / 'query.fmt'
        template.write_text('CHECK_CONFIG\nLIST_CONFIG\n')
        result = self.run_script('generate_query_config.pl', config, psa,
                                 template, self.output)
        self.assertEqual(result.returncode, 0, result.stderr)
        generated = self.output.read_text()
        self.assertNotIn('defined(MBEDTLS_CALLBACK)', generated)
        self.assertIn('defined(MBEDTLS_CALLBACK_VALUE)', generated)


    def test_size_build_restores_configuration_on_failure(self):
        calculator = self.calculator()
        config = self.directory / 'mbedtls_config.h'
        crypto = self.directory / 'crypto_config.h'
        config.write_text('original TLS config')
        crypto.write_text('original crypto config')

        def failed_build(*_args, **_kwargs):
            config.write_text('temporary TLS config')
            crypto.write_text('temporary crypto config')
            raise subprocess.CalledProcessError(1, 'make')

        with mock.patch.object(sizes, 'CONFIG_H', str(config)), \
                mock.patch.object(sizes, 'CRYPTO_CONFIG_H', str(crypto)), \
                mock.patch.object(sizes.subprocess, 'check_output', side_effect=failed_build):
            with self.assertRaises(SystemExit):
                calculator._build_libraries('.')
        self.assertEqual(config.read_text(), 'original TLS config')
        self.assertEqual(crypto.read_text(), 'original crypto config')

    def test_size_failure_removes_worktree_once(self):
        calculator = self.calculator()
        calculator.git_rev = 'example'
        with mock.patch.object(calculator, '_create_git_worktree', return_value='temp-example'), \
                mock.patch.object(calculator, '_remove_worktree') as remove, \
                mock.patch.object(sizes.subprocess, 'check_output',
                                  side_effect=subprocess.CalledProcessError(1, 'make')):
            with self.assertRaises(SystemExit):
                calculator.cal_libraries_code_size()
        remove.assert_called_once_with('temp-example')


    def test_size_records_accept_blank_lines(self):
        generator = sizes.CodeSizeGeneratorWithSize(logging.getLogger(__name__))
        generator._set_size_record('old', 'TLS',
                                   'text data bss dec hex filename\n\n'
                                   '1 2 3 6 6 sample.o\n\n'
                                   '1 2 3 6 6 (TOTALS)\n')
        self.assertEqual(generator.code_size['old']['TLS']['sample.o'].total, 6)
        record = self.directory / 'record.txt'
        record.write_text('TLS\n\nsample.o 1 2 3 6\n\nTLS-TOTALS 1 2 3 6\n')
        generator.read_size_record('new', str(record))
        self.assertEqual(generator.code_size['new']['TLS']['sample.o'].total, 6)
