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

    def test_size_cache_includes_optimization(self):
        small = sizes.CodeSizeDistinctInfo('old', 'abc123', 'x86_64',
                                            'default', 'cc', '-Os')
        fast = sizes.CodeSizeDistinctInfo('new', 'abc123', 'x86_64',
                                           'default', 'cc', '-O2')
        self.assertNotEqual(small.get_info_indication(), fast.get_info_indication())


    def test_feature_adjacent_sections(self):
        (self.directory / 'mbedtls_config.h').write_text(
            '// SECTION: TLS feature selection\n#define MBEDTLS_SSL_TLS_C\n'
            '// SECTION: X.509 feature selection\n#define MBEDTLS_X509_USE_C\n')
        (self.directory / 'version_features.fmt').write_text('FEATURE_DEFINES\n')
        result = self.run_script('generate_features.pl', self.directory,
                                 self.directory, self.output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"X509_USE_C"', self.output.read_text())


    def test_query_indented_comments(self):
        config = self.directory / 'config.h'
        config.write_text('  //#define MBEDTLS_SSL_TEST_FEATURE\n')
        psa = self.directory / 'psa.h'
        psa.write_text('')
        template = self.directory / 'query.fmt'
        template.write_text('CHECK_CONFIG\nLIST_CONFIG\n')
        result = self.run_script('generate_query_config.pl', config, psa,
                                 template, self.output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('defined(MBEDTLS_SSL_TEST_FEATURE)', self.output.read_text())


    def test_query_duplicate_definitions(self):
        config = self.directory / 'config.h'
        config.write_text('#if SOME_CONDITION\n#define MBEDTLS_TEST 1\n'
                          '#else\n#define MBEDTLS_TEST 2\n#endif\n')
        psa = self.directory / 'psa.h'
        psa.write_text('')
        template = self.directory / 'query.fmt'
        template.write_text('CHECK_CONFIG\nLIST_CONFIG\n')
        result = self.run_script('generate_query_config.pl', config, psa,
                                 template, self.output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_text().count('OUTPUT_MACRO_NAME_VALUE(MBEDTLS_TEST)'), 1)


    def test_skip_suite_literal_dot(self):
        for name in ('test_suite_foo.bar', 'test_suite_fooXbar'):
            suite = self.directory / name
            suite.write_text('#!/bin/sh\necho "1 / 1 tests (0 skipped)"\n')
            suite.chmod(0o700)
            (self.directory / (name + '.datax')).write_text('')
        result = subprocess.run(['perl', str(ROOT / 'tests/scripts/run-test-suites.pl'),
                                 '--skip=foo.bar'], cwd=self.directory,
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('1 suites, 1 tests run, 1 suites skipped', result.stdout)


    def test_failed_size_record_preserves_previous_file(self):
        comparison = object.__new__(sizes.CodeSizeComparison)
        comparison.logger = mock.Mock()
        comparison.csv_dir = str(self.directory)
        comparison.size_common_info = sizes.CodeSizeCommonInfo('x86_64', 'size -t')
        info = sizes.CodeSizeDistinctInfo('new', 'current', 'x86_64', 'default', 'cc', '-Os')
        record = self.directory / (info.get_info_indication() + '-size.csv')
        record.write_text('previous record')
        comparison.cal_code_size = mock.Mock(return_value={})
        comparison.code_size_generator = mock.Mock()
        def fail(_revision, _data, output):
            output.write('partial record')
            output.flush()
            raise ValueError('invalid measurement')
        comparison.code_size_generator.write_record.side_effect = fail
        with self.assertRaises(ValueError):
            comparison.gen_code_size_report(info)
        self.assertEqual(record.read_text(), 'previous record')
        self.assertEqual(list(self.directory.iterdir()), [record])


    def test_size_record_filenames_round_trip(self):
        generator = sizes.CodeSizeGeneratorWithSize(logging.getLogger(__name__))
        text = ('text data bss dec hex filename\n'
                '1 2 3 6 6 a file.o (ex archive.a)\n'
                '1 2 3 6 6 TLS-TOTALS_extra.o (ex archive.a)\n'
                '2 4 6 12 c (TOTALS)\n')
        record = self.directory / 'record.txt'
        with record.open('w') as output:
            generator.write_record('old', {'TLS': text}, output)
        generator.read_size_record('new', str(record))
        self.assertEqual(set(generator.code_size['new']['TLS']),
                         {'a file.o', 'TLS-TOTALS_extra.o', 'TLS-TOTALS'})


    def test_size_tool_paths(self):
        comparison = object.__new__(sizes.CodeSizeComparison)
        comparison.logger = mock.Mock()
        for command in ('/usr/bin/size -t', 'arm-none-eabi-size -t', '"/path with spaces/size" -t'):
            common = sizes.CodeSizeCommonInfo('x86_64', command)
            comparison.size_common_info = common
            self.assertNotIn('/', common.get_info_indication())
            parser = comparison._CodeSizeComparison__generate_size_parser()
            self.assertIsInstance(parser, sizes.CodeSizeGeneratorWithSize)
