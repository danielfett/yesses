import os
import unittest

from yesses.runner import Runner


class RunTests(unittest.TestCase):
    # Don't change this file. It is automatically created
    # by create_run_tests.py.

    def run_test_case(self, test_case: str):
        with open(f"tests/test_cases/{test_case}", "r") as config_file:
            runner = Runner(config_file, False)
            runner.run(None, None)
            self.assertEqual(runner.config.alertslist.alerts, [])
    
    def test_information_leakage(self):
        self.run_test_case('information_leakage.yml')

    def test_hidden_paths(self):
        self.run_test_case('hidden_paths.yml')

    def test_apache2_full(self):
        self.run_test_case('apache2_full.yml')

    def test_linked_paths(self):
        self.run_test_case('linked_paths.yml')

    def tearDown(self) -> None:
        for file in os.listdir("tests/test_cases/"):
            if not file.endswith(".yml"):
                os.remove(f"tests/test_cases/{file}")
