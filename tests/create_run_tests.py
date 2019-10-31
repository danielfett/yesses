import os


def create_run_tests_file():
    beginning = """import os
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
    """

    ending = """
    def tearDown(self) -> None:
        for file in os.listdir("tests/test_cases/"):
            if not file.endswith(".yml"):
                os.remove(f"tests/test_cases/{file}")
"""

    with open("tests/run_tests.py", "w") as file:
        file.writelines(beginning)

        for f in os.listdir("tests/test_cases/"):  # type: str
            parts = f.split('.')
            file.write('\n')
            file.write(f"    def test_{parts[0]}(self):\n")
            file.write(f"        self.run_test_case('{f}')\n")

        file.writelines(ending)


if __name__ == "__main__":
    create_run_tests_file()
