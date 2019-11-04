import os
import unittest

from yesses.runner import Runner


class RunTestsBase(unittest.TestCase):

    def run_test_case(self, test_case: str):
        with open(f"tests/test_cases/{test_case}", "r") as config_file:
            runner = Runner(config_file, False)
            runner.run(None, None)
            self.assertEqual(runner.config.alertslist.alerts, [])

    def tearDown(self) -> None:
        for file in os.listdir("tests/test_cases/"):
            if not file.endswith(".yml"):
                os.remove(f"tests/test_cases/{file}")


def run():
    test_cases = {}
    for f in os.listdir("tests/test_cases/"):  # type: str
        parts = f.split('.')
        test_cases[f"test_{parts[0]}"] = lambda s: s.run_test_case(f)

    RunTests = type(
        'RunTests',
        (RunTestsBase,),
        test_cases
    )

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RunTests)
    unittest.TextTestRunner().run(suite)


def start_environment() -> int:
    # TODO start environment
    return 0


if __name__ == "__main__":
    run()
