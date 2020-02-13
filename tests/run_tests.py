from typing import Optional
import os
import sys
import subprocess
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
        if f.endswith(".yml"):
            parts = f.split(".")
            name = parts[0].replace("-", "_")

            def run_test_case(self, test=f):
                self.run_test_case(test)

            test_cases[f"test_{name}"] = run_test_case

    RunTests = type("RunTests", (RunTestsBase,), test_cases)

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RunTests)
    test_runner = unittest.TextTestRunner().run(suite)
    if len(test_runner.errors) > 0:
        sys.exit(-1)
    sys.exit(
        len(test_runner.failures)
    )  # Returns the number of failed tests as status code


def start_environment(build_option: Optional[str] = "") -> int:
    return_status = subprocess.call(
        "cd tests/certificates && bash create_certs.sh", shell=True
    )
    if return_status != 0:
        sys.exit("Could not create certificates!")
    subprocess.call(
        f"docker-compose -f tests/docker-compose.yml build {build_option}", shell=True
    )
    return_status = subprocess.call(
        "docker-compose -f tests/docker-compose.yml run test_container", shell=True
    )
    subprocess.call("docker-compose -f tests/docker-compose.yml down", shell=True)
    return return_status


if __name__ == "__main__":
    run()
