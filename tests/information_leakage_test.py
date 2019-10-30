from yesses.runner import Runner


def test_information_leakage():
    config_file = open("tests/test_cases/information_leakage.yml", "r")
    runner = Runner(config_file, False)
    runner.run(None, None)
    pass

