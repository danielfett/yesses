from .config import Config
from .state import State
from .findingslist import FindingsList
from .alertslist import AlertsList
from .step import Step
from .runner import Runner

categories = ['scan', 'discover']

def all_modules():
    all_modules = {}

    import importlib
    import inspect
    for m in categories:
        module = importlib.import_module(f"yesses.{m}")
        classes = list(member[1] for member in inspect.getmembers(module) if type(member[1]) == type)
        all_modules[m] = classes

    return all_modules
