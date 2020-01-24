from importlib import import_module
from .findingslist import FindingsList
import re
import yaml


class Output:
    def __init__(self, config, raw):
        self.output_class = list(raw.keys())[0]
        self.config = config
        kwargs = raw[self.output_class]

        try:
            self.output_obj = getattr(
                import_module("yesses.outputs"), self.output_class
            )(**kwargs)
        except TypeError as e:
            raise Exception(
                f'Unable to initialize output "{self.output_class}": {str(e)}\n\n{self}'
            )

    def run(self, time):
        self.output_obj.run(
            self.config.alertslist, self.config.steps, self.config.raw_config, time
        )
