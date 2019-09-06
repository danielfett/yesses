from importlib import import_module
from yesses import verbs
from .findingslist import FindingsList
import re
import yaml


class Output:
    def __init__(self, raw):
        self.output_class = list(raw.keys())[0]
        kwargs = raw[self.output_class]
        
        try:
            self.output_obj = getattr(import_module('yesses.outputs'), self.output_class)(
                **kwargs
            )
        except TypeError as e:
            raise Exception(f'Unable to initialize output "{self.output_class}": {str(e)}\n\n{self}')

    def run(self, alertslist):
        self.output_obj.run(alertslist)
