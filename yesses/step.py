from importlib import import_module
from yesses import verbs
from .findingslist import FindingsList
import re
import yaml


class Step:
    def __init__(self, raw, number):
        self.raw = raw
        self.number = number
        self.action = list(raw.keys())[0]
        self.action_module, self.action_class = self.split_action(self.action)

        self.kwargs = raw[self.action]

    def execute(self, findings):
        kwargs_modified = {}
        for name, value in self.kwargs.items():
            try:
                kwargs_modified[name] = findings.get_from_use_expression(value)
            except FindingsList.NotAUseExpression:
                kwargs_modified[name] = value

        temp_findings = self.call_class_from_action(
            **kwargs_modified
        )
        yield from verbs.execute(self, temp_findings, findings)

    def call_class_from_action(self, **kwargs):
        try:
            obj = getattr(import_module(f'yesses.{self.action_module}'), self.action_class)(
                **kwargs
            )
        except TypeError as e:
            raise Exception(f'Unable to initialize action "{self.action}": {str(e)}\n\n{self}')
        
        return obj.run()

    def has_verb(self, verb_name):
        return verb_name in self.raw

    def get_verb_args(self, verb_name):
        return self.raw[verb_name]

    def __str__(self):
        return yaml.safe_dump(self.raw)

    @staticmethod
    def split_action(action):
        verb, subj = action.split(' ', 1)
        def uc(match):
            return match.group(1).upper()
        cls = re.sub('( [a-z])', uc, subj)
        cls = cls.replace(' ', '')
        return verb, cls
