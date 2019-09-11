from importlib import import_module
from yesses import verbs
from .findingslist import FindingsList
import re
import yaml
import logging
from contextlib import contextmanager
from datetime import datetime, timedelta
from io import StringIO as StringBuffer


log = logging.getLogger('step')

class Step:
    LOG_FORMATTER = logging.Formatter()
    LOG_LEVEL = logging.DEBUG
    
    def __init__(self, raw, number):
        self.raw = raw
        self.number = number
        self.action = list(raw.keys())[0]
        self.action_module, self.action_class = self.split_action(self.action)

        self.log_buffer = StringBuffer()
        self.duration = timedelta(0)

        self.kwargs = raw[self.action]

        log.info(f"Step {number} = {self.action}")

    def get_log(self):
        return self.log_buffer.getvalue()

    def execute(self, findings):
        kwargs_modified = {}
        for name, value in self.kwargs.items():
            name = name.replace(' ', '_')
            try:
                kwargs_modified[name] = findings.get_from_use_expression(value)
            except FindingsList.NotAUseExpression:
                kwargs_modified[name] = value

        self.inputs = kwargs_modified

        temp_findings = self.call_class_from_action()
        log.info(f"{self.action} took {self.duration.total_seconds()}s and produced {len(self.get_log())} bytes of output.")
        yield from verbs.execute(self, temp_findings, findings)

    def call_class_from_action(self):
        try:
            with self.capture_log():
                obj = getattr(import_module(f'yesses.{self.action_module}'), self.action_class)(
                    self,
                    **self.inputs
                )
            
        except TypeError as e:
            raise Exception(f'Unable to initialize action "{self.action}": {str(e)}\n\n{self.get_definition()}') 

        with self.capture_log():
            return obj.run_module()

    @contextmanager
    def capture_log(self):
        log_handler = logging.StreamHandler(self.log_buffer)
        log_handler.setFormatter(self.LOG_FORMATTER)
        log_handler.setLevel(self.LOG_LEVEL)
        logger = logging.getLogger()
        logger.addHandler(log_handler)
        start = datetime.now()
        try:
            yield
        finally:
            end = datetime.now()
            logger.removeHandler(log_handler)
            self.duration += (end - start)


    def has_verb(self, verb_name):
        return verb_name in self.raw

    def get_verb_args(self, verb_name):
        return self.raw[verb_name]

    def __str__(self):
        return f"Step #{self.number}: {self.action}"
    
    def get_definition(self):
        return yaml.safe_dump(self.raw)

    def get_inputs(self):
        return yaml.safe_dump(self.inputs)

    @staticmethod
    def split_action(action):
        verb, subj = action.split(' ', 1)
        def uc(match):
            return match.group(1).upper()
        cls = re.sub('( [a-z])', uc, subj)
        cls = cls.replace(' ', '')
        return verb, cls
