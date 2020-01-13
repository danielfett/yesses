from .module import YModule
from .findingslist import FindingsList
import yaml
import logging
from contextlib import contextmanager
from datetime import datetime, timedelta
from io import StringIO as StringBuffer
from .parsers import FindParser, ExpectParser

log = logging.getLogger("step")


class Step:
    LOG_FORMATTER = logging.Formatter()
    LOG_LEVEL = logging.DEBUG
    RESERVED = ["find", "expect", "name"]

    def __init__(self, raw, number):
        self.raw = raw
        self.number = number
        self.parse_action()
        self.parse_name()
        self.parse_find()
        self.log_buffer = StringBuffer()
        self.duration = timedelta(0)

    def parse_action(self):
        """From the raw step description, find the key that describes the
        action, get the respective class for executing the action, and
        store the keywords.

        """

        words = [word for word in self.raw.keys() if word not in self.RESERVED]
        if len(words) == 0:
            raise Exception(f"No action found.")
        if len(words) > 1:
            raise Exception(f"More than one action found: {words}.")
        self.action = words[0]
        self.action_class = YModule.class_from_string(self.action)
        self.kwargs = self.raw[self.action]
        log.info(f"Step {self.number} = {self.action}")

    def parse_name(self):
        """From the raw step description, find the 'name' key and store it as
        the name for the step. If none exists, use the action as the
        name.

        """
        if "name" in self.raw:
            self.name = self.raw["name"]
        else:
            self.name = self.action

    def parse_find(self):
        if not "find" in self.raw:
            raise Exception(f"Missing keyword 'find'.")
        self.find_mapping = FindParser.parse_find_mapping(self.raw["find"])

    def get_log(self):
        return self.log_buffer.getvalue()

    def load_findings(self, findings):
        self.findings = findings
        kwargs_modified = {}
        for name, value in self.kwargs.items():
            name = name.replace(" ", "_")
            try:
                kwargs_modified[name] = findings.get_from_use_expression(value)
            except FindingsList.NotAUseExpression:
                kwargs_modified[name] = value

        self.inputs = kwargs_modified

    def execute(self):
        temp_findings = self.call_class_from_action()
        log.info(
            f"{self.action} took {self.duration.total_seconds()}s and produced {len(self.get_log())} bytes of output."
        )

        # Merge temporary findings into permanent findings
        # using alias table created in init
        for name, alias in self.find_mapping.items():
            if not name in temp_findings:
                raise Exception(f"Did not find key {name} in output {temp_findings}.")
            self.findings.set(alias, temp_findings[name])

        # Return a generator producing all alerts created by the
        # expect functions. Ideally, the ExpectParser would run when
        # initializing the whole step, but then the expect_functions
        # need to be stored somewhere so that they do not get picked
        # up by the yaml serializer (they are not serializable, and
        # there is no need to serialize them).
        expect_functions = ExpectParser.parse_expect(self.raw.get("expect", []))
        for fn in expect_functions:
            yield from fn(self)

    def call_class_from_action(self):
        try:
            with self.capture_log():
                obj = self.action_class(self, **self.inputs)

        except TypeError as e:
            raise Exception(
                f'Unable to initialize action "{self.action}": {str(e)}\n\n{self.get_definition()}'
            )

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
            self.duration += end - start

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
