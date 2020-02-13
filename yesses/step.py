from .module import YModule
from .findingslist import FindingsList
import yaml
import logging
from contextlib import contextmanager
from datetime import datetime, timedelta
from io import StringIO as StringBuffer
from .parsers import FindParser, ExpectParser, UseParser
from dataclasses import dataclass


log = logging.getLogger("step")


@dataclass
class StepInput:
    required_keys: list


@dataclass
class LiteralStepInput(StepInput):
    data: object

    def check_has_keys(self, _):
        if self.required_keys is None:
            return
        else:
            if not isinstance(self.data, list):
                raise Exception(
                    f"Expected input to be a list, but it is {type(self.data)}"
                )
            required_keys = set(self.required_keys)
            for element in self.data:
                if not isinstance(element, dict):
                    raise Exception(
                        f"Expected input to be a dictionary, but it is {type(element)}"
                    )
                provided_keys = set(element.keys())
                if not required_keys.issubset(provided_keys):
                    missing_keys = required_keys - provided_keys
                    raise Exception(
                        f"Provided input is missing the key(s): {', '.join(missing_keys)}"
                    )

    def resolve(self, _):
        return self.data


@dataclass
class GlobalFindingsStepInput(StepInput):
    findingskeys: list

    def check_has_keys(self, provided_keys_in_global_findingslist):
        required_keys = set(self.required_keys)
        for key in self.findingskeys:
            if not key in provided_keys_in_global_findingslist:
                raise Exception(
                    f"No input with name '{key}' exists. Valid input keys existing at that point in the run: {', '.join(provided_keys_in_global_findingslist.keys())}"
                )
            provided_keys = set(provided_keys_in_global_findingslist[key])
            if not required_keys.issubset(provided_keys):
                missing_keys = required_keys - provided_keys
                raise Exception(
                    f"Input is missing the key(s): {', '.join(missing_keys)}"
                )

    def resolve(self, findingslist):
        all_entries = []
        for key in self.findingskeys:
            for entry in findingslist.get(key):
                if not entry in all_entries:
                    all_entries.append(entry)
        return all_entries


@dataclass
class StepOutput:
    name: str
    alias: str
    provided_keys: list


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
        self.parse_expect()
        self.parse_inputs()
        self.log_buffer = StringBuffer()
        self.duration = timedelta(0)
        self.output_data = None

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
            self.name = f"{self.raw['name']} ({self.action})"
        else:
            self.name = self.action

    def parse_find(self):
        if not "find" in self.raw:
            raise Exception(f"Missing keyword 'find'.")
        self.outputs = []
        for name, alias in FindParser.parse_find_mapping(self.raw["find"]).items():
            output_field, properties = self.action_class.find_matching_output_field(
                name
            )
            self.outputs.append(
                StepOutput(
                    name=name, alias=alias, provided_keys=properties["provided_keys"]
                )
            )

    def parse_expect(self):
        """This is a hack. The parser should be run here, but the results need
        to be stored. We do not store the results as of now, since
        that breaks YAML serialization. Instead, we run the parser
        twice (see execute()).

        """
        functions = ExpectParser.parse_expect(self.raw.get("expect", []))

        # store for each rule the required keys
        self.required_fields_for_expect = []
        for function in functions:
            self.required_fields_for_expect.append(
                (function.rule, function.required_fields)
            )

    def validate_expect(self, provided_keys_in_global_findingslist):
        for rule, required_fields in self.required_fields_for_expect:
            for required_field in required_fields:
                if required_field in provided_keys_in_global_findingslist:
                    break
                for output in self.outputs:
                    if output.alias == required_field:
                        break
                else:
                    raise Exception(
                        f"Rule '{rule}' requires output '{required_field}', which does not exist at this point in the run."
                    )

    def parse_inputs(self):
        """Inputs to the step can be defined literally (by providing the data
        itself) or with the 'use' keyword to pull in results from the
        global findings dictionary. This function converts the keyword
        arguments provided to the step into a class that either
        contains the literal data or the list of keys to pull from the
        global findings list. After all steps have completed this
        conversion, it can be checked if the data required to execute
        each step is actually provided by previous steps.

        """

        self.inputs = {}

        for name, value in self.kwargs.items():
            name = name.replace(" ", "_")

            if not name in self.action_class.INPUTS:
                raise Exception(f"Unknown input name: '{name}' for step {self}")
            required_keys = self.action_class.INPUTS[name]["required_keys"]

            if type(value) is not str or not value.startswith("use "):
                self.inputs[name] = LiteralStepInput(
                    data=value, required_keys=required_keys
                )
                continue

            keys = [group.key for group in UseParser.parse(value)]
            self.inputs[name] = GlobalFindingsStepInput(
                findingskeys=keys, required_keys=required_keys
            )

    def get_log(self):
        return self.log_buffer.getvalue()

    def load_findings(self, findings):
        self.findings = findings
        self.input_resolved = {
            k: v.resolve(self.findings) for k, v in self.inputs.items()
        }

    def execute(self):
        temp_findings = self.call_class_from_action()
        log.info(
            f"{self.action} took {self.duration.total_seconds()}s and produced {len(self.get_log())} bytes of output."
        )

        # Merge temporary findings into permanent findings
        # using alias table created in init
        self.output_data = {}
        for output in self.outputs:
            self.output_data[output.alias] = temp_findings[output.name]

        self.findings.update(self.output_data)

        # Return a generator producing all alerts created by the
        # expect functions. Ideally, the ExpectParser would *only* run
        # when initializing the whole step, but then the
        # expect_functions need to be stored somewhere so that they do
        # not get picked up by the yaml serializer (they are not
        # serializable, and there is no need to serialize them).
        # Therefore, the parser is run twice.
        expect_functions = ExpectParser.parse_expect(self.raw.get("expect", []))
        for fn in expect_functions:
            yield from fn(self)

    def call_class_from_action(self):
        try:
            with self.capture_log():
                obj = self.action_class(self, **self.input_resolved,)

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
        return yaml.safe_dump(self.raw, default_flow_style=False, default_style="")

    def get_inputs(self):
        return yaml.safe_dump(
            self.input_resolved, default_flow_style=False, default_style=""
        )

    def get_outputs(self):
        return yaml.safe_dump(
            self.output_data, default_flow_style=False, default_style=""
        )
