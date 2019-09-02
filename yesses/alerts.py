from dataclasses import dataclass
from enum import Enum
import logging

@dataclass
class Alert:
    # Severity enum corresponds to python log levels
    class Severity(Enum):
        INFORMATIVE = 31
        MEDIUM = 41
        HIGH = 51
        VERY_HIGH = 52

        @classmethod
        def parse(cls, text):
            return cls[text.strip().upper().replace(' ', '_')]

    severity = Severity.MEDIUM
    violated_rule: str
    findings: list
    step: object

    def __str__(self):
        return f"Violation of rule: {self.violated_rule}\n{self.dump_findings(self.findings)}"

    def log(self):
        logging.log(self.severity, str(self))

    @staticmethod
    def dump_findings(findings):
        def tuple_to_list(inp):
            if isinstance(inp, tuple) or isinstance(inp, set):
                inp = list(inp)
            if isinstance(inp, list):
                inp = list(map(tuple_to_list, inp))
            if isinstance(inp, dict):
                inp = {k:tuple_to_list(v) for k, v in inp.items()}
            return inp
        
        return dump(tuple_to_list(findings), default_flow_style=False)


for level in Alert.Severity:
    logging.addLevelName(level.value, f'ALERT_{level.name}')
