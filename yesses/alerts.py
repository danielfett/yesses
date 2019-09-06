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

    violated_rule: str
    findings: list
    step: object
    severity: Severity = Severity.MEDIUM

    def __str__(self):
        return f"Violation of rule: {self.violated_rule}\n{self.dump_findings(self.findings)}"

    def log(self):
        logging.log(self.severity, str(self))


for level in Alert.Severity:
    logging.addLevelName(level.value, f'ALERT_{level.name}')

# needed for yaml import?
Severity = Alert.Severity
