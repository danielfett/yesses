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
            return cls[text.strip().upper().replace(" ", "_")]

    violated_rule: str
    findings: list
    step: object
    severity: Severity = Severity.MEDIUM


for level in Alert.Severity:
    logging.addLevelName(level.value, f"ALERT_{level.name}")

# needed for yaml import?
Severity = Alert.Severity
