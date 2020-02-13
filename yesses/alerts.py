from dataclasses import dataclass
from enum import Enum
import logging


class AlertSeverity(Enum):
    INFORMATIVE = 31
    MEDIUM = 41
    HIGH = 51
    VERY_HIGH = 52

    @classmethod
    def parse(cls, text):
        return cls[text.strip().upper().replace(" ", "_")]


@dataclass
class Alert:
    # Severity enum corresponds to python log levels

    violated_rule: str
    findings: list
    step: object
    severity: AlertSeverity = AlertSeverity.MEDIUM


for level in AlertSeverity:
    logging.addLevelName(level.value, f"ALERT_{level.name}")
