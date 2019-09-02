from dataclasses import dataclass
from enum import Enum


@dataclass
class SecMessage:
    severity = Severity.MEDIUM
    message: str
    place: str
    
