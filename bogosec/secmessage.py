from dataclasses import dataclass
from enum import Enum

class Severity(Enum):
    INFORMATIVE = 0
    MEDIUM = 1
    HIGH = 2
    VERY_HIGH = 3

@dataclass
class SecMessage:
    severity = Severity.MEDIUM
    message: str
    place: str
    
