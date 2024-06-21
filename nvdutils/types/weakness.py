from enum import Enum
from typing import List
from dataclasses import dataclass


class WeaknessType(Enum):
    Primary = 1
    Secondary = 2


@dataclass
class WeaknessDescription:
    lang: str
    value: str

    def is_cwe_id(self, value: str = None) -> bool:
        if value:
            return self.value == value

        return self.value not in ['NVD-CWE-noinfo', 'NVD-CWE-Other']

    def __str__(self):
        return f"{self.lang}: {self.value}"


@dataclass
class Weakness:
    source: str
    type: WeaknessType
    description: List[WeaknessDescription]

    def is_single(self) -> bool:
        return len(self.description) == 1

    def is_cwe_id(self, value: str = None) -> bool:
        # If True for any descriptions, then the weakness is a/the CWE ID
        return any(desc.is_cwe_id(value) for desc in self.description)

    def __len__(self):
        return len(self.description)

    def __str__(self):
        return f"{self.source}: {', '.join(str(desc) for desc in self.description)}"
