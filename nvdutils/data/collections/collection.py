from typing import Iterator
from abc import ABC, abstractmethod
from dataclasses import dataclass

from nvdutils.models.cve import CVE


@dataclass
class CVECollection(ABC):
    @abstractmethod
    def add_entry(self, cve: CVE):
        pass

    @abstractmethod
    def __iter__(self) -> Iterator[CVE]:
        pass

    @abstractmethod
    def __len__(self):
        pass
