from typing import Dict, Iterator
from dataclasses import dataclass, field

from nvdutils.models.cve import CVE
from nvdutils.data.collections.collection import CVECollection


@dataclass
class CVEDictionary(CVECollection):
    entries: Dict[str, CVE] = field(default_factory=dict)

    def add_entry(self, cve: CVE):
        self.entries[cve.id] = cve

    def __iter__(self) -> Iterator[CVE]:
        return iter(self.entries.values())

    def __len__(self):
        return len(self.entries)

