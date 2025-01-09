from typing import Dict, Iterator
from dataclasses import dataclass, field

from nvdutils.models.cve import CVE
from nvdutils.data.collections.collection import CVECollection
from nvdutils.data.collections.dictionaries.dictionary import CVEDictionary


@dataclass
class CVEYearlyDictionary(CVECollection):
    entries: Dict[str, CVEDictionary] = field(default_factory=dict)

    def __iter__(self) -> Iterator[CVE]:
        for cve_dict in self.entries.values():
            for cve in cve_dict:
                yield cve

    def __len__(self):
        return sum([len(cve_dict) for cve_dict in self.entries.values()])

    def add_entry(self, cve: CVE):
        year = cve.id.split("-")[1]

        if year not in self.entries:
            self.entries[year] = CVEDictionary()

        self.entries[year].add_entry(cve)

    """
    def __str__(self):
        df = pd.DataFrame([stats.to_dict() for stats in self.stats.values()])
        return df.to_string(index=False)
    """
