from typing import List, Iterator
from pydantic import BaseModel, Field

from nvdutils.common.enums.weaknesses import WeaknessType
from nvdutils.models.weaknesses.weakness import Weakness


class Weaknesses(BaseModel):
    primary: List[Weakness] = Field(default_factory=list)
    secondary: List[Weakness] = Field(default_factory=list)

    def __iter__(self) -> Iterator[Weakness]:
        return iter(self.primary + self.secondary)

    def __len__(self):
        return len(self.primary + self.secondary)

    def has_primary(self) -> bool:
        return bool(self.primary)

    def has_secondary(self) -> bool:
        return bool(self.secondary)

    def get_by_source(self, source: str) -> List[Weakness]:
        return [_weakness for _weakness in self if _weakness.source == source]

    def get_by_type(self, weakness_type: WeaknessType) -> List[Weakness] | None:
        if weakness_type == WeaknessType.Primary:
            return self.primary

        if weakness_type == WeaknessType.Secondary:
            return self.secondary

        return None

    def get_by_id(self, cwe_id: str) -> List[Weakness]:
        return [_weakness for _weakness in self if _weakness.has_value(cwe_id)]

    def get(self, weakness_type: WeaknessType = None, source: str = None) -> List[Weakness]:
        """
            Get weaknesses for this CVE
            :param weakness_type: filter by weakness type
            :param source: filter by source

            :return: list of weaknesses
        """
        if not weakness_type and not source:
            return self

        if not source:
            return self.get_by_type(weakness_type)

        if not weakness_type:
            return self.get_by_source(source)

        return [_weakness for _weakness in self.get_by_source(source) if _weakness.type == weakness_type]
