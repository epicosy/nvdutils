from typing import List, Iterator
from pydantic import BaseModel
from nvdutils.models.descriptions.description import Description


class Descriptions(BaseModel):
    elements: List[Description]

    def __iter__(self) -> Iterator[Description]:
        return iter(self.elements)

    def get_eng_description(self) -> Description:
        for desc in self.elements:
            if desc.lang == 'en':
                return desc

        raise ValueError('No english description')

    def has_multiple_vulnerabilities(self) -> bool:
        desc = self.get_eng_description()

        return desc.has_multiple_vulnerabilities()

    def has_multiple_components(self) -> bool:
        desc = self.get_eng_description()

        return desc.has_multiple_components()

    def is_disputed(self) -> bool:
        desc = self.get_eng_description()

        return desc.is_disputed()

    def is_unsupported(self) -> bool:
        desc = self.get_eng_description()

        return desc.is_unsupported()
