from typing import List, Iterator
from pydantic import BaseModel, Field

from nvdutils.models.references.reference import Reference


class References(BaseModel):
    """

    """
    elements: List[Reference] = Field(default_factory=list)

    def __iter__(self) -> Iterator[Reference]:
        return iter(self.elements)

    @property
    def tags(self):
        tags = set()

        for ref in self.references:
            tags.update(ref.tags)

        return list(tags)

    @property
    def domains(self):
        domains = set()

        for ref in self.references:
            domains.add(ref.url.host)

        return list(domains)

    def __len__(self):
        return len(self.elements)

    def __str__(self):
        return ', '.join(str(ref) for ref in self.elements)
