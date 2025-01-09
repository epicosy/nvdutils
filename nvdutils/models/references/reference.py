from typing import List

from pydantic import BaseModel, Field, field_validator, AnyUrl
from nvdutils.common.enums.cve import TagType


class Reference(BaseModel):
    url: AnyUrl
    source: str
    tags: List[TagType] = Field(default_factory=list)

    @field_validator('tags', mode='before')
    def map_tags(cls, tags):
        if isinstance(tags, list):
            try:
                return [TagType[tag.replace(" ", "").replace("/", "")] for tag in tags]
            except KeyError as e:
                raise ValueError(f"Invalid tag: {e.args[0]}") from e
        return tags

    def has_patch_tag(self):
        return TagType.Patch in self.tags

    def to_dict(self):
        tags_list = [tag.name for tag in self.tags]

        return {
            "url": self.url,
            "source": self.source,
            "tags": tags_list,
        }

    def __str__(self):
        tags_str = ', '.join([tag.name for tag in self.tags])
        return f"{self.source}: {self.url} ({tags_str})"
