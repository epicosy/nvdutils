from datetime import datetime
from collections import defaultdict
from typing import Any, List, Iterator, Set, Union

from pydantic import BaseModel, Field, field_validator

from nvdutils.models.metrics import Metrics
from nvdutils.models.weaknesses import Weaknesses
from nvdutils.models.references import References
from nvdutils.models.descriptions import Descriptions
from nvdutils.models.configurations import Configurations
from nvdutils.common.enums.cve import Status, CVETagType


class CVETag(BaseModel):
    source: str = Field(alias="sourceIdentifier")
    tags: List[CVETagType] = Field(default_factory=list)


class CVETags(BaseModel):
    elements: List[CVETag] = Field(default_factory=list)

    def __iter__(self) -> Iterator[CVETag]:
        return iter(self.elements)

    def unique(self, values: bool = False) -> Set[Union[CVETagType, str]]:
        """
            values: whether to return the values or the tags
        """
        return {tag.value if values else tag for el in self.elements for tag in el.tags}


class CVE(BaseModel):
    id: str
    source: str = Field(alias="sourceIdentifier")
    status: Status = Field(alias="vulnStatus")
    tags: CVETags = Field(alias="cveTags")
    published_date: datetime = Field(alias="published")
    last_modified_date: datetime = Field(alias="lastModified")
    descriptions: Descriptions
    configurations: Configurations = Field(default_factory=Configurations)
    weaknesses: Weaknesses = Field(default_factory=Weaknesses)
    metrics: Metrics
    references: References

    @field_validator("status", mode="before")
    def parse_status(cls, value):
        """
            Parses the <vulnStatus> node into a Status object.
        """

        return Status(value)

    @field_validator("tags", mode="before")
    def parse_tags(cls, values):
        """
            Encapsulates the <tags> node into a CVETags object.
        """

        return {
                'elements': values
        }

    @field_validator("descriptions", mode="before")
    def parse_descriptions(cls, values):
        """
            Encapsulates the <descriptions> node into a Descriptions object.
        """

        return {
                'elements': values
        }

    @field_validator("configurations", mode="before")
    def parse_configurations(cls, values):
        """
            Encapsulates the <configurations> node into a Configurations object.
        """

        return {
                'elements': values
        }

    @field_validator("weaknesses", mode="before")
    def parse_weaknesses(cls, values):
        """
            Encapsulates the <weaknesses> node into a Weaknesses object.
        """

        parsed = defaultdict(list)

        for el in values:
            parsed[el['type'].lower()].append(el)

        return parsed

    @field_validator("metrics", mode="before")
    def parse_metrics(cls, values):
        """
            Converts cvssMetricV30 and cvssMetricV31 keys to cvssMetricV3.
        """

        if 'cvssMetricV30' in values:
            values['cvssMetricV3'] = values.pop('cvssMetricV30')
        if 'cvssMetricV31' in values:
            values['cvssMetricV3'] = values.pop('cvssMetricV31')

        return values

    @field_validator("references", mode="before")
    def parse_references(cls, values):
        """
            Encapsulates the <references> node into a References object.
        """

        return {
                'elements': values
        }

    def has_status(self):
        return self.status is not None
