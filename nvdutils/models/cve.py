from datetime import datetime
from collections import defaultdict
from typing import Any

from pydantic import BaseModel, Field, field_validator

from nvdutils.models.metrics import Metrics
from nvdutils.models.weaknesses import Weaknesses
from nvdutils.models.references import References
from nvdutils.models.descriptions import Descriptions
from nvdutils.models.configurations import Configurations
from nvdutils.common.enums.cve import Status


class CVE(BaseModel):
    id: str
    source: str = Field(alias="sourceIdentifier")
    status: Status = Field(alias="vulnStatus")
    published_date: datetime = Field(alias="published")
    last_modified_date: datetime = Field(alias="lastModified")
    descriptions: Descriptions
    configurations: Configurations = Field(default_factory=Configurations)
    weaknesses: Weaknesses = Field(default_factory=Weaknesses)
    metrics: Metrics
    references: References

    def model_post_init(self, __context: Any) -> None:
        """
            Set the status to UNSUPPORTED/DISPUTED if the descriptions indicate that the CVE is unsupported/disputed.
        """
        if self.status in [Status.MODIFIED, Status.ANALYZED]:
            if self.descriptions.is_unsupported():
                self.status = Status.UNSUPPORTED
            elif self.descriptions.is_disputed():
                self.status = Status.DISPUTED

    @field_validator("status", mode="before")
    def parse_status(cls, value):
        """
            Parses the <vulnStatus> node into a Status object.
        """

        return Status(value)

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
