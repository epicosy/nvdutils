from typing import List
from pydantic import BaseModel, field_validator

from nvdutils.common.enums.weaknesses import WeaknessType


# TODO: this class should be moved to a separate file
class WeaknessDescription(BaseModel):
    lang: str
    value: str

    @property
    def id(self) -> int:
        """
            :return: the numeric value of the CWE ID
        """
        return int(self.value.split('-')[-1])


class Weakness(BaseModel):
    source: str
    type: WeaknessType
    description: List[WeaknessDescription]

    @field_validator("description", mode="before")
    def validate_description(cls, values):
        """
            Validate the value of the description
        """

        if not isinstance(values, list):
            raise ValueError("Description must be a list.")

        # TODO: these descriptions are skipped for now, should be handled in the future
        return [
            value for value in values
            if value["value"] not in ['NVD-CWE-noinfo', 'NVD-CWE-Other']
        ]

    @field_validator("type", mode="before")
    def map_type(cls, value):
        if not value:
            raise ValueError("Missing weakness type")

        return WeaknessType[value]

    def has_value(self, value: str) -> bool:
        # If True for any descriptions, then the weakness is a/the CWE ID
        return any([desc.value == value for desc in self.description])

    @property
    def ids(self) -> List[int]:
        """
            :return: the numeric value of all CWE IDs
        """
        return [desc.id for desc in self.description if desc.value]

    @property
    def is_single(self) -> bool:
        """
            :return: True if the weakness has only one CWE ID
        """
        return len(self.ids) == 1

    def __len__(self):
        return len(self.description)
