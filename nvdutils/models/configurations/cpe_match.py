from pydantic import BaseModel, Field, field_validator

from cpelib.types.cpe import CPE
from cpelib.types.item import cpe_parser


class CPEMatch(BaseModel):
    criteria_id: str = Field(alias="matchCriteriaId")
    criteria: str
    vulnerable: bool
    cpe: CPE = Field(alias="criteria")
    version_start_including: str = None
    version_start_excluding: str = None
    version_end_including: str = None
    version_end_excluding: str = None

    @field_validator("cpe", mode="before")
    def parse_cpe(cls, value):
        """
        Automatically extract cpe from `criteria` after initialization.
        """
        cpe_dict = cpe_parser.parser(value)

        return CPE(**cpe_dict)
