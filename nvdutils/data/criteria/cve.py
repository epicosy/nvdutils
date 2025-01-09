from typing import List
from datetime import datetime
from dataclasses import dataclass, field

from nvdutils.models.cve import CVE
from nvdutils.common.enums.cve import Status
from nvdutils.data.criteria.base import BaseCriteria, AttributeCriterion


DEFAULT_START_YEAR = 1999
DEFAULT_END_YEAR = datetime.now().year


@dataclass
class CVECriteria(BaseCriteria):
    """
        Class to store options for filtering CVEs

        Attributes:
            valid (bool): Whether to filter out invalid CVEs (not MODIFIED or ANALYZED)
            start (int): The start year for the filter
            end (int): The end year for the filter
            source_identifiers (List[str]): The source identifiers to include
    """
    name: str = 'cve_criteria'
    valid: bool = None
    start: int = DEFAULT_START_YEAR
    end: int = DEFAULT_END_YEAR
    source_identifiers: List[str] = field(default_factory=list)

    def populate(self, cve: CVE):
        self.update(
            AttributeCriterion('is_valid', self.valid, cve.status and cve.status in [Status.MODIFIED, Status.ANALYZED])
        )
        self.update(
            AttributeCriterion('has_sources', len(self.source_identifiers) > 0, cve.source in self.source_identifiers)
        )

        # TODO: account for the rest of the criteria
