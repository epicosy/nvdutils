from typing import Iterator
from dataclasses import dataclass, field

from nvdutils.models.cve import CVE

from nvdutils.data.criteria.cve import CVECriteria
from nvdutils.data.criteria.base import BaseCriteria
from nvdutils.data.criteria.metrics import MetricsCriteria
from nvdutils.data.criteria.weaknesses import WeaknessesCriteria
from nvdutils.data.criteria.descriptions import DescriptionsCriteria
from nvdutils.data.criteria.configurations import ConfigurationsCriteria


@dataclass
class BaseProfile:
    """
        Class to store criteria for selecting CVEs

        Attributes:
            cve_criteria (CVECriteria): The criteria for filtering CVEs
            configuration_criteria (ConfigurationsCriteria): The criteria for filtering configurations
            description_criteria (DescriptionsCriteria): The criteria for filtering descriptions
            metrics_criteria (MetricsCriteria): The criteria for filtering metrics
            weakness_criteria (WeaknessesCriteria): The criteria for filtering weaknesses
    """
    cve_criteria: CVECriteria = field(default=None)
    configuration_criteria: ConfigurationsCriteria = field(default=None)
    description_criteria: DescriptionsCriteria = field(default=None)
    metrics_criteria: MetricsCriteria = field(default=None)
    weakness_criteria: WeaknessesCriteria = field(default=None)

    def __iter__(self) -> Iterator[BaseCriteria]:
        # Return all attributes that are not None and are instances of BaseCriteria
        return iter(filter(lambda x: x is not None and isinstance(x, BaseCriteria), self.__dict__.values()))

    def __call__(self, cve: CVE) -> bool:
        outcomes = []

        for criteria in self:
            criteria.populate(cve)
            outcomes.append(criteria())

        return all(outcomes) if outcomes else True

    def to_dict(self):
        return {
            v.name: v.to_dict() for v in self
        }
