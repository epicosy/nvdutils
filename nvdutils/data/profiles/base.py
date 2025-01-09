from typing import Iterator
from dataclasses import dataclass

from nvdutils.models.cve import CVE
from nvdutils.data.criteria.cve import CVECriteria
from nvdutils.data.criteria.base import BaseCriteria
from nvdutils.data.criteria.metrics import MetricsCriteria
from nvdutils.data.criteria.weaknesses import WeaknessesCriteria
from nvdutils.data.criteria.descriptions import DescriptionsCriteria
from nvdutils.data.criteria.configurations import ConfigurationsCriteria


@dataclass
class BaseProfile:
    cve_criteria: CVECriteria = CVECriteria(valid=True)
    configuration_criteria: ConfigurationsCriteria = ConfigurationsCriteria(is_single=True)
    description_criteria: DescriptionsCriteria = None
    metrics_criteria: MetricsCriteria = None
    weakness_criteria: WeaknessesCriteria = None

    def __iter__(self) -> Iterator[BaseCriteria]:
        # Return all attributes that are not None and are instances of BaseCriteria
        return iter(filter(lambda x: x is not None and isinstance(x, BaseCriteria), self.__dict__.values()))

    @property
    def time_range(self):
        return range(self.cve_criteria.start, self.cve_criteria.end + 1)

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
