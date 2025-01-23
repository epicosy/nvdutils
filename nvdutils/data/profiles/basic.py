from dataclasses import dataclass, field

from nvdutils.data.criteria.cve import CVECriteria
from nvdutils.data.profiles.base import BaseProfile
from nvdutils.data.criteria.metrics import MetricsCriteria
from nvdutils.data.criteria.weaknesses import WeaknessesCriteria
from nvdutils.data.criteria.configurations import ConfigurationsCriteria


@dataclass
class BasicProfile(BaseProfile):
    """
        Profile for selecting CVEs that are valid and have the expected metadata fields.
    """
    cve_criteria: CVECriteria = field(default_factory=lambda: CVECriteria(valid=True))
    metrics_criteria: MetricsCriteria = field(default_factory=MetricsCriteria)
    weakness_criteria: WeaknessesCriteria = field(default_factory=WeaknessesCriteria)
    configuration_criteria: ConfigurationsCriteria = field(default_factory=ConfigurationsCriteria)
