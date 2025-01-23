from cpelib.types.cpe import CPEPart
from dataclasses import dataclass, field

from nvdutils.data.profiles.basic import BasicProfile
from nvdutils.data.criteria.configurations import AffectedProductCriteria, ConfigurationsCriteria


@dataclass
class SingleApplication(BasicProfile):
    """
        Profile for selecting CVEs that affect only a product that is an application.
    """
    configuration_criteria: ConfigurationsCriteria = field(
        default_factory=lambda: ConfigurationsCriteria(
            affected_products=AffectedProductCriteria(
                part=CPEPart.Application,
                is_single=True
            )
        )
    )
