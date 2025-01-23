
from dataclasses import dataclass, field

from nvdutils.data.profiles.basic import BasicProfile
from nvdutils.data.criteria.metrics import MetricsCriteria, CVSSv3Criteria


remote_zero_click_cvss = CVSSv3Criteria(
    attack_vector='NETWORK',
    attack_complexity='LOW',
    privileges_required='NONE',
    user_interaction='NONE',
)


@dataclass
class ZeroClickProfile(BasicProfile):
    """
        Profile for selecting CVEs that may be exploited without user interaction.
    """
    metrics_criteria: MetricsCriteria = field(
        default_factory=lambda: MetricsCriteria(
            cvss=remote_zero_click_cvss
        )
    )
