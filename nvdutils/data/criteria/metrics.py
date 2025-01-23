from dataclasses import dataclass

from nvdutils.models.cve import CVE
from nvdutils.common.enums.metrics import CVSSVersion
from nvdutils.models.metrics.impact import ImpactMetrics
from nvdutils.models.metrics.cvss import CVSS, CVSSv2, CVSSv3
from nvdutils.data.criteria.base import BaseCriteria, AttributeCriterion


@dataclass
class ImpactMetricsCriteria(BaseCriteria):
    """
        Class for filtering impact metrics

        Attributes:
            confidentiality (str): The confidentiality impact to include
            integrity (str): The integrity impact to include
            availability (str): The availability impact
    """
    confidentiality: str = None
    integrity: str = None
    availability: str = None

    def populate(self, impact_metrics: ImpactMetrics):
        self.update(
            AttributeCriterion(
                'confidentiality_impact',
                self.confidentiality is not None,
                impact_metrics.confidentiality == self.integrity
            )
        )

        self.update(
            AttributeCriterion(
                'integrity_impact',
                self.integrity is not None,
                impact_metrics.integrity == self.integrity
            )
        )

        self.update(
            AttributeCriterion(
                'availability_impact',
                self.availability is not None,
                impact_metrics.availability == self.availability
            )
        )


@dataclass
class CVSSCriteria(BaseCriteria):
    """
        Base class for storing criteria for CVSS attributes

        Attributes:
            version (CVSSVersion): The CVSS version to select
            impact_metrics (ImpactMetricsCriteria): The impact metrics criteria to apply
    """
    name: str = 'CVSS_criteria'
    version: CVSSVersion = None
    impact_metrics: ImpactMetricsCriteria = None

    def populate(self, cvss: CVSS):
        if self.impact_metrics:
            self.impact_metrics.populate(cvss.impact_metrics)
            self.update(self.impact_metrics)


@dataclass
class CVSSv2Criteria(CVSSCriteria):
    """
        Class for storing criteria for CVSS v2 attributes

        Attributes:
            access_vector (str): The access vector to include
            access_complexity (str): The access complexity to include
            authentication (str): The authentication to include
            ac_insuf_info (bool): Whether to include insufficient information access complexity
            obtain_all_privilege (bool): Whether to include obtain all privilege
            obtain_user_privilege (bool): Whether to include obtain user privilege
            obtain_other_privilege (bool): Whether to include obtain other privilege
            user_interaction_required (bool): Whether to include user interaction required
    """
    name = 'CVSS_v2_criteria'
    version: CVSSVersion = CVSSVersion.v2_0
    access_vector: str = None
    access_complexity: str = None
    authentication: str = None
    ac_insuf_info: bool = None
    obtain_all_privilege: bool = None
    obtain_user_privilege: bool = None
    obtain_other_privilege: bool = None
    user_interaction_required: bool = None

    def populate(self, cvss: CVSSv2):
        # TODO: too long and complex, can be simplified
        super().populate(cvss)

        self.update(
            AttributeCriterion(
                'v2_access_vector',
                self.access_vector is not None,
                cvss.access_vector == self.access_vector
            )
        )

        self.update(
            AttributeCriterion(
                'v2_access_complexity',
                self.access_complexity is not None,
                cvss.access_complexity == self.access_complexity
            )
        )

        self.update(
            AttributeCriterion(
                'v2_authentication',
                self.authentication is not None,
                cvss.authentication == self.authentication
            )
        )

        self.update(
            AttributeCriterion(
                'v2_ac_insuf_info',
                self.ac_insuf_info is not None,
                cvss.ac_insuf_info == self.ac_insuf_info
            )
        )

        self.update(
            AttributeCriterion(
                'v2_obtain_all_privilege',
                self.obtain_all_privilege is not None,
                cvss.obtain_all_privilege == self.obtain_all_privilege
            )
        )

        self.update(
            AttributeCriterion(
                'v2_obtain_user_privilege',
                self.obtain_user_privilege is not None,
                cvss.obtain_user_privilege == self.obtain_user_privilege
            )
        )

        self.update(
            AttributeCriterion(
                'v2_obtain_other_privilege',
                self.obtain_other_privilege is not None,
                cvss.obtain_other_privilege == self.obtain_other_privilege
            )
        )

        self.update(
            AttributeCriterion(
                'v2_user_interaction_required',
                self.user_interaction_required is not None,
                cvss.user_interaction_required == self.user_interaction_required
            )
        )


@dataclass
class CVSSv3Criteria(CVSSCriteria):
    """
        Class for storing criteria for CVSS v3 attributes

        Attributes:
            attack_vector (str): The attack vector to include
            attack_complexity (str): The attack complexity to include
            privileges_required (str): The privileges required to include
            user_interaction (str): The user interaction to include
            scope (str): The scope to include
    """
    name = 'CVSS_v3_criteria'
    version: CVSSVersion = CVSSVersion.v3
    attack_vector: str = None
    attack_complexity: str = None
    privileges_required: str = None
    user_interaction: str = None
    scope: str = None

    def populate(self, cvss: CVSSv3):
        super().populate(cvss)

        self.update(
            AttributeCriterion(
                'v3_attack_vector',
                self.attack_vector is not None,
                cvss.attack_vector == self.attack_vector
            )
        )

        self.update(
            AttributeCriterion(
                'v3_attack_complexity',
                self.attack_complexity is not None,
                cvss.attack_complexity == self.attack_complexity
            )
        )

        self.update(
            AttributeCriterion(
                'v3_privileges_required',
                self.privileges_required is not None,
                cvss.privileges_required == self.privileges_required
            )
        )

        self.update(
            AttributeCriterion(
                'v3_user_interaction',
                self.user_interaction is not None,
                cvss.user_interaction == self.user_interaction
            )
        )

        self.update(AttributeCriterion('v3_scope', self.scope is not None, cvss.scope == self.scope))


@dataclass
class MetricsCriteria(BaseCriteria):
    """
        Class to store criteria for Metrics attributes

        Attributes:
            cvss: CVSSCriteria: The CVSS criteria to apply
    """
    name: str = 'metrics_criteria'
    cvss: CVSSCriteria = None

    def populate(self, cve: CVE):
        # TODO: consider multiple CVSS versions
        if self.cvss is not None:
            cvss_list = cve.metrics.get_by_version(self.cvss.version)

            if cvss_list:
                # TODO: decide which cvss to use when there are multiple
                cvss = cvss_list[0]
                self.cvss.populate(cvss)
                self.update(self.cvss)
        else:
            self.update(AttributeCriterion('has_metrics', True, len(cve.metrics) > 0))
