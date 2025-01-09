from dataclasses import dataclass

from nvdutils.models.cve import CVE
from nvdutils.data.criteria.base import BaseCriteria, AttributeCriterion


@dataclass
class DescriptionsCriteria(BaseCriteria):
    """
        Class to store criteria for Description attributes

        Attributes:
            is_single_vuln (bool): Whether to filter out CVEs with multiple vulnerabilities
            is_single_component (bool): Whether to filter out CVEs with multiple components
    """
    name: str = 'description_criteria'
    is_single_vuln: bool = False
    is_single_component: bool = False

    def populate(self, cve: CVE):
        self.update(
            AttributeCriterion(
                'is_single_vuln',
                self.is_single_vuln,
                not cve.descriptions.has_multiple_vulnerabilities()
            )
        )
        self.update(
            AttributeCriterion(
                'is_single_component',
                self.is_single_component,
                not cve.descriptions.has_multiple_components()
            )
        )
        # TODO: account for strings like "Not vulnerable" in vendorComments
