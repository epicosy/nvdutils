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
            is_single_sentence (bool): Whether to filter out CVEs with multiple sentences
    """
    name: str = 'description_criteria'
    is_single_vuln: bool = False
    is_single_component: bool = False
    is_single_sentence: bool = False

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
        self.update(
            AttributeCriterion(
                'is_single_sentence',
                self.is_single_sentence,
                not cve.descriptions.is_multi_sentence()
            )
        )
        # TODO: account for strings like "Not vulnerable" in vendorComments
