from typing import List
from dataclasses import dataclass

from nvdutils.models.cve import CVE
from nvdutils.models import Weaknesses
from nvdutils.models.weaknesses.weakness import Weakness
from nvdutils.common.enums.weaknesses import WeaknessType
from nvdutils.data.criteria.base import BaseCriteria, AttributeCriterion


@dataclass
class CWECriteria(BaseCriteria):
    """
        Class to store criteria for CWEs attributes.
    """
    cwe_id: str = None
    is_single: bool = False

    def populate(self, weaknesses: List[Weakness] | Weaknesses):
        """
            This checks if there are any CWEs in the list of weaknesses (either specified or not).
            It also checks if the weaknesses are single CWEs if the option is enabled.
        """

        if self.cwe_id:
            weaknesses = [weakness for weakness in weaknesses if weakness.has_value(self.cwe_id)]
            self.update(AttributeCriterion('has_cwe_id', True, len(weaknesses) > 0))
        else:
            weaknesses = [weakness for weakness in weaknesses if len(weakness.ids) > 0]
            self.update(AttributeCriterion('has_cwe', True, len(weaknesses) > 0))

        if self.is_single and len(weaknesses) > 0:
            # Only one should be necessary to be single CWE for the check
            self.update(AttributeCriterion('is_single', True, any([weakness.is_single for weakness in weaknesses])))


@dataclass
class WeaknessesCriteria(BaseCriteria):
    """
        Class for storing criteria for Weaknesses attributes.

        Attributes:
            cwe_criteria (str): Checks if the list of weaknesses contains CWE-IDs.
            weakness_type (WeaknessType): The type of weakness to filter out
    """
    name: str = 'weakness_criteria'
    cwe_criteria: CWECriteria = None
    weakness_type: WeaknessType = None

    def populate(self, cve: CVE):
        weaknesses = cve.weaknesses.get_by_type(self.weakness_type) if self.weakness_type else cve.weaknesses

        if self.cwe_criteria:
            self.cwe_criteria.populate(weaknesses)
            self.update(self.cwe_criteria)
        else:
            self.update(AttributeCriterion('has_weaknesses', True, len(cve.weaknesses) > 0))

        self.update(AttributeCriterion('has_weakness_type', self.weakness_type is not None, len(weaknesses) > 0))
