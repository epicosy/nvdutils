from dataclasses import dataclass
from cpelib.types.definitions import CPEPart

from nvdutils.models.cve import CVE
from nvdutils.models import Configurations
from nvdutils.data.criteria.base import BaseCriteria, AttributeCriterion


@dataclass
class AffectedProductCriteria(BaseCriteria):
    """
        Class for storing criteria for affected products attributes

        Attributes:
            part (CPEPart): Picks only the products with the specified part
            is_single (bool): Whether to filter out CVEs with multiple affected products
    """
    name: str = 'affected_products_criteria'
    part: CPEPart = None
    is_single: bool = False

    def populate(self, configurations: Configurations):
        if self.part:
            products = {_p for _p in configurations.vulnerable_products if _p.part == self.part}
        else:
            products = configurations.vulnerable_products

        # TODO: maybe these checks should be mutually exclusive
        self.update(AttributeCriterion('has_affected_products', True, len(products) > 0))
        self.update(AttributeCriterion('is_single', self.is_single, len(products) == 1))


@dataclass
class ConfigurationsCriteria(BaseCriteria):
    """
        Class for storing criteria for configuration attributes

        Attributes:
            affected_products (AffectedProductCriteria): Criteria for affected products
            is_single (bool): Whether to include CVEs with multiple configurations
    """
    name: str = 'configurations_criteria'
    affected_products: AffectedProductCriteria = None
    is_single: bool = False

    def populate(self, cve: CVE):
        if self.affected_products:
            self.affected_products.populate(cve.configurations)
            self.update(self.affected_products)
        else:
            self.update(AttributeCriterion('has_config', True, len(cve.configurations) > 0))

        self.update(AttributeCriterion('is_single', self.is_single, len(cve.configurations) == 1))

        # TODO: add flags to select configurations by heuristics
        #  e.g. find CVEs with vulnerable application that affects OS
        #     if len(app_products) == 1 and CPEPart.Hardware.value not in parts:
        #         return True
