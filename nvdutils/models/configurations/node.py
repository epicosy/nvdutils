from typing import List, Set, Dict, Any
from collections import defaultdict
from pydantic import BaseModel, Field

from cpelib.types.product import Product
from cpelib.types.definitions import CPEPart

from nvdutils.models.configurations.cpe_match import CPEMatch


class Node(BaseModel):
    operator: str
    negate: bool
    cpe_match: List[CPEMatch] = Field(alias="cpeMatch")
    is_vulnerable: bool = None
    is_context_dependent: bool = None
    is_multi_component: bool = None

    @property
    def non_vulnerable_products(self) -> Set[Product]:
        return {match.cpe.get_product() for match in self.cpe_match if not match.vulnerable}

    @property
    def vulnerable_products(self) -> Set[Product]:
        return {match.cpe.get_product() for match in self.cpe_match if match.vulnerable}

    @property
    def products(self) -> Set[Product]:
        return self.vulnerable_products.union(self.non_vulnerable_products)

    def model_post_init(self, __context: Any):
        """
            Initialize contextual attributes for this node.
        """
        # TODO: check if all attributes are necessary
        self.is_multi_component = len(self.vulnerable_products) > 1
        inconsistent_products = bool(self.vulnerable_products & self.non_vulnerable_products)

        # some nodes have the same product as both vulnerable and non-vulnerable, we want to filter that
        if inconsistent_products and not self.is_multi_component:
            self.is_context_dependent = False
        else:
            # examples: CVE-1999-0766, CVE-2019-18937, CVE-2022-24844
            self.is_context_dependent = len(self.vulnerable_products) > 0 and len(self.non_vulnerable_products) > 0

        if self.is_context_dependent:
            self.is_vulnerable = True
        else:
            all_vulnerable = not self.non_vulnerable_products and self.vulnerable_products
            any_vulnerable = bool(self.vulnerable_products)
            self.is_vulnerable = all_vulnerable if self.operator == 'AND' else any_vulnerable

    def get_targets(self, target_type: str, is_part: CPEPart = None) -> Dict[str, set]:
        """
        Get target hw/sw for the vulnerable products.

        :param target_type: Type of target to fetch ('sw' or 'hw')
        :param is_part: Filter by CPE part
        :return: Dictionary of target hw/sw values for this node
        """

        if target_type not in ['sw', 'hw']:
            raise ValueError("target_type must be either 'sw' or 'hw'")

        target_key = f'target_{target_type}'

        # Initialize target as a defaultdict of sets to automatically handle duplicates
        target_values = defaultdict(set)

        for cpe_match in self.cpe_match:
            if not cpe_match.vulnerable:
                continue

            if is_part and cpe_match.cpe.part != is_part.value:
                continue

            target_value = getattr(cpe_match.cpe, target_key)

            if target_value in ['*', '-']:
                # Skip wildcards/blanks
                continue

            key = f"{cpe_match.cpe.vendor} {cpe_match.cpe.product}"

            target_values[key].add(target_value)

        return target_values
