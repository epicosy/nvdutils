from pydantic import BaseModel
from typing import List, Set, Dict
from collections import defaultdict

from cpelib.types.product import Product
from cpelib.types.definitions import CPEPart
from nvdutils.models.configurations.node import Node


class Configuration(BaseModel):
    nodes: List[Node]
    is_vulnerable: bool = None
    is_multi_component: bool = None
    is_platform_specific: bool = None
    operator: str = None

    @property
    def non_vulnerable_nodes(self) -> List[Node]:
        return [node for node in self.nodes if not node.is_vulnerable]

    @property
    def vulnerable_nodes(self) -> List[Node]:
        return [node for node in self.nodes if node.is_vulnerable]

    def model_post_init(self, __context):
        """
            Initialize contextual attributes for this configuration.
        """
        # TODO: check if all attributes are necessary
        self.is_platform_specific = any([node.is_context_dependent for node in self.nodes])

        if self.is_platform_specific:
            self.is_vulnerable = True
        else:
            all_vulnerable = not self.non_vulnerable_nodes and self.vulnerable_nodes
            any_vulnerable = bool(self.vulnerable_nodes)
            self.is_vulnerable = all_vulnerable if self.operator == 'AND' else any_vulnerable

        self.is_multi_component = len({_p for node in self.vulnerable_nodes for _p in node.vulnerable_products}) > 1

    @property
    def vulnerable_products(self) -> Set[Product]:
        """
            Get all vulnerable products for this configuration.

            :return: set of vulnerable products for this configuration
        """
        return {_p for node in self.vulnerable_nodes for _p in node.vulnerable_products}

    def get_targets(self, target_type: str, is_part: CPEPart = None) -> Dict[str, list]:
        """
            Get target sw/hw for the vulnerable products.
            :param target_type: type of target to fetch ('sw' or 'hw')
            :param is_part: filter by CPE part

            :return: dictionary of target hw/sw values for this configuration
        """
        target_values = defaultdict(list)

        for _node in self.nodes:
            node_target_sw = _node.get_target(target_type, is_part=is_part)

            for key, value in node_target_sw.items():
                target_values[key].extend(value)

        # Convert lists to sets to remove duplicates, then back to lists
        target_values = {key: list(set(value)) for key, value in target_values.items()}

        return target_values
