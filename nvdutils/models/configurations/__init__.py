from collections import defaultdict
from pydantic import BaseModel, Field
from typing import List, Set, Union, Dict, Iterator

from cpelib.types.product import Product
from cpelib.types.definitions import CPEPart

from nvdutils.models.configurations.node import Node
from nvdutils.models.configurations.configuration import Configuration


class Configurations(BaseModel):
    elements: List[Configuration] = Field(default_factory=list)

    def __iter__(self) -> Iterator[Configuration]:
        return iter(self.elements)

    @property
    def non_vulnerable_configurations(self) -> List[Configuration]:
        return [config for config in self.elements if not config.is_vulnerable]

    @property
    def vulnerable_configurations(self) -> List[Configuration]:
        return [config for config in self.elements if config.is_vulnerable]

    @property
    def vulnerable_products(self) -> Set[Product]:
        """
            Get all vulnerable products for this CVE
        """

        return {_p for config in self.vulnerable_configurations for _p in config.vulnerable_products}

    def get_vulnerable_parts(self, ordered: bool = False, values: bool = False, string: bool = False) \
            -> Union[Set[CPEPart], Set[str], List[str], str]:
        """
            Get all vulnerable parts for the configurations. Useful for knowing which parts are affected.

            :param ordered: whether to return the parts in a sorted order
            :param values: whether to return the part values
            :param string: whether to return the parts as a string

            :return: set of parts, set of part values, list of part values, or string of part values
        """
        # TODO: check if method is really necessary/useful

        if values:
            _output = {product.part.value for product in self.vulnerable_products}

            if ordered:
                _output = sorted(_output)

            if string:
                _output = "::".join(_output)

        else:
            _output = {product.part for product in self.vulnerable_products}

        return _output

    def get_targets(self, target_type: str, is_part: CPEPart = None) -> Dict[str, list]:
        # TODO: check if method is necessary, configurations should be independent, meaning that the targets are
        #  specific to each configuration
        """
            Get target sw/hw for the vulnerable configurations.

            :param target_type: type of target software to fetch ('sw' or 'hw')
            :param is_part: filter by CPE part

            :return: dictionary of target hw/sw values for this CVE
        """
        if is_part:
            assert isinstance(is_part, CPEPart), 'is_part must be an instance of CPEPart'

        target_values = defaultdict(list)

        for config in self.elements:
            config_target = config.get_target(target_type, is_part)

            for key, value in config_target.items():
                target_values[key].extend(value)

        # Convert lists to sets to remove duplicates, then back to lists
        target_values = {key: list(set(value)) for key, value in target_values.items()}

        return target_values

    def __len__(self):
        return len(self.elements)
