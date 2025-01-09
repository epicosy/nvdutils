from abc import abstractmethod, ABC
from typing import Dict, Any, Iterator
from dataclasses import dataclass, field


@dataclass
class AttributeCriterion:
    name: str
    apply: bool = False
    value: bool = False


@dataclass
class BaseCriteria(ABC):
    """
        Base class for holding data attributes criteria
    """
    name: str
    criteria: Dict[str, AttributeCriterion] = field(default_factory=dict)

    def __iter__(self) -> Iterator[AttributeCriterion]:
        return iter(self.criteria.values())

    def __call__(self) -> bool:
        """
        Evaluate the criteria. Returns True if no criteria apply, otherwise checks all applicable criteria.
        """
        to_apply = self.applicable_values()
        return True if not to_apply else all(to_apply)

    def applicable_values(self) -> list:
        """
        Get the values of criteria marked as applicable.
        """
        return [v.value for v in self.criteria.values() if v.apply]

    def update(self, criteria: Any):
        """
        Update or add a criterion to the criteria dictionary.
        """
        if isinstance(criteria, BaseCriteria):
            # TODO: just a short-term solution, should be refactored
            for criterion in criteria:
                self.criteria[f"{criteria.name}_{criterion.name}"] = criterion

        elif isinstance(criteria, AttributeCriterion):
            self.criteria[criteria.name] = criteria

    def to_dict(self) -> Dict[str, bool]:
        """
        Convert the applicable criteria to a dictionary format.
        """
        return {k: v.value for k, v in self.criteria.items() if v.apply}

    @abstractmethod
    def populate(self, attributes: Any):
        """
            Populate the attributes criteria based on the input attributes
        """
        raise NotImplementedError
