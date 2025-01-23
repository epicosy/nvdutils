from collections import defaultdict
from dataclasses import dataclass, field

from nvdutils.data.profiles.base import BaseProfile


@dataclass
class Stats:
    """
        Class to store yearly statistics for the loader

        Attributes:
            total (int): The total number of CVEs
            selected (int): The number of selected CVEs
            skipped (int): The number of CVEs skipped based on attributes criteria.
            details (dict): A nested dictionary tracking the reasons (criteria) for skipping CVEs.
    """
    total: int = 0
    selected: int = 0
    skipped: int = 0
    details: dict = field(default_factory=lambda: defaultdict(int))

    def update(self, outcome: bool, profile: BaseProfile):
        """
            Update the detailed statistics for loaded CVEs based on the outcome of the profile criteria.

            Args:
                outcome (bool): The outcome of the profile criteria
                profile (BaseProfile): The profile used for evaluating the attributes in a CVE
        """
        self.total += 1

        if outcome:
            self.selected += 1
        else:
            self.skipped += 1

        # Iterate through the checks and update the `details` dictionary.
        for key, value in profile.to_dict().items():
            if isinstance(value, dict):  # Handle nested dictionary (e.g., detailed checks like CWE, CVSS)
                if key not in self.details:
                    self.details[key] = defaultdict(int)  # Create a nested defaultdict for details[key]

                for k, v in value.items():
                    # Only count if the value is True
                    self.details[key][k] += 1 if v else 0
            else:
                # Only count if the value is True
                if value:
                    self.details[key] += 1

    def display(self) -> str:
        """
            Display the statistics
        """
        display_str = "["

        for key, values in self.details.items():
            # key_display = key.replace("_", " ")
            key_display = ' '.join([k.capitalize() for k in key.split('_')])  # Convert snake_case to 'Title Case'
            display_str += f"{key_display}: ("

            for k, v in values.items():
                k_display = k.replace("_", " ")
                display_str += f"{k_display}={v}, "

            display_str = display_str[:-2] + ") | "

        display_str = display_str[:-3] + "]"

        return display_str
