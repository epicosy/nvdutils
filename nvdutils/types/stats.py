from collections import defaultdict
from dataclasses import dataclass, field

from nvdutils.types.options import CVEOptionsCheck


@dataclass
class LoaderYearlyStats:
    """
        Class to store yearly statistics for the loader

        Attributes:
            year (int): The year of the statistics
            total (int): The total number of CVEs
            processed (int): The number of CVEs successfully processed
            skipped (int): The number of CVEs skipped based on options check
            details (dict): A nested dictionary tracking the reasons (checks) for skipping CVEs.
    """
    year: int
    total: int = 0
    processed: int = 0
    skipped: int = 0
    details: dict = field(default_factory=lambda: defaultdict(int))

    def update_details_with_checks(self, checks: CVEOptionsCheck):
        """
        Update the detailed statistics for skipped CVEs based on the outcome of the checks.

        Args:
            checks (CVEOptionsCheck): The result of the options check for a CVE, indicating which checks failed.
        """
        check_dict = checks.to_dict()

        # Iterate through the checks and update the `details` dictionary.
        for key, value in check_dict.items():
            if isinstance(value, dict):  # Handle nested dictionary (e.g., detailed checks like CWE, CVSS)
                if key not in self.details:
                    self.details[key] = defaultdict(int)  # Create a nested defaultdict for details[key]

                for k, v in value.items():
                    # Only count if the value is True
                    if v:
                        self.details[key][k] += 1
            else:
                # Only count if the value is True
                if value:
                    self.details[key] += 1

    def to_dict(self):
        return self.__dict__
