from itertools import combinations
from pydantic import BaseModel, Field
from typing import List, Iterator, Optional

from nvdutils.utils.helpers import pairwise_inconsistency
from nvdutils.models.metrics.cvss import CVSS, CVSSv2, CVSSv3
from nvdutils.common.enums.metrics import CVSSVersion, MetricsType


class Metrics(BaseModel):
    cvss_v2: List[CVSSv2] = Field(default_factory=list, alias="cvssMetricV2")
    cvss_v3: List[CVSSv3] = Field(default_factory=list, alias="cvssMetricV3")
    # TODO: implement cvssMetricV4

    def __iter__(self) -> Iterator[CVSS]:
        return iter(self.cvss_v2 + self.cvss_v3)

    def __len__(self):
        return len(self.cvss_v2 + self.cvss_v3)

    def has_cvss_v2(self):
        return bool(self.cvss_v2)

    def has_cvss_v3(self):
        return bool(self.cvss_v3)

    def has_version(self, version: CVSSVersion):
        if version == CVSSVersion.v2_0:
            return self.has_cvss_v2()
        elif version == CVSSVersion.v3:
            return self.has_cvss_v3()
        else:
            return False

    def get_by_version(self, version: CVSSVersion) -> List[CVSS] | None:
        if version == CVSSVersion.v2_0:
            return self.cvss_v2
        elif version == CVSSVersion.v3:
            return self.cvss_v3
        else:
            return None

    def get_by_type(self, metric_type: MetricsType):
        return [_cvss for _cvss in self if _cvss.metrics_type == metric_type]

    def get(self, metric_type: MetricsType = None, version: CVSSVersion = None) -> List[CVSS]:
        """
            Get metrics for this CVE
            :param metric_type: filter by Metric type (Primary or Secondary)
            :param version: filter by CVSS version (V2, V3, V4, etc.)

            :return: list of metrics
        """
        if not metric_type and not version:
            return self

        if not version:
            return self.get_by_type(metric_type)

        if not metric_type:
            return self.get_by_version(version)

        return [_cvss for _cvss in self.get_by_version(version) if _cvss.metrics_type == metric_type]

    def get_cvss_v3_inconsistency_score(self) -> Optional[float]:
        if len(self.cvss_v3) < 2:
            return None

        vectors = {c.vector for c in self.cvss_v3}
        if len(vectors) == 1:
            return 0.0

        # Compute all pairwise inconsistency scores
        pair_scores = [
            pairwise_inconsistency(a, b)
            for a, b in combinations(self.cvss_v3, 2)
        ]

        # Return the average
        return sum(pair_scores) / len(pair_scores)
