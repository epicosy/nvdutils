import requests
from requests import Response

from nvdutils.models.metrics.cvss import CVSSv3
from nvdutils.models.references.reference import Reference
from nvdutils.common.constants import METRICS_NUMERICAL_VALUES


def get_url(reference: Reference, timeout: int = 5) -> Response | None:
    # TODO: decide if this should belong to the Reference class or not
    try:
        response = requests.get(reference.url, timeout=timeout)

        if response.status_code == 200:
            return response

    except requests.RequestException as e:
        print(f"Request to {reference.url} failed with exception: {e}")

    return None


def pairwise_inconsistency(cvss_a: CVSSv3, cvss_b: CVSSv3) -> float:
    """Compute inconsistency between two CVSS v3 objects."""

    metrics_a = cvss_a.to_dict()
    metrics_b = cvss_b.to_dict()

    scope_a = metrics_a["scope"]
    scope_b = metrics_b["scope"]

    # Remove scope
    del metrics_a["scope"]
    del metrics_b["scope"]

    # Merge impact metrics
    metrics_a.update(cvss_a.impact_metrics.to_dict())
    metrics_b.update(cvss_b.impact_metrics.to_dict())

    # Sort keys for alignment
    metrics_a = sorted(metrics_a.items())
    metrics_b = sorted(metrics_b.items())

    if len(metrics_a) != len(metrics_b):
        raise ValueError("Metrics are not of the same length")

    # Start score with scope inconsistency
    total_score = 1 if scope_a != scope_b else 0

    for (key_a, value_a), (key_b, value_b) in zip(metrics_a, metrics_b):

        # Handle privileges_required special case
        if key_a == "privileges_required":
            key_a = f"{key_a}_{scope_a}"
            key_b = f"{key_b}_{scope_b}"

        # Determine normalization range
        metric_values = (
            list(METRICS_NUMERICAL_VALUES[key_a].values()) +
            list(METRICS_NUMERICAL_VALUES[key_b].values())
        )
        max_diff = max(metric_values) - min(metric_values)

        # Actual difference
        diff = abs(
            METRICS_NUMERICAL_VALUES[key_a][value_a]
            - METRICS_NUMERICAL_VALUES[key_b][value_b]
        )
        normalized = diff / max_diff
        total_score += normalized

    # Normalize by number of metrics + scope
    return total_score / (len(metrics_a) + 1)
