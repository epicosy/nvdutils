from enum import Enum


class CVSSVersion(Enum):
    # https://nvd.nist.gov/vuln-metrics/cvss
    # The NVD began supporting the CVSS v3.1 guidance on September 10th, 2019.
    # The NVD does not offer CVSS v3.0 and v3.1 vector strings for the same CVE.
    # All new and additional CVE assessments are done using the CVSS v3.1 guidance.
    v1_0 = 1
    v2_0 = 2
    v3 = 3
    v4_0 = 4


class MetricsType(Enum):
    Primary = 1
    Secondary = 2
