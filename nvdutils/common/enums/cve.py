from enum import Enum


class Status(Enum):
    # https://nvd.nist.gov/vuln/vulnerability-status
    # NVD Statuses + 2 Custom Statuses extracted from the CVE descriptions
    RECEIVED = 'Received'
    AWAITING_ANALYSIS = 'Awaiting Analysis'
    UNDERGOING_ANALYSIS = 'Undergoing Analysis'
    ANALYZED = 'Analyzed'
    MODIFIED = 'Modified'
    DEFERRED = 'Deferred'
    REJECTED = 'Rejected'
    # Custom Statuses
    DISPUTED = 'Disputed'
    UNSUPPORTED = 'Unsupported'


class TagType(Enum):
    ThirdPartyAdvisory = 1
    MailingList = 2
    PermissionsRequired = 3
    ToolSignature = 4
    VDBEntry = 5
    ReleaseNotes = 6
    Patch = 7
    TechnicalDescription = 8
    PressMediaCoverage = 9
    Exploit = 10
    USGovernmentResource = 11
    BrokenLink = 12
    NotApplicable = 13
    Product = 14
    URLRepurposed = 15
    VendorAdvisory = 16
    Mitigation = 17
    IssueTracking = 18
    Other = 19
