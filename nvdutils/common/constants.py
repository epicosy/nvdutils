from datetime import datetime


DEFAULT_START_YEAR = 1999
DEFAULT_END_YEAR = datetime.now().year


MULTI_VULNERABILITY = r'(multiple|several|various)(?P<vuln_type>.+?)(vulnerabilities|flaws|issues|weaknesses|overflows|injections)'
MULTI_COMPONENT = (r'(several|various|multiple)(.+?|)(parameters|components|plugins|features|fields|pages|locations|'
                   r'properties|instances|vectors|files|functions|elements|options|headers|sections|forms|places|areas|'
                   r'values|inputs|endpoints|widgets|settings|layers|nodes)')


ENUMERATIONS = r'((\(| )\d{1,2}(\)|\.| -) .+?){2,}\.'
FILE_NAMES_PATHS = r'( |`|"|\')[\\\/\w_]{3,}\.[a-z]+'
VARIABLE_NAMES = r'( |"|`|\')(\w+\_\w+){1,}'
URL_PARAMETERS = r'(\w+=\w+).+?( |,)'
REMOVE_EXTRA_INFO = r'\s*\(.*?\)'
MULTI_SENTENCE = r'\w+\.\s+[A-Z0-9]'

# TODO: temporary solution
METRICS_NUMERICAL_VALUES = {
    "attack_vector": {
        "NETWORK": 0.85,
        "ADJACENT_NETWORK": 0.62,
        "LOCAL": 0.55,
        "PHYSICAL": 0.2
    },
    "attack_complexity": {
        "LOW": 0.77,
        "HIGH": 0.44,
    },
    "privileges_required_UNCHANGED": {
        "NONE": 0.85,
        "LOW": 0.62,
        "HIGH": 0.27,
    },
    "privileges_required_CHANGED": {
        "NONE": 0.85,
        "LOW": 0.68,
        "HIGH": 0.50
    },
    "user_interaction": {
        "NONE": 0.85,
        "REQUIRED": 0.62
    },
    "confidentiality": {
        "NONE": 0,
        "LOW": 0.22,
        "HIGH": 0.56,
    },
    "integrity": {
        "NONE": 0,
        "LOW": 0.22,
        "HIGH": 0.56,
    },
    "availability": {
        "NONE": 0,
        "LOW": 0.22,
        "HIGH": 0.56,
    }
}
