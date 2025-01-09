from datetime import datetime


DEFAULT_START_YEAR = 1999
DEFAULT_END_YEAR = datetime.now().year


MULTI_VULNERABILITY = r'(multiple|several|various)(?P<vuln_type>.+?)(vulnerabilities|flaws|issues|weaknesses)'
MULTI_COMPONENT = (r'(several|various|multiple)(.+?|)(parameters|components|plugins|features|fields|pages|locations|'
                   r'properties|instances|vectors|files|functions|elements|options|headers|sections|forms|places|areas|'
                   r'values|inputs|endpoints|widgets|settings|layers|nodes)')


ENUMERATIONS = r'((\(| )\d{1,2}(\)|\.| -) .+?){2,}\.'
FILE_NAMES_PATHS = r'( |`|"|\')[\\\/\w_]{3,}\.[a-z]+'
VARIABLE_NAMES = r'( |"|`|\')(\w+\_\w+){1,}'
URL_PARAMETERS = r'(\w+=\w+).+?( |,)'
