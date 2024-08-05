
MULTI_VULNERABILITY = r'(multiple|several|various)(?P<vuln_type>.+?)(vulnerabilities|flaws|issues|weaknesses)'
MULTI_COMPONENT = (r'(several|various|multiple)(.+?|)(parameters|components|plugins|features|fields|pages|locations|'
                   r'properties|instances|vectors|files|functions|elements|options|headers|sections|forms|places|areas|'
                   r'values|inputs|endpoints|widgets|settings|layers|nodes)')

ENUMERATIONS = r'((\(| )\d{1,2}(\)|\.| -) .+?){2,}\.'
FILE_NAMES_PATHS = r'( |`|"|\')[\\\/\w_]{3,}\.[a-z]+'
VARIABLE_NAMES = r'( |"|`|\')(\w+\_\w+){1,}'
URL_PARAMETERS = r'(\w+=\w+).+?( |,)'


PLATFORM_SPECIFIC_SW = (r'(windows|linux|^mac$|macos|mac_os_x|^ios$|android|freebsd|openbsd|netbsd|solaris|aix|hp-ux|'
                        r'microsoft|apple|suse|red_hat|redhat|centos|fedora|debian|ubuntu|gentoo|iphone|ipad|ipod|_os$|'
                        r'unix|sunos|netware|kaios|alpine|qubesos|operating_system)')

# some of the keywords found in the CPEs are indirectly related to the hardware
PLATFORM_SPECIFIC_HW = r'(x86|x64|arm|arm64|ipad|unix|linux|windows|iphone_os|android)'
