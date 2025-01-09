import re
from pydantic import BaseModel

from nvdutils.common.constants import (MULTI_VULNERABILITY, MULTI_COMPONENT, ENUMERATIONS, FILE_NAMES_PATHS,
                                       VARIABLE_NAMES, URL_PARAMETERS)


multiple_vulnerabilities_pattern = re.compile(MULTI_VULNERABILITY, re.IGNORECASE)
multiple_components_pattern = re.compile(MULTI_COMPONENT, re.IGNORECASE)
enumerations_pattern = re.compile(ENUMERATIONS, re.IGNORECASE)
file_names_paths_pattern = re.compile(FILE_NAMES_PATHS, re.IGNORECASE)
variable_names_pattern = re.compile(VARIABLE_NAMES, re.IGNORECASE)
url_parameters_pattern = re.compile(URL_PARAMETERS, re.IGNORECASE)


class Description(BaseModel):
    lang: str
    value: str

    def is_disputed(self):
        return '** DISPUTED' in self.value

    def is_unsupported(self):
        return '** UNSUPPORTED' in self.value

    def has_multiple_vulnerabilities(self):
        match = multiple_vulnerabilities_pattern.search(self.value)

        return match and len(match.group('vuln_type').split()) < 5

    def has_multiple_components(self):
        match = multiple_components_pattern.search(self.value)

        if match and len(match.group(2).split()) < 5:
            return True

        # check for enumerations
        if re.findall(enumerations_pattern, self.value):
            return True

        # check for multiple distinct file names/paths, variable names, and url parameters
        for pattern in [file_names_paths_pattern, variable_names_pattern, url_parameters_pattern]:
            match = re.findall(pattern, self.value)

            if match:
                # check if the matches are unique and greater than 2 (margin for misspellings and other issues)
                return len(set(match)) > 2

        # TODO: probably there are more, but this is a good start

        return False

    def __str__(self):
        return f"{self.lang}: {self.value}"
