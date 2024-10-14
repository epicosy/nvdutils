import re
from typing import List, Dict, Union
from cpeparser import CpeParser
from urllib.parse import urlparse


from nvdutils.types.weakness import Weakness, WeaknessType, WeaknessDescription
from nvdutils.types.cvss import BaseCVSS, CVSSv2, CVSSv3, CVSSType, CVSSScores, ImpactMetrics
from nvdutils.types.configuration import Configuration, Node, CPEMatch, CPE
from nvdutils.types.reference import Reference, CommitReference

from nvdutils.utils.templates import (PLATFORM_SPECIFIC_SW, PLATFORM_SPECIFIC_HW, HOST_OWNER_REPO_REGEX,
                                      COMMIT_REF_REGEX, COMMIT_SHA_REGEX)

cpe_parser = CpeParser()
platform_specific_sw_pattern = re.compile(PLATFORM_SPECIFIC_SW, re.IGNORECASE)
platform_specific_hw_pattern = re.compile(PLATFORM_SPECIFIC_HW, re.IGNORECASE)


def clean_commit_url(ref: str) -> str:
    """
        Normalizes commit reference
    """
    if "CONFIRM:" in ref:
        # e.g., https://github.com/{owner}/{repo}/commit/{sha}CONFIRM:
        ref = ref.replace("CONFIRM:", '')

    if 'git://' in ref and 'github.com' in ref:
        ref = ref.replace('git://', 'https://')

    if '#' in ref and ('#comments' in ref or '#commitcomment' in ref):
        # e.g., https://github.com/{owner}/{repo}/commit/{sha}#commitcomment-{id}
        ref = ref.split('#')[0]

    if '.patch' in ref:
        # e.g., https://github.com/{owner}/{repo}/commit/{sha}.patch
        ref = ref.replace('.patch', '')
    if '%23' in ref:
        # e.g., https://github.com/absolunet/kafe/commit/c644c798bfcdc1b0bbb1f0ca59e2e2664ff3fdd0%23diff
        # -f0f4b5b19ad46588ae9d7dc1889f681252b0698a4ead3a77b7c7d127ee657857
        ref = ref.replace('%23', '#')

    # the #diff part in the url is used to specify the section of the page to display, for now is not relevant
    if "#diff" in ref:
        ref = ref.split("#")[0]
    if "?w=1" in ref:
        ref = ref.replace("?w=1", "")
    if "?branch=" in ref:
        ref = ref.split("?branch=")[0]
    if "?diff=split" in ref:
        ref = ref.replace("?diff=split", "")
    if re.match(r".*(,|/)$", ref):
        if "/" in ref:
            ref = ref[0:-1]
        else:
            ref = ref.replace(",", "")
    elif ")" in ref:
        ref = ref.replace(")", "")

    return ref


def parse_commit_reference(reference: Reference) -> Union[Reference, CommitReference]:
    """
        Transform a Reference of a commit into a CommitReference object. If the commit url does not conform to the
        expected format, it will be returned as a Reference object.

        reference: Reference object to be transformed

        return: CommitReference object if the reference conforms to the expected format, otherwise a Reference
    """

    # TODO: implement regex expression to extract information from the following github references
    # e.g., https://github.com/intelliants/subrion/commits/develop
    # e.g., https://gitlab.gnome.org/GNOME/gthumb/commits/master/extensions/cairo_io/cairo-image-surface-jpeg.c
    # e.g., https://github.com/{owner}/{repo}/commits/{branch}
    # e.g., https://github.com/moby/moby/pull/35399/commits/a21ecdf3c8a343a7c94e4c4d01b178c87ca7aaa1
    has_sha = re.search(COMMIT_SHA_REGEX, reference.url)

    if has_sha:
        # TODO: implement functionality to extract the owner and repo from the following
        # # e.g., https://github.com/{owner}/{repo}/commits/master?after={sha}+{no_commits}
        if '/master?' not in reference.url:
            # TODO: extract useful information (diff, branch, etc.) from the raw url and keep in the CommitReference
            reference.processed_url = clean_commit_url(reference.url)
            host_repo_owner = re.search(HOST_OWNER_REPO_REGEX, reference.processed_url)

            if host_repo_owner:
                return CommitReference.from_reference(
                    reference=reference,
                    vcs=urlparse(host_repo_owner.group('host')).hostname.split('.')[0],
                    owner=host_repo_owner.group('owner'),
                    repo=host_repo_owner.group('repo'),
                    sha=has_sha.group(0)
                )

    return reference


def parse_references(references: List[dict]) -> List[Reference]:
    parsed_references = []

    for ref_dict in references:
        reference = Reference(**ref_dict)
        has_host_commit = re.search(COMMIT_REF_REGEX, reference.url)

        if has_host_commit:
            reference = parse_commit_reference(reference)

        parsed_references.append(reference)

    return parsed_references


def parse_weaknesses(weaknesses: list) -> Dict[str, Weakness]:
    parsed_weaknesses = {}

    for weakness in weaknesses:
        description = [WeaknessDescription(**desc) for desc in weakness['description']]
        parsed_weaknesses[weakness['type']] = Weakness(source=weakness['source'], type=WeaknessType[weakness['type']],
                                                       description=description)

    return parsed_weaknesses


def parse_metrics(metrics: dict) -> Dict[str, Dict[str, BaseCVSS]]:
    parsed_metrics = {}

    # TODO: metrics should have their own type like CVSSType
    for key, values in metrics.items():
        parsed_metrics[key] = {}

        if key == 'cvssMetricV40':
            # TODO: to be implemented
            continue

        for i, value in enumerate(values):
            cvss_type = CVSSType[value['type']]
            impact_metrics = ImpactMetrics(availability=value['cvssData']['availabilityImpact'],
                                           confidentiality=value['cvssData']['confidentialityImpact'],
                                           integrity=value['cvssData']['integrityImpact'])
            cvss_scores = CVSSScores(base=value['cvssData']['baseScore'], impact=value['impactScore'],
                                     exploitability=value['exploitabilityScore'])

            if key == 'cvssMetricV2':
                parsed_metrics[key][cvss_type.name] = CVSSv2(type=cvss_type, source=value['source'],
                                                             impact=impact_metrics,
                                                             scores=cvss_scores, base_severity=value['baseSeverity'],
                                                             version=value['cvssData']['version'],
                                                             vector=value['cvssData']['vectorString'],
                                                             access_vector=value['cvssData']['accessVector'],
                                                             access_complexity=value['cvssData']['accessComplexity'],
                                                             authentication=value['cvssData']['authentication'],
                                                             ac_insuf_info=value['acInsufInfo'],
                                                             obtain_all_privilege=value['obtainAllPrivilege'],
                                                             obtain_user_privilege=value['obtainUserPrivilege'],
                                                             obtain_other_privilege=value['obtainOtherPrivilege'],
                                                             user_interaction_required=value.get(
                                                                 'userInteractionRequired',
                                                                 False))
            elif 'cvssMetricV3' in key:
                parsed_metrics[key][cvss_type.name] = CVSSv3(type=cvss_type, source=value['source'],
                                                             impact=impact_metrics,
                                                             scores=cvss_scores,
                                                             base_severity=value['cvssData']['baseSeverity'],
                                                             version=value['cvssData']['version'],
                                                             vector=value['cvssData']['vectorString'],
                                                             attack_vector=value['cvssData']['attackVector'],
                                                             attack_complexity=value['cvssData']['attackComplexity'],
                                                             privileges_required=value['cvssData'][
                                                                 'privilegesRequired'],
                                                             user_interaction=value['cvssData']['userInteraction'],
                                                             scope=value['cvssData']['scope'])
            else:
                # TODO: to be implemented
                pass

    return parsed_metrics


def parse_cpe_match(match: dict, has_runtime_environment: bool) -> CPEMatch:
    cpe_version = match['criteria'].split(':')[1]
    cpe_dict = cpe_parser.parser(match['criteria'])
    cpe = CPE(cpe_version=cpe_version, **cpe_dict)
    # TODO: might be necessary to consider node operator 'OR', so far it does not seem to be the case
    is_runtime_environment = has_runtime_environment and cpe.part == 'o' and not match['vulnerable']
    is_platform_specific_sw = False
    is_platform_specific_hw = False

    if cpe.target_sw not in ['*', '-']:
        is_platform_specific_sw = platform_specific_sw_pattern.search(cpe.target_sw) is not None

    if cpe.target_hw not in ['*', '-']:
        is_platform_specific_hw = platform_specific_hw_pattern.search(cpe.target_hw) is not None

    return CPEMatch(criteria_id=match['matchCriteriaId'], criteria=match['criteria'], cpe=cpe,
                    vulnerable=match['vulnerable'], version_start_including=match.get('versionStartIncluding', None),
                    version_start_excluding=match.get('versionStartExcluding', None),
                    version_end_including=match.get('versionEndIncluding', None),
                    version_end_excluding=match.get('versionEndExcluding', None),
                    is_runtime_environment=is_runtime_environment,
                    is_platform_specific_sw=is_platform_specific_sw,
                    is_platform_specific_hw=is_platform_specific_hw)


def parse_configurations(configurations: list) -> List[Configuration]:
    parsed_configs = []

    for config in configurations:
        nodes = []
        config_operator = config.get('operator', None)
        has_runtime_environment = config_operator and config_operator == 'AND'

        for node_dict in config['nodes']:
            matches = []
            node_operator = node_dict.get('operator', None)
            # TODO: implement functionality for 'AND' operator to consider "in combination" CPEs

            for match in node_dict['cpeMatch']:
                cpe_match = parse_cpe_match(match, has_runtime_environment)
                matches.append(cpe_match)

            node = Node(operator=node_operator, negate=node_dict['negate'], cpe_match=matches)
            nodes.append(node)

        config = Configuration(operator=config_operator, nodes=nodes)
        parsed_configs.append(config)

    return parsed_configs
