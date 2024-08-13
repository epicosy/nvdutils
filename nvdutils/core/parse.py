import re
from typing import List, Dict
from cpeparser import CpeParser

from nvdutils.types.weakness import Weakness, WeaknessType, WeaknessDescription
from nvdutils.types.cvss import BaseCVSS, CVSSv2, CVSSv3, CVSSType, CVSSScores, ImpactMetrics
from nvdutils.types.configuration import Configuration, Node, CPEMatch, CPE
from nvdutils.types.cna import CNA

from nvdutils.utils.templates import PLATFORM_SPECIFIC_SW, PLATFORM_SPECIFIC_HW

cpe_parser = CpeParser()
platform_specific_sw_pattern = re.compile(PLATFORM_SPECIFIC_SW, re.IGNORECASE)
platform_specific_hw_pattern = re.compile(PLATFORM_SPECIFIC_HW, re.IGNORECASE)


def parse_cna_data(cna_data: dict) -> Dict[str, CNA]:
    return {k: CNA(id=k, **v) for k, v in cna_data.items()}


def parse_weaknesses(weaknesses: list) -> Dict[str, Weakness]:
    parsed_weaknesses = {}

    for weakness in weaknesses:
        description = [WeaknessDescription(**desc) for desc in weakness['description']]
        parsed_weaknesses[weakness['type']] = Weakness(source=weakness['source'], type=WeaknessType[weakness['type']],
                                                       description=description)

    return parsed_weaknesses


def parse_metrics(metrics: dict) -> Dict[str, BaseCVSS]:
    parsed_metrics = {}

    for key, values in metrics.items():
        if key == 'cvssMetricV40':
            # TODO: to be implemented
            continue

        for i, value in enumerate(values):
            name = f"{key}_{i}"
            cvss_type = CVSSType[value['type']]
            impact_metrics = ImpactMetrics(availability=value['cvssData']['availabilityImpact'],
                                           confidentiality=value['cvssData']['confidentialityImpact'],
                                           integrity=value['cvssData']['integrityImpact'])
            cvss_scores = CVSSScores(base=value['cvssData']['baseScore'], impact=value['impactScore'],
                                     exploitability=value['exploitabilityScore'])

            if key == 'cvssMetricV2':
                parsed_metrics[name] = CVSSv2(type=cvss_type, source=value['source'], impact=impact_metrics,
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
                                              user_interaction_required=value.get('userInteractionRequired', False))
            elif 'cvssMetricV3' in key:
                parsed_metrics[name] = CVSSv3(type=cvss_type, source=value['source'], impact=impact_metrics,
                                              scores=cvss_scores, base_severity=value['cvssData']['baseSeverity'],
                                              version=value['cvssData']['version'],
                                              vector=value['cvssData']['vectorString'],
                                              attack_vector=value['cvssData']['attackVector'],
                                              attack_complexity=value['cvssData']['attackComplexity'],
                                              privileges_required=value['cvssData']['privilegesRequired'],
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
