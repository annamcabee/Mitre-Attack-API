#!/usr/bin/env python

import requests

import simplejson as json


class AttackAPI(object):

    def convert_dict(self, list_of_dicts, query_header):
        converted_list = list()
        for d in list_of_dicts:
            converted_list.append(d[query_header])
        return converted_list

    def get_all_techniques(self):
        technique_list = list()
        response = requests.get("https://attack.mitre.org/api.php?action=ask&format=json&query=%5B%5BCategory%3ATechnique%5D%5D%7C%3FHas+CAPEC+ID%7C%3FHas+ID%7C%3FHas+analytic+details%23-ia%7C%3FHas+contributor%7C%3FHas+data+source%7C%3FHas+display+name%7C%3FHas+link+text%7C%3FHas+mitigation%23-ia%7C%3FHas+platform%7C%3FHas+tactic%7C%3FHas+technical+description%23-ia%7C%3FHas+technique+name%7C%3FRequires+permissions%7C%3FRequires+system%7C%3FBypasses+defense%7C%3FCitation+reference%7Climit%3D9999")  # noqa
        data = json.loads(response.content)
        results = data['query']['results']
        for item in results:
            technique = results[str(item)]
            technique_dict = {
                'Full Text': technique['fulltext'],
                'URL': technique['fullurl'],
                'ID': technique['printouts']['Has ID'],
                'CAPEC ID': technique['printouts']['Has CAPEC ID'],
                'Display Name': technique['printouts']['Has display name'],
                'Technique Name': technique['printouts']['Has technique name'],
                'Requires Permissions':
                    technique['printouts']['Requires permissions'],
                'Link Text': technique['printouts']['Has link text'],
                'Analytic Details':
                    technique['printouts']['Has analytic details'],
                'Contributor': technique['printouts']['Has contributor'],
                'Data Source': technique['printouts']['Has data source'],
                'Mitigation': technique['printouts']['Has mitigation'],
                'Platform': technique['printouts']['Has platform'],
                'Tactic': self.convert_dict(
                    technique['printouts']['Has tactic'], 'fulltext'),
                'Technical Description':
                    technique['printouts']['Has technical description'],
                'Requires System': technique['printouts']['Requires system'],
                'Bypass': technique['printouts']['Bypasses defense'],
                'Citation Reference':
                    technique['printouts']['Bypasses defense']
            }
            technique_list.append(technique_dict)
        return technique_list

    def get_all_groups(self):
        group_list = list()
        response = requests.get("https://attack.mitre.org/api.php?action=ask&format=json&query=%5B%5BCategory%3AGroup%5D%5D%7C%3FHas+ID%7C%3FHas+alias%7C%3FHas+description%23-ia%7C%3FHas+display+name%7C%3FHas+link+text%7C%3FHas+technique%7C%3FUses+software%7C%3FCitation+reference%7C%3FHas+URL%7Climit%3D9999")  # noqa
        data = json.loads(response.content)
        results = data['query']['results']
        for item in results:
            group = results[str(item)]
            group_dict = {
                'URL': group['fullurl'],
                'ID': group['printouts']['Has ID'],
                'Alias': group['printouts']['Has alias'],
                'Display Title': group['displaytitle'],
                'Description': group['printouts']['Has description'],
                'Name': group['printouts']['Has display name'],
                'Link Text': group['printouts']['Has link text'],
                'Technique': self.convert_dict(
                    group['printouts']['Has technique'], 'fulltext'),
                'Software': self.convert_dict(
                    group['printouts']['Uses software'], 'displaytitle'),
                'Reference': group['printouts']['Citation reference']
            }
            group_list.append(group_dict)
        return group_list

    def get_all_software(self):
        software_list = list()
        response = requests.get("https://attack.mitre.org/api.php?action=ask&format=json&query=%5B%5BCategory%3ASoftware%5D%5D%7C%3FHas+ID%7C%3FHas+alias%7C%3FHas+description%23-ia%7C%3FHas+display+name%7C%3FHas+link+text%7C%3FHas+software+type%7C%3FHas+technique%7C%3FCitation+reference%7Climit%3D9999")  # noqa
        data = json.loads(response.content)
        results = data['query']['results']
        for item in results:
            software = results[str(item)]
            software_dict = {
                'ID': software['printouts']['Has ID'],
                'Alias': software['printouts']['Has alias'],
                'Description': software['printouts']['Has description'],
                'Name': software['printouts']['Has display name'],
                'Link Text': software['printouts']['Has link text'],
                'Technique': self.convert_dict(
                    software['printouts']['Has technique'], 'fulltext'),
                'Software Type': software['printouts']['Has software type'],
                'Reference': software['printouts']['Citation reference']
            }
            software_list.append(software_dict)
        return software_list

    def get_all_subobjects(self):
        technique_subobject_list = list()
        response = requests.get("https://attack.mitre.org/api.php?action=ask&format=json&query=%5B%5BHas+technique+object%3A%3A%2B%5D%5D%7C%3FHas+technique+description%23-ia%7C%3FHas+technique+object%7Climit%3D9999")  # noqa
        data = json.loads(response.content)
        results = data['query']['results']
        for item in results:
            technique_subobject_dict = {
                'Display Title': results[str(item)]['displaytitle'],
                'Technique Name': self.convert_dict(
                    results[str(item)]['printouts']['Has technique object'],
                    'displaytitle'),
                'Technique ID': self.convert_dict(
                    results[str(item)]['printouts']['Has technique object'],
                    'fulltext'),
                'URL': self.convert_dict(
                    results[str(item)]['printouts']['Has technique object'],
                    'fullurl'),
                'Description': results[str(item)]['printouts']
                ['Has technique description']
            }
            technique_subobject_list.append(technique_subobject_dict)
        return technique_subobject_list

    def get_matrix(self):
        tactics_list = ['Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement','Execution', 'Collection', 'Exfiltration', 'Command and Control']
        tactic_technique_dict = {t:[] for t in tactics_list}
        techniques_list = self.get_all_techniques()
        for technique in techniques_list:
            for tactic in tactics_list:
                    if tactic in  technique['Tactic']:
                            tactic_technique_dict[tactic].append(technique['Display Name'])
        for tt in tactic_technique_dict:
            tactic_technique_dict[tt].sort()
        max_tactic = max(tactic_technique_dict, key=lambda k: len(tactic_technique_dict[k]))
        max_values = len(tactic_technique_dict[max_tactic])
        def value(tech, ind):
            try:
                tactic_technique_dict[tech][ind]
                return tactic_technique_dict[tech][ind]
            except:
                return " "
                pass
        matrix = []
        for i in range(max_values):
            object = {
                'Persistence': value('Persistence', i),
                'Privilege Escalation': value('Privilege Escalation', i),
                'Defense Evasion': value('Defense Evasion', i),
                'Credential Access': value('Credential Access', i),
                'Discovery': value('Discovery', i),
                'Lateral Movement': value('Lateral Movement', i),
                'Execution': value('Execution', i),
                'Collection': value('Collection', i),
                'Exfiltration': value('Exfiltration', i),
                'Command and Control': value('Command and Control', i)
            }
            matrix.append(object)
        return matrix

    def get_attribution(self):
        attri_bucket = []
        attri_final = []
        groups = self.get_all_groups()
        techniques = self.get_all_techniques()
        techsubobjects = self.get_all_subobjects()
        for g in groups:
            for grt in g['Software']:
                for x in techsubobjects:
                    if grt in x['Display Title']:
                        object = {
                            'Group': g['Name'],
                            'Group Alias': g['Alias'],
                            'Group ID': g['ID'],
                            'Software': grt,
                            'Technique Name': x['Technique Name'],
                            'Technique ID': x['Technique ID'],
                            'Description': x['Description']
                        }
                        attri_bucket.append(object)
            for y in techsubobjects:
                if y['Display Title'] == g['Display Title']:
                    object = {
                        'Group': g['Name'],
                        'Group Alias': g['Alias'],
                        'Group ID': g['ID'],
                        'Software': [],
                        'Technique Name': y['Technique Name'],
                        'Technique ID': y['Technique ID'],
                        'Description': y['Description']
                    }
                    attri_bucket.append(object)
        for t in techniques:
            for a in attri_bucket:
                if t['Full Text'] in a['Technique ID']:
                    object = {
                        'Group': a['Group'],
                        'Group Alias': a['Group Alias'],
                        'Group ID': a['Group ID'],
                        'Software': a['Software'],
                        'Tactic': t['Tactic'],
                        'Technique Name': a['Technique Name'],
                        'Technique ID': a['Technique ID'],
                        'Description': a['Description'],
                        'Data Source': t['Data Source']
                    }
                    attri_final.append(object)
        return attri_final

    def get_all(self):
        attack_all = []
        attribution = self.get_attribution()
        techniques = self.get_all_techniques()
        for t in techniques:
            for a in attribution:
                if t['Full Text'] in a['Technique ID']:
                    object = {
                        'Group': a['Group'],
                        'Group Alias': a['Group Alias'],
                        'Group ID': a['Group ID'],
                        'Tactic': a['Tactic'],
                        'Software': a['Software'],
                        'Technique Name': a['Technique Name'],
                        'Technique ID': a['Technique ID'],
                        'Description': a['Description'],
                        'Data Source': a['Data Source'],
                        'Bypass': t['Bypass'],
                        'Analytic Details': t['Analytic Details'],
                        'Mitigation': t['Mitigation'],
                        'Platform': t['Platform'],
                        'Requires Permissions': t['Requires Permissions'],
                        'Requires System': t['Requires System'],
                        'CAPEC ID': t['CAPEC ID'],
                        'Contributor': t['Contributor'],
                        'URL': t['URL']
                    }
                    attack_all.append(object)
        for x in techniques:
            object = {
                'Group': [],
                'Group Alias': [],
                'Group ID': [],
                'Software': [],
                'Tactic': x['Tactic'],
                'Technique Name': x['Technique Name'],
                'Technique ID': x['Full Text'],
                'Description': x['Technical Description'],
                'Data Source': x['Data Source'],
                'Bypass': x['Bypass'],
                'Analytic Details': x['Analytic Details'],
                'Mitigation': x['Mitigation'],
                'Platform': x['Platform'],
                'Requires Permissions': x['Requires Permissions'],
                'Requires System': x['Requires System'],
                'CAPEC ID': x['CAPEC ID'],
                'Contributor': x['Contributor'],
                'URL': x['URL']
            }
            attack_all.append(object)
        return attack_all
