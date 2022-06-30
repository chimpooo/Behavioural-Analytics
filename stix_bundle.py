from stix2 import Bundle,Malware,Indicator,Relationship, AttackPattern, Campaign, Identity, ThreatActor
from stix2 import Report
from stix2 import DomainName, File, IPv4Address
'''from stix2 import (ObjectPath, EqualityComparisonExpression, ObservationExpression,
                   GreaterThanComparisonExpression, IsSubsetComparisonExpression,
                   FloatConstant, StringConstant)'''
#import misp_analysis
#get the stix format for Sodinokibi with its details
MALWARE_ID='Sodinokibi'
has="'d41d8cd98f00b204e9800998ecf8427e'"
pattern= "[file:hashes.md5 ="
pattern_enclose="]"
pattern_value=pattern+has+pattern_enclose
threat_actor= ThreatActor(name='Pinchy Spider', threat_actor_types='ransomware as a service')

malware = Malware(name="Sodinokibi", malware_types=['ransomware'], is_family=False)
file_hash = Indicator(name="File hash for Sodinokibi",
                      pattern=pattern_value,
                      pattern_type="stix"
                      )
domainname = Indicator(name="DomainName for Sodinokibi", 
                    pattern="[domain-name:value = 'www.1test.es']", 
                    pattern_type="stix")

relationship = Relationship(file_hash, 'File Hash', malware)

g1=[AttackPattern(name="Ransomware",external_references=[{"url":"https://ncuccr.org","source_name":"some-source2",},],),
Campaign(name=""),
Identity(name="John Smith",identity_class="group",description="Ransomware as a service",),
Indicator(indicator_types=['malicious-activity'],pattern_type="stix",pattern="[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",valid_from="2021-01-01T12:34:56Z",),
malware,
ThreatActor(id=threat_actor.id,threat_actor_types=["crime-syndicate"],name="Pinchy Spider",aliases=["REvil"],),
Relationship(source_ref=threat_actor.id,target_ref=malware.id,relationship_type="uses",),
Report(report_types=["campaign"],name="Ransomware",published="2019-04-06T20:03:00.000Z",object_refs=[threat_actor.id,malware.id],),]
bundle = Bundle(g1)

#AND domain-name:resolvess_to_refs[*].value = "'198.51.100.1/32'"]",
 
#print(Indicator2.serialize(pretty=True))

#json
'''indicator1 = parse("""{
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--dbcbd659-c927-4f9a-994f-0a2632274394",
    "created": "2022-06-26T23:33:39.829Z",
    "modified": "2022-06-26T23:33:39.829Z",
    "name": "Sodinokibi",
    "indicator_types": [
        "malicious-activity"
    ],
    "pattern_type": "stix",
    "pattern_version": "2.1",
    "pattern": "[file:hashes.md5 ='d41d8cd98f00b204e9800998ecf8427e']",
    "valid_from": "2022-06-26T23:33:39.829952Z"
}""")'''

if __name__ == '__main__':
    #print(Indicator2.serialize(pretty=True))
    print(bundle.serialize(pretty=True))
