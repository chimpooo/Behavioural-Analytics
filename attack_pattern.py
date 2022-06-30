#Similarity between attack patterns calculated using STIX
from stix2 import AttackPattern, Environment, MemoryStore

env = Environment(store=MemoryStore())

ap1 = AttackPattern(
    name="Spear phising",
    external_references=[
        {
            "url": "https://ncuccr.org",
            "source_name": "virustotal",
        },
    ],
)
ap2 = AttackPattern(
    name="Spear phishing",
    external_references=[
        {
            "url": "https://1team.es",
            "source_name": "alien-vault",
        },
    ],
)
print(env.object_similarity(ap1, ap2))
print(env.object_equivalence(ap1, ap2, threshold=90))
print(env)
