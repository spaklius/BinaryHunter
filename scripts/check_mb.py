import re
with open('BinaryHunter.UI/Services/SupportedEcuCatalog.cs', 'r') as f:
    content = f.read()
keys = re.findall(r'\[\"([^\"]+)\"\] = new', content)
for k in sorted(keys):
    if 'Meb' in k or 'CP31' in k or 'CP36' in k or 'MD1' in k:
        print(k)
