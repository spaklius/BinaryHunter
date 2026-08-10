import re

with open('BinaryHunter.Core/Identification/Detectors/AutomaticDetectorRegistry.cs', 'r') as f:
    registry = f.read()

with open('BinaryHunter.UI/Services/SupportedEcuCatalog.cs', 'r') as f:
    catalog = f.read()

detector_names = re.findall(r'new (\w+Detector)\(\)', registry)
catalog_keys = set(re.findall(r'\[\"([^\"]+)\"\] = new', catalog))

# Map detector class names to likely catalog keys
def class_to_key(class_name):
    # Remove 'Detector' suffix
    name = class_name.replace('Detector', '')
    # Handle special cases
    if name == 'BoschMebMd1Cp001':
        return 'Bosch Mercedes-Benz MD1CP001'
    if name == 'DensoSubaruSh705x':
        return 'Denso Subaru SH705x'
    if name == 'ContinentalVagSimosPpd15':
        return 'Continental VAG SIMOS PPD1.x'
    # Generic conversion: insert spaces before capitals, handle acronyms
    name = re.sub(r'([a-z])([A-Z])', r'\1 \2', name)
    name = re.sub(r'([A-Z])([A-Z][a-z])', r'\1 \2', name)
    return name

missing = []
for det in detector_names:
    key = class_to_key(det)
    if key not in catalog_keys:
        missing.append((det, key))

print(f'Total detectors: {len(detector_names)}')
print(f'Missing catalog entries: {len(missing)}')
for det, key in missing:
    print(f'  {det} -> "{key}"')
