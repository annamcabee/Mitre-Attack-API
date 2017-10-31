# Mitre-Attack-API
Python library to interact with the MITRE attack framework via the MITRE API

# About
The MITRE Attack API python project provides a way for people to easily access data from the MITRE attack framework. With this project, you can manipulate data provided by the MITRE API. The "AttackAPI" object has the following methods:
- get_all_techniques()
- get_all_groups()
- get_all_software()
- get_all_subobjects()
- get_matrix()
- get_attribution()
- get_all()


# Installation
1. Clone this repo
2. From the root directory of the repo, run #code python setup.py install
3. Integrate with your code

# Examples
Examples
from mitre import AttackAPI
attack = AttackAPI()
