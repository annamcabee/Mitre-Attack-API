# Mitre-Attack-API
Python library to interact with the MITRE attack framework via the MITRE API

# About
The MITRE Attack API python project provides a way for people to easily access data from the MITRE attack framework. With this project, you can manipulate data provided by the MITRE API. The "AttackAPI" object has the following methods:

| Method        | Method Details           | 
| ------------- |:-------------:| 
| get_all_techniques()      | right-aligned | 
| get_all_groups()      | centered      | 
| get_all_software() | are neat      | 
| get_all_subobjects()      | centered      | 
| get_matrix() | are neat      | 
| get_attribution() | are neat      | 
| get_all() | are neat      | 

# Installation
1. Clone this repo
2. From the root directory of the repo, run `python setup.py install`
3. Integrate with your code

# Examples
Examples
`from mitre import AttackAPI

attack = AttackAPI()`
