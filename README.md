# Mitre-Attack-API
Python library to interact with the MITRE attack framework via the MITRE API

# About
The MITRE Attack API python project provides a way for people to easily access data from the MITRE attack framework. With this project, you can manipulate data provided by the MITRE API. The "AttackAPI" object has the following methods:

| Method        | Method Details           | 
| ------------- |-------------| 
| get_all_techniques()      | Returns a list of dictionaries with each dictionary representing a technique and its important attributes | 
| get_all_groups()      | Returns a list of dictionaries with each dictionary representing a group and its important attributes      | 
| get_all_software() | Returns a list of dictionaries with each dictionary representing a software/tool and its important attributes      | 
| get_all_subobjects()      | Returns a list of dictionaries with each dictionary representing a technique subobject and its important attributes      | 
| get_matrix() | Returns a dictionary where the keys are tactics and the values are a list techniques under that tactic      | 
| get_attribution() | Returns a list of dictionaries with each dictionary representing a group with details on the software and techniques used by that group     | 
| get_all() | Returns a a list of dictionaries with a lot of the information above in a flat format, including all of the attribution data, as well as the technique data       | 

# Installation
1. Clone this repo
2. From the root directory of the repo, run `python setup.py install`
3. Integrate with your code

# Examples
`from mitre import AttackAPI
attack = AttackAPI()`
