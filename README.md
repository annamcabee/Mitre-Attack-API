# Mitre-Attack-API
Python module to interact with the MITRE attack framework

# About
The MITRE Attack API python module provides a way for people to easily access data from the MITRE attack framework. With this module, you can manipulate data provided by the MITRE API. The "AttackAPI" object has the following methods:

| Method        | Method Details           | 
| ------------- |-------------| 
| get_all_techniques()      | Returns a list of dictionaries with each dictionary representing a technique and its important attributes | 
| get_all_groups()      | Returns a list of dictionaries with each dictionary representing a group and its important attributes      | 
| get_all_software() | Returns a list of dictionaries with each dictionary representing a software/tool and its important attributes      | 
| get_all_subobjects()      | Returns a list of dictionaries with each dictionary representing a technique subobject and its important attributes      | 
| get_matrix() | Returns a double array with each tactic and their corresponding techniques      | 
| get_attribution() | Returns a list of dictionaries with each dictionary representing a group with details on the software and techniques used by that group     | 
| get_all() | Returns a list of dictionaries with a lot of the information above in a flat format, including all of the attribution data, as well as the technique data       | 

** Note: You can see all of the above methods in use in the "Examples" section.

# Installation
If you have pip installed, run `pip install mitreapi`

Otherwise:
1. Clone this repo
2. Run `python setup.py install` in the root of the cloned repo directory

# Integrating with your Code
1. Integrate with your code through  `from mitreapi import AttackAPI`
2. The easiest way to use this package is with the pandas module, so if you dont have that run `pip install pandas`
3. Below is a trivial example of integration, look at the examples section for more information
```
from mitreapi import AttackAPI
from pandas import *
from pandas.io.json import json_normalize

attack = AttackAPI()
techniques = attack.get_all_techniques()
groups = attack.get_all_groups()
```
# Examples
[Jupyter Notebook Example](Examples.ipynb)
