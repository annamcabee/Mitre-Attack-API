#!/usr/bin/env python

from setuptools import setup

setup(
    name='mitreapi',
    version='1.1',
    description='MITRE Attack API',
    author=['Anna McAbee','Roberto Rodriguez'],
    author_email=['annamcabee@gmail.com','rrodri0622@gmail.com'],
    url='https://github.com/annamcabee/Mitre-Attack-API',
    packages=['mitreapi'],
    install_requires=['simplejson', 'requests']
)