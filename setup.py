#!/usr/bin/env python

from setuptools import setup

setup(
    name='mitreapi',
    version='1.2',
    description='MITRE Attack API',
    author=['Anna McAbee', 'Roberto Rodriguez'],
    author_email=['annamcabee@gmail.com', 'rrodri0622@gmail.com'],
    url='https://github.com/annamcabee/Mitre-Attack-API',
    packages=['mitreapi'],
    install_requires=['simplejson', 'requests'],
    classifiers=[
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3'
    ],
    keywords='MITRE Attack API'
)
