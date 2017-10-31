#!/usr/bin/env python

from distutils.core import setup

setup(
    name='mitre',
    version='1.0',
    description='MITRE Attack API',
    author=['Anna McAbee','Roberto Rodriguez'],
    author_email=['annamcabee@gmail.com','rrodri0622@gmail.com'],
    url='https://github.com/annamcabee/Mitre-Attack-API',
    download_url='https://github.com/annamcabee/Mitre-Attack-API/tarball/1.0.0',
    py_modules=['mitre'],
    install_requires=['json', 'requests', 'pandas']
)