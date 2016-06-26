#!/usr/bin/env python

"""
Setup file for pygeoip package.

@author: Jennifer Ennis <zaylea at gmail dot com>

@license:
Copyright(C) 2004 MaxMind LLC

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/lgpl.txt>.
"""

try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

setup(name='pygeoip',
      version='0.1.3',
      description='Pure Python GeoIP API',
      author='Jennifer Ennis',
      author_email='zaylea@gmail.com',
      url='http://code.google.com/p/pygeoip/',
      packages=find_packages(exclude=['tests','test_*','data','apidocs']),
      license='LGPL',
      keywords='geoip')