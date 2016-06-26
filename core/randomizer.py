#!/usr/bin/env python2.7
#coding=UTF-8

# Copyright (c) 2016 m4n3dw0lf
#
# This file is part of the program Jarvis
#
# Jarvis is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA


import sqlite3
import random


class Randomstorm(object):

        def __init__(self):
                self.numbers = []
                self.con = sqlite3.connect('config/Jarbas.db');

        def random(self,arg):
                with self.con:
                        self.cur = self.con.cursor()
                        cont = self.cur.execute("SELECT max(id) FROM {}".format(arg))
                        cont = self.cur.fetchone()
                        for i in range(1,cont[0]+1):
                                self.numbers.append(i)
                        self.cur.execute("SELECT * FROM {} where id = {} limit 1".format(arg,random.choice(self.numbers)))
                        id,msg = self.cur.fetchone()
                        return msg


