#!/usr/bin/python
__author__ = 'Brandon Dixon'
__email__ = 'brandon.s.dixon@gmail.com'
__website__= 'http://www.dueyesterday.net'
__date__ = '12/21/08'
__version__ = '1'

import openCVSS

myCVSS = openCVSS.openCVSS()
myCVSS.info()
#myCVSS.scores("local", "medium", "multiple instance", "partial", "partial", "complete", "not defined", "not defined", "not defined", "low", "high", "medium", "medium", "medium")
#myCVSS.vector("AV:L/AC:M/Au:M/C:P/I:P/A:C/CDP:L/TD:H/CR:M/IR:M/AR:M")
myCVSS.calculate()
myCVSS.displayResults()
