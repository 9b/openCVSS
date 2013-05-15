#!/usr/bin/python
__author__ = 'Brandon Dixon'
__email__ = 'brandon.s.dixon@gmail.com'
__website__= 'http://www.dueyesterday.net'
__date__ = '12/21/08'
__version__ = '1.3'

"""
 * SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * EXPRESSLY DISCLAIMED. IN NO EVENT SHALL THE CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, 
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, 
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 * POSSIBILITY OF SUCH DAMAGE.
"""

"""Common Vulnerability Scoring System Version 2 Calculator"""

class Struct:
	"""
	Allows for the creations of enums	
	Thanks to norvig.com/python-iaq.html
	"""

	def __init__(self, **entries): self.__dict__.update(entries)

class openCVSS:
	"""
	openCVSS class consisting of 2 core functions
	1 function will take all the arguments in and the other will calculate the score based on those arguments
	"""
	
	def __init__(self):
		"""Define the global variables and create enums to store variables in a clean fashion"""	

		#Define globals to use later on
		global accessVectorValues	
		global accessComplexityValues
		global authenticationValues
		global confidentialityImpactValues
		global integrityImpactValues
		global availabilityImpactValues
		global exploitabilityValues
		global remediationLevelValues
		global reportConfidenceValues
		global collateralDamageValues
		global targetDistributionValues
		global confidentialityRequirementValues
		global integrityRequirementValues
		global availabilityRequirementValues
		global badVar

		#Exception variables
		badVar = str("Variable entered is incorrect")
	
		#Organize values into enums for easy adjusting.
		enum = Struct
		accessVectorValues = enum(local=float(0.395), adjacent_network=float(0.646), network=float(1.0))
		accessComplexityValues = enum(high=float(0.35), medium=float(0.61), low=float(0.71))
		authenticationValues = enum(none=float(0.704), single_instance=float(0.56), multiple_instance=float(0.45))
		confidentialityImpactValues = enum(none=float(0.0), partial=float(0.275), complete=float(0.660))
		integrityImpactValues = enum(none=float(0.0), partial=float(0.275), complete=float(0.660))
		availabilityImpactValues = enum(none=float(0.0), partial=float(0.275), complete=float(0.660))
		exploitabilityValues = enum(unproven=float(0.85), proof_of_concept=float(0.9), functional=float(0.95), high=float(1.0), not_defined=float(1.0))
		remediationLevelValues = enum(official_fix=float(0.87), temporary_fix=float(0.90), workaround=float(0.95), unavailable=float(1.00), not_defined=float(1.00))
		reportConfidenceValues = enum(unconfirmed=float(0.90), uncorroborated=float(0.95), confirmed=float(1.00), not_defined=float(1.00))
		collateralDamageValues = enum(none=float(0), low=float(0.1), low_medium=float(0.3), medium_high=float(0.4), high=float(0.5), not_defined=float(0))
		targetDistributionValues = enum(none=float(0), low=float(0.25), medium=float(0.75), high=float(1.00), not_defined=float(1.00))
		confidentialityRequirementValues = enum(low=float(0.5), medium=float(1), high=float(1.51), not_defined=float(1))
		integrityRequirementValues = enum(low=float(0.5), medium=float(1), high=float(1.51), not_defined=float(1))		
		availabilityRequirementValues = enum(low=float(0.5), medium=float(1), high=float(1.51), not_defined=float(1))

        #SETs and GETs
	def setAV(self, AV):
		"""set AV to a value or throw exception"""
		if AV == "local" or AV == "L":
			self.accessVector = accessVectorValues.local
		elif AV == "adjacent network" or AV == "A":
			self.accessVector = accessVectorValues.adjacent_network
		elif AV == "network" or AV == "N":
			self.accessVector = accessVectorValues.network
		else:
			raise Exception, badVar

	def getAV(self):
		"""get AV value"""
		return self.accessVector

	def setAC(self, AC):
		"""set AC to a value or throw exception"""
		if AC == "high" or AC == "H":
			self.accessComplexity = accessComplexityValues.high
		elif AC == "medium" or AC == "M":
			self.accessComplexity = accessComplexityValues.medium
		elif AC == "low" or AC == "L":
			self.accessComplexity = accessComplexityValues.low
		else:
			raise Exception, badVar

	def getAC(self):
		"""get AC value"""
		return self.accessComplexity

	def setAU(self, AU):
		"""set AU to a value or throw exception"""
		if AU == "none" or AU == "N":
			self.authentication = authenticationValues.none
		elif AU == "single instance" or AU == "S":
			self.authentication = authenticationValues.single_instance
		elif AU == "multiple instance" or AU == "M":
			self.authentication = authenticationValues.multiple_instance
		else:
			raise Exception, badVar

	def getAU(self):
		"""get AU value"""
		return self.authentication

	def setCI(self, CI):
		"""set CI to a value or throw exception"""
		if CI == "none" or CI == "N":
			self.confImpact = confidentialityImpactValues.none
		elif CI == "partial" or CI == "P":
			self.confImpact = confidentialityImpactValues.partial
		elif CI == "complete" or CI == "C":
			self.confImpact = confidentialityImpactValues.complete
		else:
			raise Exception, badVar

	def getCI(self):
		"""get CI value"""
		return self.confImpact

	def setII(self, II):
		"""set II to a value or throw exception"""
		if II == "none" or II == "N":
			self.integImpact = integrityImpactValues.none
		elif II == "partial" or II == "P":
			self.integImpact = integrityImpactValues.partial
		elif II == "complete" or II == "C":
			self.integImpact = integrityImpactValues.complete
		else:
			raise Exception, badVar

	def getII(self):
		"""get II value"""
		return self.integImpact

	def setAI(self, AI):
		"""set AI to a value or throw exception"""
		if AI == "none" or AI == "N":
			self.availImpact = availabilityImpactValues.none
		elif AI == "partial" or AI == "P":
			self.availImpact = availabilityImpactValues.partial
		elif AI == "complete" or AI == "C":
			self.availImpact = availabilityImpactValues.complete
		else:
			raise Exception, badVar

	def getAI(self):
		"""get AI value"""
		return self.availImpact

	def setEX(self, EX):
		"""set EX to a value"""
		if EX == "unproven" or EX == "U":
			self.exploitability = exploitabilityValues.unproven
		elif EX == "proof-of-concept" or EX == "P":
			self.exploitability = exploitabilityValues.proof_of_concept
		elif EX == "functional" or EX == "F":
			self.exploitability = exploitabilityValues.functional
		elif EX == "high" or EX == "H":
			self.exploitability = exploitabilityValues.high
		elif EX == "undefined":
			self.exploitability = float(0)
		else:
			self.exploitability = exploitabilityValues.not_defined

	def getEX(self):
		"""get EX value"""
		return self.exploitability

	def setRL(self, RL):
		"""set RL to a value"""
		if RL == "official-fix" or RL == "O":
			self.remediationLevel = remediationLevelValues.official_fix
		elif RL == "temporary-fix" or RL == "T":
			self.remediationLevel = remediationLevelValues.temporary_fix
		elif RL == "workaround" or RL == "W":
			self.remediationLevel = remediationLevelValues.workaround
		elif RL == "unavailable" or RL == "U":
			self.remediationLevel = remediationLevelValues.unavailable
		elif RL == "undefined":
			self.remediationLevel = float(0)
		else:
			self.remediationLevel = remediationLevelValues.not_defined

	def getRL(self):
		"""get RL value"""
		return self.remediationLevel

	def setRC(self, RC):
		"""set RC to a value"""
		if RC == "unconfirmed" or RC == "UC":
			self.reportConfidence = reportConfidenceValues.unconfirmed
		elif RC == "uncorroborated" or RC == "UR":
			self.reportConfidence = reportConfidenceValues.uncorroborated
		elif RC == "confirmed" or RC == "C":
			self.reportConfidence = reportConfidenceValues.confirmed
		elif RC == "undefined":
			self.reportConfidence = float(0)
		else:
			self.reportConfidence = reportConfidenceValues.not_defined

	def getRC(self):
		"""get RC value"""
		return self.reportConfidence

	def setCD(self, CD):
		"""set CD to a value"""
		if CD == "none" or CD == "N":
			self.collateralDamage = collateralDamageValues.none
		elif CD == "low" or CD == "L":
			self.collateralDamage = collateralDamageValues.low
		elif CD == "low-medium" or CD == "LM":
			self.collateralDamage = collateralDamageValues.low_medium
		elif CD == "medium-high" or CD == "MH":
			self.collateralDamage = collateralDamageValues.medium_high
		elif CD == "high" or CD == "H":
			self.collateralDamage = collateralDamageValues.high
		elif CD == "undefined":
			self.collateralDamage = float(0)
		else:
			self.collateralDamage = collateralDamageValues.not_defined

	def getCD(self):
		"""get CD value"""
		return self.collateralDamage

	def setTD(self, TD):
		"""set TD to a value"""
		if TD == "none" or TD == "N":
			self.targetDist = targetDistributionValues.none
		elif TD == "low" or TD == "L":
			self.targetDist = targetDistributionValues.low
		elif TD == "medium" or TD == "M":
			self.targetDist = targetDistributionValues.medium
		elif TD == "high" or TD == "H":
			self.targetDist = targetDistributionValues.high
		elif TD == "undefined":
			self.targetDist = float(0)
		else:
			self.targetDist = targetDistributionValues.not_defined

	def getTD(self):
		"""get TD value"""
		return self.targetDist

	def setCR(self, CR):
		"""set CR to a value"""
		if CR == "low" or CR == "L":
			self.confReq = confidentialityRequirementValues.low
		elif CR == "medium" or CR == "M":
			self.confReq = confidentialityRequirementValues.medium
		elif CR == "high" or CR == "H":
			self.confReq = confidentialityRequirementValues.high
		elif CR == "undefined":
			self.confReq = float(0)
		else:
			self.confReq = confidentialityRequirementValues.not_defined

	def getCR(self):
		"""get CR value"""
		return self.confReq

	def setIR(self, IR):
		"""set IR to a value"""
		if IR == "low" or IR == "L":
			self.integReq = integrityRequirementValues.low
		elif IR == "medium" or IR == "M":
			self.integReq = integrityRequirementValues.medium
		elif IR == "high" or IR == "H":
			self.integReq = integrityRequirementValues.high
		elif IR == "undefined":
			self.integReq = float(0)
		else:
			self.integReq = integrityRequirementValues.not_defined

	def getIR(self):
		"""get IR value"""
		return self.integReq

	def setAR(self, AR):
		"""set AR to a value"""
		if AR == "low" or AR == "L":
			self.availReq = availabilityRequirementValues.low
		elif AR == "medium" or AR == "M":
			self.availReq = availabilityRequirementValues.medium
		elif AR == "high" or AR ==  "H":
			self.availReq = availabilityRequirementValues.high
		elif AR == "undefined":
			self.availReq = float(0)
		else:
			self.availReq = availabilityRequirementValues.not_defined

	def getAR(self):
		"""get AR value"""
		return self.availReq


	def setBaseScore(self, baseScoreCalculated):
		"""set BaseScore value"""
		self.baseScoreResult = baseScoreCalculated
	def getBaseScore(self):
		"""get BaseScore value"""
		return self.baseScoreResult

	def setImpactScore(self, impactScoreCalculated):
		"""set ImpactScore value"""
		self.impactScoreResult = impactScoreCalculated
	def getImpactScore(self):
		"""get ImpactScore value"""
		return self.impactScoreResult

	def setExploitabilityScore(self, exploitabilityScoreCalculated):
		"""set ExploitabilityScore value"""
		self.exploitabilityScoreResult = exploitabilityScoreCalculated
	def getExploitabilityScore(self):
		"""get ExploitabilityScore value"""
		return self.exploitabilityScoreResult

	def setTemporalScore(self, temporalScoreCalculated):
		"""set TemporalScore value"""
		self.temporalScoreResult = temporalScoreCalculated
	def getTemporalScore(self):
		"""get TemporalScore value"""
		return self.temporalScoreResult

	def setEnviromentalScore(self, enviromentalScoreCalculated):
		"""set EnviromentalScore value"""
		self.enviromentalScoreResult = enviromentalScoreCalculated
	def getEnviromentalScore(self):
		"""get EnviromentalScore value"""
		return self.enviromentalScoreResult

	def setAdjustedBaseScore(self, adjustedBaseScoreCalculated):
		"""set AdjustedBaseScore value"""
		self.adjustedBaseScoreResult = adjustedBaseScoreCalculated
	def getAdjustedBaseScore(self):
		"""get AdjustedBaseScore value"""
		return self.adjustedBaseScoreResult

	def setAdjustedImpactScore(self, adjustedImpactScoreCalculated):
		"""set AdjustedImpactScore value"""
		self.adjustedImpactScoreResult = adjustedImpactScoreCalculated
	def getAdjustedImpactScore(self):
		"""get AdjustedImpactScore value"""
		return self.adjustedImpactScoreResult

	def setAdjustedTemporalScore(self, adjustedTemporalScoreCalculated):
		"""set AdjustedTemporalScore value"""
		self.adjustedTemporalScoreResult = adjustedTemporalScoreCalculated
	def getAdjustedTemporalScore(self):
		"""get AdjustedTemporalScore value"""
		return self.adjustedTemporalScoreResult

	#Score Function
	def scores(self, AV, AC, AU, CI, II, AI, EX, RL, RC, CD, TD, CR, IR, AR):
		"""scores takes in 14 arguments representing several aspects of what make up a CVSS score"""	
		self.setAV(AV)
		self.setAC(AC)
		self.setAU(AU)
		self.setCI(CI)
		self.setII(II)
		self.setAI(AI)

		#Some values do not need to be defined, therefore check to see their values, if not defined then no need to show a score at the end
		if (EX == "not defined") and (RL == "not defined") and (RC == "not defined") or (EX == "ND") and (RL == "ND") and (RC == "ND"):
                        #no need to calulatate when nothing has been defined
			self.setEX("undefined")
			self.setRL("undefined")
			self.setRC("undefined")
		else:
			self.setEX(EX)
			self.setRL(RL)
			self.setRC(RC)

		#Some values do not need to be defined, therefore check to see their values, if not defined then no need to show a score at the end
		if (CD == "not defined") and (TD == "not defined") and (CR == "not defined") and (IR == "not defined") and (AR == "not defined") or (CD == "ND") and (TD == "ND") and (CR == "ND") and (IR == "ND") and (AR == "ND"):
                        #no need to calulatate when nothing has been defined
			self.setCD("undefined")
			self.setTD("undefined")
			self.setCR("undefined")
			self.setIR("undefined")
			self.setAR("undefined")
		else:
			self.setCD(CD)
			self.setTD(TD)
			self.setCR(CR)
			self.setIR(IR)
			self.setAR(AR)

	#Calculate Functions
	def calculate(self):
		"""
		Calculate all the values that were defined in the scores function
		Calculations are made based on the latest CVSS scores.
		http://nvd.nist.gov/cvsseq2.htm
		"""
		self.calcImpactScore()
		self.calcExploitabilityScore()
		self.calcBaseScore()
		self.calcTemporalScore()
		self.calcEnviromentalScore()

	def calcBaseScore(self):
		"""
                Calculates the BaseScore and then calls setBaseScore
                BaseScore = (.6*Impact +.4*Exploitability-1.5)*f(Impact)
		"""
		AV = self.getAV()
		AC = self.getAC()
		AU = self.getAU()
		
		impactScoreResult = self.getImpactScore()
		exploitabilityScoreResult = self.getExploitabilityScore()
		impacter = self.decideImpacter(impactScoreResult)

		baseScoreCalculated = round(float((.6*impactScoreResult +.4*exploitabilityScoreResult-1.5)*impacter),1)		
		self.setBaseScore(baseScoreCalculated)

	def calcImpactScore(self):
		"""
                Calculates the ImpactScore and then calls setImpactScore
                Impact = 10.41*(1-(1-ConfImpact)(1-IntegImpact)*(1-AvailImpact))
		"""
		CI = self.getCI()
		II = self.getII()
		AI = self.getAI()
		
		impactScoreCalculated = round(float(10.41*(1-(1-CI)*(1-II)*(1-AI))),1)
		self.setImpactScore(impactScoreCalculated)

	def calcExploitabilityScore(self):
		"""
                Calculates the ExploitabilityScore and then calls setExploitabilityScore
                Exploitability = 20*AccessComplexity*Authentication*AccessVector
		"""
		AV = self.getAV()
		AC = self.getAC()
		AU = self.getAU()
		
		exploitabilityScoreCalculated = round(float(20*AV*AC*AU),1)
		self.setExploitabilityScore(exploitabilityScoreCalculated)

	def calcTemporalScore(self):
		"""
                Calculates the TemporalScore and then calls setTemporalScore
                TemporalScore=BaseScore*Exploitability*RemediationLevel*ReportConfidence
		"""
		EX = self.getEX()
		RL = self.getRL()
		RC = self.getRC()

		baseScoreResult = self.getBaseScore()
		
		temporalScoreCalculated = round(float(baseScoreResult*EX*RL*RC),1)

		if temporalScoreCalculated == 0:
			temporalScoreCalculated = "Undefined"
		self.setTemporalScore(temporalScoreCalculated)

	def calcEnviromentalScore(self):
		"""
                Calculates the EnviromentalScore by calling several "adjusted" functions
                After calculation setEnviromentalScore is called
                EnvironmentalScore=(AdjustedTemporal+(10-AdjustedTemporal)*CollateralDamagePotential) * TargetDistribution
		"""
		CD = self.getCD()
		TD = self.getTD()
		
		self.calcAdjustedImpactScore() #impact first
		self.calcAdjustedBaseScore() #base second (exploitability does not change)
		self.calcAdjustedTemporalScore() #temporal third

		adjustedTemporalScoreResult = self.getAdjustedTemporalScore()
		
		enviromentalScoreCalculated = round(float((adjustedTemporalScoreResult+(10-adjustedTemporalScoreResult)*CD) * TD),1)
		if enviromentalScoreCalculated == 0:
			enviromentalScoreCalculated = "Undefined"
		self.setEnviromentalScore(enviromentalScoreCalculated)

	def calcAdjustedBaseScore(self):
		"""
                Calculates the AdjustedBaseScore and then calls setAdjustedBaseScore
		"""
		adjustedImpactScoreResult = self.getAdjustedImpactScore()
		exploitabilityScoreResult = self.getExploitabilityScore()
		impacter = self.decideImpacter(adjustedImpactScoreResult)

		adjustedBaseScoreCalculated = round(float((.6*adjustedImpactScoreResult +.4*exploitabilityScoreResult-1.5)*impacter),1)
		self.setAdjustedBaseScore(adjustedBaseScoreCalculated)

	def calcAdjustedImpactScore(self):
		"""
                Calculates the AdjustedImpactScore and then calls setAdjustedImpactScore
                AdjustedImpact = Min(10, 10.41*(1-(1-ConfImpact*ConfReq)*(1-IntegImpact*IntegReq)*(1-AvailImpact*AvailReq)))
		"""
		CI = self.getCI()
		II = self.getII()
		AI = self.getAI()
		CR = self.getCR()
		IR = self.getIR()
		AR = self.getAR()
		
		adjustedImpactScoreCalculated = round(float(min(10, 10.41*(1-(1-CI*CR)*(1-II*IR)*(1-AI*AR)))),1)
		self.setAdjustedImpactScore(adjustedImpactScoreCalculated)

	def calcAdjustedTemporalScore(self):
		"""
                Calculates the AdjustedTemporalScore and then calls setAdjustedTemporalScore
                AdjustedTemporal = TemporalScore recomputed with the Impact sub-equation replaced with the following AdjustedImpact equation.
		"""
		EX = self.getEX()
		RL = self.getRL()
		RC = self.getRC()

		adjustedBaseScoreResult = self.getBaseScore()
		
		adjustedTemporalScoreCalculated = round(float(adjustedBaseScoreResult*EX*RL*RC),1)
		self.setAdjustedTemporalScore(adjustedTemporalScoreCalculated)

	def decideImpacter(self, anyImpactScore):
		"""
                Decide what the impacter is based on the incoming impact score, then return.
                Mimics - f(Impact) = 0 if Impact=0; 1.176 otherwise
		"""
		if anyImpactScore == "0":
			impacter = float(0)
		else:
			impacter = float(1.176)

		return impacter

	#Display Functions
	def info(self):
		"""Print a banner on the top of the screen. Functions as nothing more than an add-on"""

		print "Common Vulnerability Scoring System Version 2 Calculator"
		print ">>------------------------> http://nvd.nist.gov/cvss.cfm"

	def displayResults(self):
		"""Print the results from the calculations"""
		baseScore = self.getBaseScore()
		impactScore = self.getImpactScore()
		exploitabilityScore = self.getExploitabilityScore()
		temporalScore = self.getTemporalScore()
		enviromentalScore = self.getEnviromentalScore()
		adjustedImpactScore = self.getAdjustedImpactScore()
		
		print "Base Score:", baseScore
		print "Impact Score:", impactScore
		print "Exploitability Score:", exploitabilityScore
		print "Temporal Score:", temporalScore
		print "Enviromental Score:", enviromentalScore
		if enviromentalScore != "Undefined":
			print "Modified Impact Score:", adjustedImpactScore

	def vector(self, string):
		"""Take in the vector string and pass it to the parse function"""
		self.parseVector(string)

	def parseVector(self, string):
		"""Take in vector string, parse and separate into variables. Call existing score method"""
		string = string.split('/')
		length = str(len(string))

		if length == "9":	#Base and Temp were defined
			AV = str(string[0]).partition(':')[2]
			AC = str(string[1]).partition(':')[2]
			AU = str(string[2]).partition(':')[2]
			CI = str(string[3]).partition(':')[2]
			II = str(string[4]).partition(':')[2]
			AI = str(string[5]).partition(':')[2]
			EX = str(string[6]).partition(':')[2]
			RL = str(string[7]).partition(':')[2]
			RC = str(string[8]).partition(':')[2]

			self.scores(AV, AC, AU, CI, II, AI, EX, RL, RC, "ND", "ND", "ND", "ND", "ND")
                        
		elif length == "11": #Base and Env were defined
			AV = str(string[0]).partition(':')[2]
			AC = str(string[1]).partition(':')[2]
			AU = str(string[2]).partition(':')[2]
			CI = str(string[3]).partition(':')[2]
			II = str(string[4]).partition(':')[2]
			AI = str(string[5]).partition(':')[2]
			CD = str(string[6]).partition(':')[2]
			TD = str(string[7]).partition(':')[2]
			CR = str(string[8]).partition(':')[2]
			IR = str(string[9]).partition(':')[2]
			AR = str(string[10]).partition(':')[2]

			self.scores(AV, AC, AU, CI, II, AI, "ND", "ND", "ND", CD, TD, CR, IR, AR)

		elif length == "14": #Everything was defined
			AV = str(string[0]).partition(':')[2]
			AC = str(string[1]).partition(':')[2]
			AU = str(string[2]).partition(':')[2]
			CI = str(string[3]).partition(':')[2]
			II = str(string[4]).partition(':')[2]
			AI = str(string[5]).partition(':')[2]
			EX = str(string[6]).partition(':')[2]
			RL = str(string[7]).partition(':')[2]
			RC = str(string[8]).partition(':')[2]
			CD = str(string[9]).partition(':')[2]
			TD = str(string[10]).partition(':')[2]
			CR = str(string[11]).partition(':')[2]
			IR = str(string[12]).partition(':')[2]
			AR = str(string[13]).partition(':')[2]
			self.scores(AV, AC, AU, CI, II, AI, EX, RL, RC, CD, TD, CR, IR, AR)
                        
		else: #Just the Base options
			AV = str(string[0]).partition(':')[2]
			AC = str(string[1]).partition(':')[2]
			AU = str(string[2]).partition(':')[2]
			CI = str(string[3]).partition(':')[2]
			II = str(string[4]).partition(':')[2]
			AI = str(string[5]).partition(':')[2]
			self.scores(AV, AC, AU, CI, II, AI, "ND", "ND", "ND", "ND", "ND", "ND", "ND", "ND")



