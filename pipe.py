import os
import json
i,o,u = os.popen3("./out")
while True:
	out = o.readline()
	if out != "":
		try:
			data = json.loads(out)
			print "aad : " + data["aad"]
			print "tk : " + data["tk"]
		except:
			print "eccezione"
			#print out
#
#out = json.loads(cry)
