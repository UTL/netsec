import os 
i,o,u = os.popen3("./out")
while 1<2:
	out = o.readline()
	if out != "":
		print out
#import json
#out = json.loads(cry)
