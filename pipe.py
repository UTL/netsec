import json, base64, binascii, os, sys
sys.path.append('cryptopy')

from crypto.cipher.ccm import CCM
from crypto.cipher.aes import AES

#funzione di libreria presa "com'e'"
FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])

def dump(src, length=8):
	N=0; result=''
	while src:
		s,src = src[:length],src[length:]
		hexa = ' '.join(["%02X"%ord(x) for x in s])
		s = s.translate(FILTER)
		result += "%04X   %-*s   %s\n" % (N, length*3, hexa, s)
		N+=length
	return result



def decripta(data):
	try:
		aad = binify(data["aad"])
		tk = binify(data["tk"])
		nonce = binify(data["nonce"])
		data = binify(data["data"])

		print "-----------AAD----------"
		print dump(aad)
		print "-----------NONCE----------"
		print dump(tk)
		print "-----------TK----------"
		print dump(nonce)
		print "-----------DATI CIFRATI----------"
		print dump(data)

		micsize = 8 #il mic nel wpa2 e' di 8 bit

		decrypter = CCM(AES(tk,len(tk)),micsize, nonceSize=len(nonce))
		plainText = decrypter.decrypt(data,nonce,aad)
		print "-----------DATI IN CHIARO----------"
		print dump(plainText)
	except: #IntegrityCheckError:
		print "Controllo di integrita' fallito, pacchetto non decriptato"		

def binify(inp):
	return base64.b16decode(str(inp).upper())


i,o,u = os.popen3("./out")
while True:
	out = o.readline()
	if out != "":
		try:
			data = json.loads(out)
			decripta(data)
		except ValueError:
			print "Dati non Json"
			print out
			#print out
#
#out = json.loads(cry)



