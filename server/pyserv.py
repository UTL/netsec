import SocketServer, json, base64, binascii, sys, signal
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
		dati = binify(data["data"])
		mac1 = binify(data["mac1"])
		mac2 = binify(data["mac2"])
		print "-----------MAC1-----------"
		print dump(mac1)
		print "-----------MAC2-----------"
		print dump(mac2)
		print "-----------AAD------------"
		print dump(aad)
		print "-----------NONCE----------"
		print dump(tk)
		print "-----------TK-------------"
		print dump(nonce)
		print "-----------DATI CIFRATI----------"
		print dump(dati)

		decrypter = CCM(AES(tk,len(tk))) #di default ha gia mic e lunghezza nonce settati per il ccmp
		plainText = decrypter.decrypt(dati,nonce,aad)
		print "-----------DATI IN CHIARO----------"
		print dump(plainText)

	except:
		print '\033[91m' "---CONTROLLO DI INTEGRITA' FALLITO---" '' '\033[0m' "" ''
		

def binify(inp):
	return base64.b16decode(str(inp).upper())



def signal_handler(signal, frame):
        print 'Rilevato Ctrl+C'
	print 'Chiusura programma in corso'
        sys.exit(0)



def gestore(out):
	if out != "":
		try:
			data = json.loads(out)
			#1 = messaggio
			#2 = dati da decriptare
			if data["command"] == "2":
				decripta(data)
			elif data["command"] == "1":
				print "-----------MESSAGGIO----------"
				print data["msg"]
				print ""
		except ValueError:
			print "Dati non Json"
			print out
			#print out


class MyTCPHandler(SocketServer.StreamRequestHandler):

    def handle(self):
        # self.rfile is a file-like object created by the handler;
        # we can now use e.g. readline() instead of raw recv() calls      
		while True:
			self.data = self.rfile.readline().strip()
			if not self.data:
				break
			#print self.data
			try:
				dati = json.loads(self.data)
				#1 = messaggio
				#2 = dati da decriptare
				if dati["command"] == "2":
					decripta(dati)
				elif dati["command"] == "1":
					print "-----------MESSAGGIO----------"
					print dati["msg"]
					print ""
			except ValueError:
				print "Dati non Json"
				print self.data
	

signal.signal(signal.SIGINT, signal_handler)
print ""
print ""
print "Progetto Network Security"
print "Rizzardi Enrico"
print ""
print "Ricordarsi di verificare ssid e pw"
print ""
print "Server in ascolto"
print ""

HOST, PORT = "localhost", 12345
server = SocketServer.TCPServer((HOST, PORT), MyTCPHandler)

server.serve_forever()
