import SocketServer, json, base64, binascii, sys, signal
sys.path.append('cryptopy')

from crypto.cipher.ccm import CCM
from crypto.cipher.aes import AES


#funzione di libreria presa "com'e'"
FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])

try:
   fh = open("log.txt", "w")
   fh.write("Inizio log\n")
except IOError:
   print '\033[91m' "Errore di I/O impossibile scrivere il file di log ./log.txt" '' '\033[0m' "" ''


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
		src = binify(data["src"])
		dst = binify(data["dst"])
		strlist = []
		strlist.append("-----SOURCE MAC ADDRESS---")
		strlist.append(dump(src))
		strlist.append("------DEST MAC ADDRESS----")
		strlist.append(dump(dst))
		strlist.append("-----------AAD------------")
		strlist.append(dump(aad))
		strlist.append("-----------NONCE----------")
		strlist.append(dump(tk))
		strlist.append("-----------TK-------------")
		strlist.append(dump(nonce))
		strlist.append("-----------DATI CIFRATI----------")
		strlist.append(dump(dati))
		
		longstr = "\n".join(strlist)
		print longstr
		fh.write(longstr)

		decrypter = CCM(AES(tk,len(tk)))
		plainText = decrypter.decrypt(dati,nonce,aad)
		strlist = []
		strlist.append("-----------DATI IN CHIARO----------")
		strlist.append(dump(plainText))
		
		longstr = "\n".join(strlist)
		print longstr
		fh.write(longstr)
	except:
		print '\033[91m' "---CONTROLLO DI INTEGRITA' FALLITO---" '' '\033[0m' "" ''
		fh.write("---CONTROLLO DI INTEGRITA' FALLITO---\n")
		

def binify(inp):
	return base64.b16decode(str(inp).upper())



def signal_handler(signal, frame):
        print 'Rilevato Ctrl+C'
	print 'Chiusura programma in corso'
	try:
   		fh.write("Close stream\n")
		fh.close()
	except IOError:
		print "Error: can\'t find file or read data"
        sys.exit(0)



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
					print '\033[92m' "-----------MESSAGGIO----------" ''
					print dati["msg"]
					print '\033[0m' "" ''
			except ValueError:
				print "Dati non Json"
				print self.data
	

signal.signal(signal.SIGINT, signal_handler)
print "Network security: confidentiality in WPA-personal"
print ""
print "Rizzardi Enrico 75789"
print ""
print "Server in ascolto"
print ""



HOST, PORT = "localhost", 12345
server = SocketServer.TCPServer((HOST, PORT), MyTCPHandler)

server.serve_forever()
