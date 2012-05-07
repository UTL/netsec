#! /usr/bin/env python
import scapy.config
scapy.config.conf.logLevel = 40 # Suppress useless warnings from scapy...
from scapy.all import *
from scapy_wpa import *
from Handshake import *
from Station import *
from AccessPoint import *
from binfunctions import *
from pbkdf2 import passPhraseToPSK
from ccmp import CCMP_decrypt
import tkip



def confronta(cipher, hexstrings):
	str = hexarray2bin(hexstrings)
	if str == cipher:
		print "OK"
	else:
		print "ERRORE:"
		print "risulta : ", str2hex(cipher)
		print "previsto: ", str2hex(str)



print "TEST DELLA FUNZIONE PRF"

print "Test 1...",
key = "\x0b"*20
prefix = "prefix"
data = "Hi There"
nbits = 512

cipher = PRF(key, prefix, data, nbits)

check = [
"0xbcd4c650b30b9684951829e0d75f9d54",
"0xb862175ed9f00606e17d8da35402ffee",
"0x75df78c3d31e0f889f012120c0862beb",
"0x67753e7439ae242edb8373698356cf5a"
]

confronta(cipher, check)

print "Test 2...",
key = "Jefe"
prefix = "prefix"
data = "what do ya want for nothing?"
nbits = 512

cipher = PRF(key, prefix, data, nbits)

check = [
"0x51f4de5b33f249adf81aeb713a3c20f4",
"0xfe631446fabdfa58244759ae58ef9009",
"0xa99abf4eac2ca5fa87e692c440eb4002",
"0x3e7babb206d61de7b92f41529092b8fc"
]

confronta(cipher, check)

print "Test 3...",
key = "\xaa"*20
prefix = "prefix"
data = "\xdd"*50
nbits = 512

cipher = PRF(key, prefix, data, nbits)

check = [
"0xe1ac546ec4cb636f9976487be5c86be1",
"0x7a0252ca5d8d8df12cfb0473525249ce",
"0x9dd8d177ead710bc9b590547239107ae",
"0xf7b4abd43d87f0a68f1cbd9e2b6f7607"
]

confronta(cipher, check)



print "TEST DELLA FUNZIONE PBKDF2"

print "Test 1...",
passphrase = "password"
ssid = "IEEE"

cipher = passPhraseToPSK( passphrase, ssid )

check = [
"f42c6fc52df0ebef9ebb4b90b38a5f90",
"2e83fe1b135a70e23aed762e9710a12e"
]

confronta(cipher, check)


print "Test 2...",
passphrase = "ThisIsAPassword"
ssid = "ThisIsASSID"

cipher = passPhraseToPSK( passphrase, ssid )

check = [
"0dc0d6eb90555ed6419756b9a15ec3e3",
"209b63df707dd508d14581f8982721af"
]

confronta(cipher, check)


print "Test 3...",
passphrase = "a"*32
ssid = "Z"*32

cipher = passPhraseToPSK( passphrase, ssid )

check = [
"becb93866bb8c3832cb777c2f559807c",
"8c59afcb6eae734885001300a981cc62"
]

confronta(cipher, check)


print "TEST DERIVAZIONE CHIAVI"

PMK = hexarray2bin([
"0dc0d6eb90555ed6419756b9a15ec3e3",
"209b63df707dd508d14581f8982721af"
])

AA = "a0:a1:a1:a3:a4:a5"

SPA = "b0:b1:b2:b3:b4:b5"

SNonce = hexarray2bin([
"c0c1c2c3c4c5c6c7c8c9d0d1d2d3d4d5",
"d6d7d8d9dadbdcdddedfe0e1e2e3e4e5"
])

ANonce = hexarray2bin([
"e0e1e2e3e4e5e6e7e8e9f0f1f2f3f4f5",
"f6f7f8f9fafbfcfdfeff000102030405"
])


print "Test 1 (CCMP-TK)...",

hs = Handshake(Station(SPA, AccessPoint(AA)))
hs.setTipoEnc("HMAC_SHA1_AES")
hs.ANonce = ANonce
hs.SNonce = SNonce
hs.PMK = PMK
hs.calcolaChiavi()

check = [
"b2360c79e9710fdd58bea93deaf06599"
]

confronta(hs.getTK(), check)


print "Test 2 (TKIP-KCK)...",

hs = Handshake(Station(SPA, AccessPoint(AA)))
hs.setTipoEnc("HMAC_MD5_RC4")
hs.ANonce = ANonce
hs.SNonce = SNonce
hs.PMK = PMK
hs.calcolaChiavi()

check = [
"379f9852d0199236b94e407ce4c00ec8"
]

confronta(hs.getKCK(), check)

print "Test 3 (TKIP-KEK)...",
check = [
"47c9edc01c2c6e5b4910caddfb3e51a7"
]

confronta(hs.getKEK(), check)

print "Test 4 (TKIP-TK)...",
check = [
"b2360c79e9710fdd58bea93deaf06599",
"db980afbc29c152855740a6ce5ae3827"
]

confronta(hs.getTK(), check)

'''
TODO:
Authenticator Tx MIC_key = db980afbc29c1528
Supplicant Tx MIC_key    = 55740a6ce5ae3827
'''




print "ALTRI TEST PRF"

print "Test 1...",
key = "\x0b"*20
prefix = "prefix"
data = "Hi There"
nbits = 192

cipher = PRF(key, prefix, data, nbits)

check = [
"bc d4 c6 50 b3 0b 96 84 95 18 29 e0 d7 5f 9d 54",
"b8 62 17 5e d9 f0 06 06"
]

confronta(cipher, check)


print "Test 2...",
key = "Jefe"
prefix = "prefix-2"
data = "what do ya want for nothing?"
nbits = 256

cipher = PRF(key, prefix, data, nbits)

check = [
"47 c4 90 8e 30 c9 47 52 1a d2 0b e9 05 34 50 ec",
"be a2 3d 3a a6 04 b7 73 26 d8 b3 82 5f f7 47 5c"
]

confronta(cipher, check)


print "Test 3...",
key = "\xaa"*80
prefix = "prefix-3"
data = "Test Using Larger Than Block-Size Key - Hash Key First"
nbits = 384

cipher = PRF(key, prefix, data, nbits)

check = [
"0a b6 c3 3c cf 70 d0 d7 36 f4 b0 4c 8a 73 73 25",
"55 11 ab c5 07 37 13 16 3b d0 b8 c9 ee b7 e1 95",
"6f a0 66 82 0a 73 dd ee 3f 6d 3b d4 07 e0 68 2a"
]

confronta(cipher, check)


print "Test 4...",
key = "\x0b"*20
prefix = "prefix-4"
data = "Hi There Again"
nbits = 512

cipher = PRF(key, prefix, data, nbits)

check = [
"24 8c fb c5 32 ab 38 ff a4 83 c8 a2 e4 0b f1 70",
"eb 54 2a 2e 09 16 d7 bf 6d 97 da 2c 4c 5c a8 77",
"73 6c 53 a6 5b 03 fa 4b 37 45 ce 76 13 f6 ad 68",
"e0 e4 a7 98 b7 cf 69 1c 96 17 6f d6 34 a5 9a 49"
]

confronta(cipher, check)


print "TEST DECRIPTAZIONE CCMP"

print "Test 1...",
pkt = hexarray2bin([
"00 00 18 00 6e 48 00 00 00 02 6c 09 a0 00 da 81",
"03 00 00 00 00 00 00 00 ",
"08 48 C3 2C 0F D2 E1 28",
"A5 7C 50 30 F1 84 44 08  AB AE A5 B8 FC BA 80 33",
"0C E7 00 20 76 97 03 B5  F3 D0 A2 FE 9A 3D BF 23",
"42 A6 43 E4 32 46 E8 0C  3C 04 D0 19 78 45 CE 0B",
"16 F9 76 23 1D 99 F0 66"
])
key = hexarray2bin(["c9 7c 1f 67 ce 37 11 85 51 4a 8a 19 f2 bd d5 2f"])
check = [
"F8 BA 1A 55 D0 2F 85 AE  96 7B B6 2F B6 CD A8 EB",
"7E 78 A0 50"
]

pkt = RadioTap(pkt[:-4]) # Eliminiamo l'FCS in questi pacchetti
try:
	plain = CCMP_decrypt(pkt, key, outputStr=True)
	confronta(plain, check)
except:
	print 'Errore di decodifica!'



print "Test 2...",
pkt = hexarray2bin([
"00 00 18 00 6e 48 00 00 00 02 6c 09 a0 00 da 81",
"03 00 00 00 00 00 00 00",
"38 c0 6a 51 ea 10 0c 84 68 50 ee c1 76 2c 88 de af 2e e9 f4 6a 07",
"e0 cc ea 97 00 a0 ba cb f3 31 81 4b 69 65 d0 5b f2 b2 ed 38 d4 be",
"b0 69 fe 82 71 4a 61 0b 54 2f bf 8d a0 6a a4 ae 25 3c 47 38"
])
key = hexarray2bin(["8f 7a 05 3f a5 77 a5 59  75 29 27 20 97 a6 03 d5"])
check = [
"83 A0 63 4B 5E D7 62 7E  B9 DF 22 5E 05 74 03 42",
"DE 19 41 17"
]

pkt = RadioTap(pkt[:-4]) # Eliminiamo l'FCS in questi pacchetti
try:
	plain = CCMP_decrypt(pkt, key, outputStr=True)
	confronta(plain, check)
except:
	print 'Errore di decodifica!'


print "Test 3... (Non va, ha il QC)",
pkt = hexarray2bin([
"00 00 18 00 6e 48 00 00 00 02 6c 09 a0 00 da 81",
"03 00 00 00 00 00 00 00",
"b8 c8 dc 61 d9 57 7d f7 63 c8 b6 a8 8a df 36 91 dc 4a 8b ca 94 dd",
"60 82 20 85 ae a5 00 a0 f3 a0 dc 2f 89 d8 58 03 40 b6 26 a0 b6 d4",
"d0 13 bf 18 f2 91 b8 96 46 c8 fd 1f 1f 61 a9 fb 4b b3 60 3f 5a ad"
])
key = hexarray2bin(["40 cf b7 a6 2e 88 01 3b  d6 d3 af fc c1 91 04 1e"])
check = [
""
]

pkt = RadioTap(pkt[:-4]) # Eliminiamo l'FCS in questi pacchetti
try:
	plain = CCMP_decrypt(pkt, key, outputStr=True)
	confronta(plain, check)
except:
	print 'Errore di decodifica!'


print "Test 4...",
pkt = hexarray2bin([
"00 00 18 00 6e 48 00 00 00 02 6c 09 a0 00 da 81",
"03 00 00 00 00 00 00 00",
"18 79 81 46 9b 50 f4 fd 56 f6 ef ec 95 20 16 91 83 57 0c 4c cd ee",
"20 a0 23 e7 00 e0 73 40 ec 5e 12 c5 37 eb f3 ab 58 4e f1 fe f9 a1",
"f3 54 7a 8c 13 b3 22 5a 2d 09 57 ec fa be 95 b9 aa fa 0c c8"
])
key = hexarray2bin(["1b db 34 98 0e 03 81 24 a1 db 1a 89 2b ec 36 6a"])
check = [
"98 BE CA 86 F4 B3 8D A2  0C FD F2 47 24 C5 8E B8",
"35 66 53 39"
]

pkt = RadioTap(pkt[:-4]) # Eliminiamo l'FCS in questi pacchetti
try:
	plain = CCMP_decrypt(pkt, key, outputStr=True)
	confronta(plain, check)
except Exception:
	print 'Errore di decodifica!'


# pacchetto 635


print "TEST WPA1"

print "Test 1 (Phase1)...",
TK = hexarray2bin([
"12 34 56 78 90 12 34 56 78 90 12 34 56 78 90 12",
"34 56 78 90 12 34 56 78 90 12 34 56 78 90 12 34"
])
TA = hexarray2bin(["02 03 04 05 06 07"])
IV32 = hexarray2bin(["00 00 00 00"])

check = [
"58 bb 1f 07 93 9e 38 b4 4b 25"
]

# 8.6.1 pag 244
phase1key = tkip.fase1(TK[:16], TA, IV32)
confronta(phase1key, check)


print "Test 2 (Phase2)...",
phase1key = hexarray2bin(check)
IV16 = hexarray2bin(["00 01"])

check = [
	"00 20 01 4c fe 67 be d2 7c 86 7b 1b f8 02 8b 1c"
]

phase2key = tkip.fase2(TK[:16], phase1key, IV16)
confronta(phase2key, check)



print "Test 3 (Phase1)...",
TK = hexarray2bin([
"00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
])
TA = hexarray2bin(["10 22 33 44 55 66"])
IV = hexarray2bin(["00 00 00 00"])

check = [
"3d d2 01 6e 76 f4 86 97 b2 e8"
]

phase1key = tkip.fase1(TK[:16], TA, IV)
confronta(phase1key, check)


print "Test 4 (Phase2)...",
IV = hexarray2bin(["00 00"])

check = [
	"00 20 00 33 EA 8D 2F 60 CA 6D 13 74 23 4A 66 0B"
]

phase2key = tkip.fase2(TK[:16], phase1key, IV)
confronta(phase2key, check)





print "Test 5 (Phase1)...",
TK = hexarray2bin([
"A9 90 6D C8 3E 78 92 3F 86 04 E9 9E F6 CD BA BB"
])
TA = hexarray2bin(["50 30 F1 84 44 08"])
IV = hexarray2bin(["B5 03 97 76"])

check = [
"26 D5 F1 E1 2A 59 20 21 0E 8E"
]

phase1key = tkip.fase1(TK[:16], TA, IV)
confronta(phase1key, check)


print "Test 6 (Phase2)...",
phase1key = hexarray2bin(check)
IV = hexarray2bin(["E7 0C"])

check = [
	"E7 67 0C 68 15 E0 2E 3F 1C 15 92 92 D4 E2 78 82"
]

phase2key = tkip.fase2(TK[:16], phase1key, IV)
confronta(phase2key, check)



print "Test 7 (Phase1)...",
TK = hexarray2bin([
"63 89 3B 25 08 40 B8 AE 0B D0 FA 7E 61 D2 78 3E"
])
TA = hexarray2bin(["64 F2 EA ED DC 25"])
IV = hexarray2bin(["20 DC FD 43"])

check = [
"7C 67 49 D7 97 24 B5 E9 B4 F1"
]

phase1key = tkip.fase1(TK[:16], TA, IV)
confronta(phase1key, check)


print "Test 8 (Phase2)...",
phase1key = hexarray2bin(check)
IV = hexarray2bin(["FF FF"])

check = [
	"FF 7F FF 93 81 0F C6 E5 8F 5D D3 26 25 15 44 CE"
]

phase2key = tkip.fase2(TK[:16], phase1key, IV)
confronta(phase2key, check)



print "Test 9 (Phase1)...",
TK = hexarray2bin([
"C8 AD C1 6A 8B 4D DA 3B 4D D5 B6 54 38 35 9B 05"
])
TA = hexarray2bin(["94 5E 24 4E 4D 6E"])
IV = hexarray2bin(["8B 15 73 B7"])

check = [
"EF F1 3F 38 A3 64 60 A9 76 F3"
]

phase1key = tkip.fase1(TK[:16], TA, IV)
confronta(phase1key, check)


print "Test 10 (Phase2)...",
phase1key = hexarray2bin(check)
IV = hexarray2bin(["30 f8"])

check = [
	"30 30 F8 65 0D A0 73 EA 61 4E A8 F4 74 EE 03 19"
]

phase2key = tkip.fase2(TK[:16], phase1key, IV)
confronta(phase2key, check)





print "TEST RC4"
print "Test 1...",

plain = hexarray2bin(["00 00 00 00 00 00 00 00"])
key = hexarray2bin(["01 23 45 67 89 ab cd ef"])

check = [
"74 94 C2 E7 10 4B 08 79"
]

cipher = tkip.rc4(plain, key)
confronta(cipher, check)



print "Test 2...",
plain = hexarray2bin(["dc ee 4c f9 2c"])
key = hexarray2bin(["61 8a 63 d2 fb"])

check = [
"f1 38 29 c9 de"
]

cipher = tkip.rc4(plain, key)
confronta(cipher, check)



print "Test 3...",
plain = hexarray2bin([
	"52 75 69 73 6c 69 6e 6e",
	"75 6e 20 6c 61 75 6c 75",
	"20 6b 6f 72 76 69 73 73",
	"73 61 6e 69 2c 20 74 e4",
	"68 6b e4 70 e4 69 64 65",
	"6e 20 70 e4 e4 6c 6c e4",
	"20 74 e4 79 73 69 6b 75",
	"75 2e 20 4b 65 73 e4 79",
	"f6 6e 20 6f 6e 20 6f 6e",
	"6e 69 20 6f 6d 61 6e 61",
	"6e 69 2c 20 6b 61 73 6b",
	"69 73 61 76 75 75 6e 20",
	"6c 61 61 6b 73 6f 74 20",
	"76 65 72 68 6f 75 75 2e",
	"20 45 6e 20 6d 61 20 69",
	"6c 6f 69 74 73 65 2c 20",
	"73 75 72 65 20 68 75 6f",
	"6b 61 61 2c 20 6d 75 74",
	"74 61 20 6d 65 74 73 e4",
	"6e 20 74 75 6d 6d 75 75",
	"73 20 6d 75 6c 6c 65 20",
	"74 75 6f 6b 61 61 2e 20",
	"50 75 75 6e 74 6f 20 70",
	"69 6c 76 65 6e 2c 20 6d",
	"69 20 68 75 6b 6b 75 75",
	"2c 20 73 69 69 6e 74 6f",
	"20 76 61 72 61 6e 20 74",
	"75 75 6c 69 73 65 6e 2c",
	"20 6d 69 20 6e 75 6b 6b",
	"75 75 2e 20 54 75 6f 6b",
	"73 75 74 20 76 61 6e 61",
	"6d 6f 6e 20 6a 61 20 76",
	"61 72 6a 6f 74 20 76 65",
	"65 6e 2c 20 6e 69 69 73",
	"74 e4 20 73 79 64 e4 6d",
	"65 6e 69 20 6c 61 75 6c",
	"75 6e 20 74 65 65 6e 2e",
	"20 2d 20 45 69 6e 6f 20",
	"4c 65 69 6e 6f"
])
key = hexarray2bin([
	"29 04 19 72 fb 42 ba 5f",
	"c7 12 77 12 f1 38 29 c9"
])

check = [
	"35 81 86 99 90 01 e6 b5",
	"da f0 5e ce eb 7e ee 21",
	"e0 68 9c 1f 00 ee a8 1f",
	"7d d2 ca ae e1 d2 76 3e",
	"68 af 0e ad 33 d6 6c 26",
	"8b c9 46 c4 84 fb e9 4c",
	"5f 5e 0b 86 a5 92 79 e4",
	"f8 24 e7 a6 40 bd 22 32",
	"10 b0 a6 11 60 b7 bc e9",
	"86 ea 65 68 80 03 59 6b",
	"63 0a 6b 90 f8 e0 ca f6",
	"91 2a 98 eb 87 21 76 e8",
	"3c 20 2c aa 64 16 6d 2c",
	"ce 57 ff 1b ca 57 b2 13",
	"f0 ed 1a a7 2f b8 ea 52",
	"b0 be 01 cd 1e 41 28 67",
	"72 0b 32 6e b3 89 d0 11",
	"bd 70 d8 af 03 5f b0 d8",
	"58 9d bc e3 c6 66 f5 ea",
	"8d 4c 79 54 c5 0c 3f 34",
	"0b 04 67 f8 1b 42 59 61",
	"c1 18 43 07 4d f6 20 f2",
	"08 40 4b 39 4c f9 d3 7f",
	"f5 4b 5f 1a d8 f6 ea 7d",
	"a3 c5 61 df a7 28 1f 96",
	"44 63 d2 cc 35 a4 d1 b0",
	"34 90 de c5 1b 07 11 fb",
	"d6 f5 5f 79 23 4d 5b 7c",
	"76 66 22 a6 6d e9 2b e9",
	"96 46 1d 5e 4d c8 78 ef",
	"9b ca 03 05 21 e8 35 1e",
	"4b ae d2 fd 04 f9 46 73",
	"68 c4 ad 6a c1 86 d0 82",
	"45 b2 63 a2 66 6d 1f 6c",
	"54 20 f1 59 9d fd 9f 43",
	"89 21 c2 f5 a4 63 93 8c",
	"e0 98 22 65 ee f7 01 79",
	"bc 55 3f 33 9e b1 a4 c1",
	"af 5f 6a 54 7f"
]

cipher = tkip.rc4(plain, key)
confronta(cipher, check)



print "TEST DECRIPTAZIONE WPA-TKIP"

print "Test 1 (anche fase1+2)...",
TK = hexarray2bin(["00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"])
TA = hexarray2bin(["10 22 33 44 55 66"])
IV32 = hexarray2bin(["00 00 00 00"])
IV16 = hexarray2bin(["00 00"])

cipher = hexarray2bin([
	"06 60 91 dc 37 82 31 ca 75 84 82 b6 54 b7 c5 3a",
	"81 4a cb bd 31 1e cc 3b 5c f7 df 69 53 0f c5 1b"
])


check = [
"08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17",
"18 19 1a 1b",
"9c 12 11 62  08 e9 a0 83"
]

phase1key = tkip.fase1(TK[:16], TA, IV32)
phase2key = tkip.fase2(TK[:16], phase1key, IV16)
try:
	plain = tkip.decrypt(cipher, phase2key)
	confronta(plain, check)
except Exception, e:
	print "Errore:", e


print "Test 2...",
TK = hexarray2bin(["36 23 0f 41 40 20 c9 e3 02 cb 5d 5d 28 d5 ff bf"])
TA = hexarray2bin(["01 02 03 04 05 06"])
# b2a_p(pack('<Q',0x123456785BA0)[:6])
# a0 5b 78 56 34 12
IV32 = hexarray2bin(["78 56 34 12"])[::-1]
IV16 = hexarray2bin(["a0 58"])[::-1] # FIXME: 58 o 5B???


cipher = hexarray2bin([
	#"58 11 A0 20 78 56 34 12",
	"12 86 13 90 94 44 88 49 a3 9f e1 48 e0 f4 f3 8f",
	"78 ee de 66 c4 a2 8c a1 bd 39 00 7f 88 9b 95 c6",
	"e6 9d cd 19 31 dc 25 61 c3 e1 9a d4 a6 4d 22",
	"13 9b fa 26"
])

phase1key = tkip.fase1(TK[:16], TA, IV32)
phase2key = tkip.fase2(TK[:16], phase1key, IV16)


check = [
"aa aa 03 00 00 00 08 00 45 00 00 4e 66 1a 00 00",
"80 11 be 64 0a 00 01 22 0a ff ff ff 00 89 00 89",
"00 3a 00 00 80 a6 01 10 00 01 00 00 00 00 00"
]

try:
	plain = tkip.decrypt(cipher, phase2key)
	confronta(plain, check)
except Exception, e:
	print "Errore:", e


print "Test 3 (MPDU completo)...",
protectedMPDU = hexarray2bin([
	"08 41 23 01 01 02 03 04 05 06 01 02 03 04 05 06",
	"01 22 33 44 55 66 00 00 a0 7b 5b 20 78 56 34 12",
	"b8 2c 10 90 94 44 80 49 e6 9f e1 06 86 ee f3 8f",
	"f8 ff 60 02 ce a2 8d 83 b7 c6 ff 80 88 12 95 4f",
	"e6 a7 cd 19 b1 7a 24 71 c3 e0 9a d4 a6 4d 22 13",
	"9b fa 26"
])

#pkt = Dot11(protectedMPDU[:-4]) # Eliminiamo l'FCS in questi pacchetti

pkt = Dot11(protectedMPDU)

try:
	plain = TKIP_decrypt(pkt, TK, outputStr=True)
	confronta(plain, check)
except:
	print "Errore:", e



print "Test 4 (MPDU completo)...",
TK = hexarray2bin([
	"12 34 56 78 90 12 34 56 78 90 12 34 56 78 90 12",
	"34 56 78 90 12 34 56 78 90 12 34 56 78 90 12 34"
])

protectedMPDU = hexarray2bin([
	"08 42 2c 00 02 03 04 05 06 08 02 03 04 05 06 07",
	"02 03 04 05 06 07 d0 02 00 20 01 20 00 00 00 00",
	"c0 0e 14 fc e7 cf ab c7 75 47 e6 66 e5 7c 0d ac",
	"70 4a 1e 35 8a 88 c1 1c 8e 2e 28 2e 38 01 02 7a",
	"46 56 05 5e e9 3e 9c 25 47 02 e9 73 58 05 dd b5",
	"76 9b a7 3f 1e bb 56 e8 44 ef 91 22 85 d3 dd 6e",
	"54 1e 82 38 73 55 8a db a0 79 06 8a bd 7f 7f 50",
	"95 96 75 ac c4 b4 de 9a a9 9c 05 f2 89 a7 c5 2f",
	"ee 5b fc 14 f6 f8 e5 f8"
])

check = [
	"aa aa 03 00 00 00 08 00 45 00 00 54 00 00 40 00",
	"40 01 a5 55 c0 a8 0a 02 c0 a8 0a 01 08 00 3a b0",
	"00 00 00 00 cd 4c 05 00 00 00 00 00 08 09 0a 0b",
	"0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b",
	"1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b",
	"2c 2d 2e 2f 30 31 32 33 34 35 36 37 68 81 a3 f3",
	"d6 48 d0 3c"
]


pkt = Dot11(protectedMPDU)

try:
	plain = TKIP_decrypt(pkt, TK, outputStr=True)
	confronta(plain, check)
except:
	print "Errore:", e



print "TEST SU MICHAEL"
print "Test 1...",
key = hexarray2bin(["00 00 00 00 00 00 00 00"])
data = ""

check = ["82 92 5c 1c a1 d1 30 b8"]
MIC = tkip.michael(key, data)
confronta(MIC, check)


print "Test 2...",
key = hexarray2bin(["82 92 5c 1c a1 d1 30 b8"])
data = "M"

check = ["43 47 21 ca 40 63 9b 3f"]
MIC = tkip.michael(key, data)
confronta(MIC, check)


print "Test 3...",
key = hexarray2bin(["43 47 21 ca 40 63 9b 3f"])
data = "Mi"

check = ["e8 f9 be ca e9 7e 5d 29"]
MIC = tkip.michael(key, data)
confronta(MIC, check)


print "Test 4...",
key = hexarray2bin(["e8 f9 be ca e9 7e 5d 29"])
data = "Mic"

check = ["90 03 8f c6 cf 13 c1 db"]
MIC = tkip.michael(key, data)
confronta(MIC, check)


print "Test 5...",
key = hexarray2bin(["90 03 8f c6 cf 13 c1 db"])
data = "Mich"

check = ["d5 5e 10 05 10 12 89 86"]
MIC = tkip.michael(key, data)
confronta(MIC, check)


print "Test 6...",
key = hexarray2bin(["d5 5e 10 05 10 12 89 86"])
data = "Michael"

check = ["0a 94 2b 12 4e ca a5 46"]
MIC = tkip.michael(key, data)
confronta(MIC, check)

