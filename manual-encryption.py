#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

__author__      = "Abraham Rubinstein"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
import binascii
import rc4

#Cle wep AA:AA:AA:AA:AA
key='\xaa\xaa\xaa\xaa\xaa'

#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]  

# rc4 seed est composé de IV+clé
seed = arp.iv+key 

# recuperation de icv dans le message (arp.icv) (en chiffre) -- je passe au format "text". Il y a d'autres manières de faire ceci...
icv_encrypted='{:x}'.format(arp.icv).decode("hex")

# text chiffré y-compris l'icv
message_encrypted=arp.wepdata+icv_encrypted 

# déchiffrement avec rc4
cleartext=rc4.rc4crypt(message_encrypted,seed)  

# le ICV est les derniers 4 octets - je le passe en format Long big endian
icv_enclair=cleartext[-4:]

(icv_numerique,)=struct.unpack('!L', icv_enclair)

# le message sans le ICV
text_enclair=cleartext[:-4] 
	
print 'Text: ' + text_enclair.encode("hex")
print 'icv:  ' + icv_enclair.encode("hex")
print 'icv(num): ' + str(icv_numerique)
print 'icv chiffre: ' + icv_encrypted.encode("hex")


## TASK

# rc4 seed est composé de IV+clé
seed = arp.iv+key

# Le message sans le ICV
plaintxt=text_enclair

icv_plaintxt=(binascii.crc32(plaintxt) & 0xFFFFFFFF)

icv_litleEndian=struct.pack('<I', icv_plaintxt)

# Le flux à chiffrer composé de l'icv du bloc
fluxClearTxt = text_enclair + icv_litleEndian

# Chiffrement à l'aide de rc4
cyphetxt=rc4.rc4crypt(fluxClearTxt,seed)


#MAJ contenu msg chiffré (msg + icv)
arp.wepdata = cyphetxt[:-4]
#MAJ contenu ICV (icv chiffré)
arp.icv = int(icv_litleEndian.encode('hex'), 16)




wrpcap('exo1.pcap',arp, append=False)







