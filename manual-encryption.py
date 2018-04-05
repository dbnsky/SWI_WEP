#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""

__author__      = "Nguefack Zacharie, Gallandat Théo, Emmanuel Schmid"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"

from scapy.all import *
import binascii
import rc4

#Cle wep AA:AA:AA:AA:AA
key='\xaa\xaa\xaa\xaa\xaa'

print "Key: " + key.encode("hex")
# Récupération de la trame "template"
arp = rdpcap('arp.cap')[0]  

# rc4 seed est composé de IV+clé
seed = arp.iv + key

print "Seed: " + seed.encode("hex")

# Le messagee en clair
plaintxt="ThisMessageWasEncryptedAndNowItIsNot!"

print "Text Msg: " + plaintxt

#Création de l'icv
icv=(binascii.crc32(plaintxt) & 0xFFFFFFFF)

print "Base ICV: " + str(icv)

#Converstion de l'icv en littleEndian
icv_litleEndian=struct.pack('<L', icv)

print "ICV littleEndian: " + icv_litleEndian.encode("hex")

# Le flux à chiffrer composé de l'icv du bloc et du message en clair
streamClearTxt = plaintxt + icv_litleEndian

# Chiffrement à l'aide de rc4
encryptedTxt=rc4.rc4crypt(streamClearTxt,seed)

print "Encrypted Text Msg: " + encryptedTxt.encode("hex")

#MAJ contenu msg chiffré (msg + icv)
arp.wepdata = encryptedTxt[:-4]

#MAJ contenu ICV (icv chiffré)
icv_chiff = encryptedTxt[-4:]

(arp.icv,) = struct.unpack('!L', icv_chiff)

wrpcap('exo2.pcap',arp, append=False)

print "Output created : exo2.pcap"







