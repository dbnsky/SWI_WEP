#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

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

#Fonction de division de la data en nombre de fragements souhaité
def fragmentClearData(clearData, nbFragement):
    	frgmntSz = len(clearData)/nbFragement
	fragements = []
	for i in range(0, nbFragement):
		if i == (nbFragement - 1):
			fragements.append(clearData[i*frgmntSz:])
		else:
			fragements.append(clearData[i*frgmntSz: (frgmntSz * (i+1)) - 1])
    	return fragements

# Nombre de fragement souhaité
nbfrgmnt = 5

# Message à chiffrer
plaintxt = "Un vieil indien explique à son petit fils que chacun de nous a en lui deux loups qui se livrent bataille. Le premier loup  représente la sérénité, l’amour et la gentillesse. Le second loup représente la peur l’avidité et la haine. « Lequel des deux loups gagne ? « demande l’enfant. « Celui que l’on nourrit. » Répond le grand père. Sagesse Amérindienne."
print "Text Msg: " + plaintxt

data_frgmnts = fragmentClearData(plaintxt, nbfrgmnt)


#creation des trames 
for index, dataToEncrypt in enumerate(data_frgmnts):

	# Récupération de la trame "template"
	arp = rdpcap('arp.cap')[0]

	# rc4 seed est composé de IV+clé
	seed = arp.iv+key 

	# Calcul ICV
	icv = (binascii.crc32(dataToEncrypt) & 0xFFFFFFFF)
	print "Base ICV: " + str(icv)

	# Converstion de l'icv en littleEndian
	icv_LittleEndian = struct.pack('<L', icv)
	print "ICV littleEndian: " + icv_LittleEndian.encode("hex")

	# Message à chiffrer : data + icv
	fluxClearTxt = dataToEncrypt + icv_LittleEndian

	# Chiffrement à l'aide de rc4
	encryptedTxt=rc4.rc4crypt(fluxClearTxt, seed)
	print "Encrypted Text Msg: " + encryptedTxt.encode("hex")

	#MAJ contenu msg chiffré (msg + icv)
	arp.wepdata = encryptedTxt[:-4]
	
	#MAJ contenu ICV (icv chiffré)
	icv_chiff = encryptedTxt[-4:]

	# Construit valeur numérique de l'ICV chiffrée
	(icv_test,) = struct.unpack('!L', icv_chiff)
	
	#MAJ arp ICV
	arp.icv = icv_test

	arp.SC = index
	print "Index de la trame: " + str(arp.SC)

	# les premiers fragements on le flag : MoreFragement
	if index < (nbfrgmnt - 1) :
		arp.FCfield += 4

	print "MoreFragement flag: " + str(arp.FCfield)

	# Enregistre les fragements dans un fichier pcap
	wrpcap('exo3.pcap',arp, append=True)
	print "\n"

print "Output created : exo3.pcap"



