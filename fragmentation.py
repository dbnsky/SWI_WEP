#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

__author__      = "Abraham Rubinstein"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= 
__status__ 		= 

from scapy.all import *
import binascii
import rc4



#Cle wep AA:AA:AA:AA:AA
key='\xaa\xaa\xaa\xaa\xaa'





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
plaintxt = "Un vieil indien explique à son petit fils que chacun de nous a en lui deux loups qui se livrent bataille. Le premier loup représente la sérénité, l’amour et la gentillesse. Le second loup représente la peur l’avidité et la haine. « Lequel des deux loups gagne ? « demande l’enfant. « Celui que l’on nourrit. » Répond le grand père. Sagesse Amérindienne."
data_frgmnts = fragmentClearData(plaintxt, nbfrgmnt)

for index, dataToEncrypt in enumerate(data_frgmnts):

	#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
	arp = rdpcap('arp.cap')[0]

	# rc4 seed est composé de IV+clé
	seed = arp.iv+key 

	# Calcul ICV du texte en claire
	icv_plaintxt = (binascii.crc32(dataToEncrypt) & 0xFFFFFFFF)
	# Constuire
	icv_LittleEndian = struct.pack('<L', icv_plaintxt)

	# Message à chiffrer : data + icv
	fluxClearTxt = dataToEncrypt + icv_LittleEndian

	# Chiffrement à l'aide de rc4
	cyphetxt=rc4.rc4crypt(fluxClearTxt, seed)

	#MAJ contenu msg chiffré (msg + icv)
	arp.wepdata = cyphetxt[:-4]
	
	#MAJ contenu ICV (icv chiffré)
	icv_chiff = cyphetxt[-4:]

	# Construit valeur numérique de l'ICV chiffrée
	(icv_test,) = struct.unpack('!L', icv_chiff)
	
	#MAJ arp ICV
	arp.icv = icv_test

	arp.SC = index

	# les premiers fragements on le flag : MoreFragement
	if index < (nbfrgmnt - 1) :
		print arp.SC
		arp.FCfield += 4


	# Enregistre les fragements dans un fichier pcap
	wrpcap('fragmentation.pcap',arp, append=True)



