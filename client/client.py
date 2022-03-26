#!/usr/bin/env python3.6
'''
Author: Ravindra kumar and Jude K Anil
Function: Implement Client function which either asks or provides a requested file. 
Last Modified: 05-March-2022
Bugs: None
'''

import os
import sys
import socket
import getopt
import base64
import time
from datetime import date
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def start():
	myname, mode, caport,caip, serverip, serverport= "","",60000, "", "", 60001
    
	try:
	    opts,args = getopt.getopt(sys.argv[1:],"n:m:a:p:q:d:",["name=","caip=","caport=","serverip=","serverport="])
	except getopt.GetoptError as err:
	    print(err)
	    print("Syntax: ./client -n myname -m R -d serverIP -q serverport -a caip -p caport")
	    sys.exit(2)
	for o,a in opts:
		if o in ('-n','--name'):
			myname = a
		elif o == '-m':
			mode = a
		elif o in ("-d","--serverip"):
			serverip = a
		elif o in ("-q",'--serverport'):
			serverport = int(a)
		elif o in ('-a',"--caip"):
			caip = a
		elif o in ("-p","--caport"):
			caport = int(a)
		else:
			print(o,"",a)
			assert False, "unhandled option"

	# print("**************************Requesting for Certificate**************************")
	# requestCertificate(myname,caport,caip)
	
	if mode == 'R':
		print("**************************Acting as a Client**************************")
		Client(myname,serverip,serverport)
	else:
		print("Unknown mode.")
		sys.exit(2)

def requestCertificate(myname,caport,caip):
	certificatefilename = "Certificate.dat"
	cakeyfilename = "capubkey.pem"
	mypubkeyfilename = "clientpubkey.pem"
	myprivkeyfilename = "clientprivkey.pem"
	capubkeyfile = open(cakeyfilename,'rb')
	mypubkeyfile = open(mypubkeyfilename,'rb')
	myprivkeyfile = open(myprivkeyfilename,'rb')
	mypubkey = mypubkeyfile.read()
	RSAcapubkey = serialization.load_pem_public_key(capubkeyfile.read())
	RSAmyprivkey = serialization.load_pem_private_key(myprivkeyfile.read(),password = None)
	mynameb64 = base64.b64encode(myname.encode("ascii"))
	# print(cryptography.__version__)
	encmyname = RSAcapubkey.encrypt(mynameb64,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
	dataToCA = "301".encode("ascii")+"|".encode("ascii")+mypubkey+"|".encode("ascii")+base64.b64encode(encmyname)
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as skt:
		skt.connect((caip,caport))
		recdata = (skt.recv(2048)).decode()
		print(recdata)
		skt.send(dataToCA)
		print(f"To {(caip,caport)}:Sent 301 request.")
		recdata = skt.recv(2048)
		# print(recdata)
		recdata = recdata.decode("ascii").split('|')
		code = int(recdata[0])
		if code == 302:
			print(f"From {(caip,caport)}:Received 302 information.")
			clientname = base64.b64decode(recdata[1].encode("ascii"))
			certificate = base64.b64decode(recdata[2])
			# print(code,"\nclientname\n",clientname,"\ncertificate\n",certificate)
			enchash = base64.b64decode(recdata[-1])
			signature = RSAmyprivkey.decrypt(enchash,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
			try:
				RSAcapubkey.verify(signature,certificate,padding.PSS(mgf=padding.MGF1(algorithm=hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
			except InvalidSignature as e:
				print("Invalid Signature.")
				sys.exit(3)
			print("Signature matched.")
			certificatefile = open(certificatefilename,"wb")
			certificatefile.write(certificate+'|'.encode("ascii")+base64.b64encode(signature))
			certificatefile.close()
			print(f"Certificate saved in {certificatefilename}.")



def Client(myname, serverip,serverport):
	cakeyfilename = "capubkey.pem"
	capubkeyfile = open(cakeyfilename,'rb')
	RSAcapubkey = serialization.load_pem_public_key(capubkeyfile.read())
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as skt:
		skt.connect((serverip,serverport))
		recdata = (skt.recv(2048)).decode()
		print(f'From {(serverip,serverport)}: {recdata}')	# Hello message from Sender.

		certificatefile = open("Certificate.dat","rb")
		certificate = certificatefile.read()
		certificatefile.close()
		clientrandom = os.urandom(32)
		print("Generated clientrandom key.")
		datatosend = "601".encode("ascii") +"|".encode("ascii") + base64.b64encode(myname.encode("ascii")) + '|'.encode("ascii") + base64.b64encode(clientrandom) + "|".encode("ascii") + base64.b64encode(certificate)
		skt.send(datatosend)
		print(f'To {(serverip,serverport)}: Sent 601 request.')
		recdata = skt.recv(2048)
		# print("Received data: ",recdata)
		recdata = recdata.decode("ascii").split('|')
		code = int(recdata[0])
		if code == 602:
			print(f'From {(serverip,serverport)}: Received 602 information.')
			servername = base64.b64decode(recdata[1])
			serverrandom = base64.b64decode(recdata[2])
			servercertificatewithhash = base64.b64decode(recdata[3])
			servercertificatewithhash = servercertificatewithhash.decode("ascii").split('|')
			servercertificate =  servercertificatewithhash[0].encode("ascii")
			signature = base64.b64decode(servercertificatewithhash[-1])
			try:
				RSAcapubkey.verify(signature,servercertificate,padding.PSS(mgf=padding.MGF1(algorithm=hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
			except InvalidSignature as e:
				print("Invalid Signature.")
				sys.exit(3)
			print("Signature matched.")
			certExpdate= servercertificate[-10::1].decode("ascii")
			today = date.today()
			certExpdate = date(int(certExpdate[:4]),int(certExpdate[5:7]),int(certExpdate[8:]))
			if (certExpdate-today).days < 0:
				print("Server's Certificate expired.")
				sys.exit(3)
			print("Server's Certificate valid.")
			serverpubkey = ((servercertificate.decode("ascii")).split("-----"))[1:4]
			serverpubkey = "-----"+"-----".join(serverpubkey)+"-----"
			# print(serverpubkey)
			RSAserverpubkey = serialization.load_pem_public_key(serverpubkey.encode("ascii"))
			PreMasterKey = os.urandom(48)
			print("Generated session key.")
			EncPreMasterKey = RSAserverpubkey.encrypt(PreMasterKey,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
			print("Encrypted PreMasterSecret key with server's public key.")
			datatosend = "603".encode("ascii") + '|'.encode("ascii") + base64.b64encode(EncPreMasterKey)
			# print(datatosend)
			print(f'Sent EncPreMasterSecret.')
			skt.send(datatosend)
			print(f'To {(serverip,serverport)}: Sent 603 request.')

			# Generating all keys using PRF Function given in textbook.
			secret_key = PRF_Fun(PreMasterKey,"master secret",clientrandom+serverrandom)[:48]
			key_block = PRF_Fun(secret_key,"key expansion",clientrandom+serverrandom)
			client_write_MAC_key = key_block[:32]
			server_write_MAC_key = key_block[32:64]
			client_write_key = key_block[64:88]
			server_write_key = key_block[88:112]
			client_write_IV = key_block[112:128]
			server_write_IV = key_block[128:144]
			print(key_block,len(key_block))


			
# PRF_Fun as described in textbook. 			
def PRF_Fun(secret_key,label,seed1):
	seed = label.encode()+seed1;
	prf_res = b''
	for i in range(5):	#32(HMAC-sha-256)+32+24(aes-192)+24+16(IV)+16 =144B
		h = hmac.HMAC(secret_key, hashes.SHA256());
		h.update(seed)
		s1 = h.finalize()
		h = hmac.HMAC(secret_key, hashes.SHA256());
		h.update(s1+seed)
		prf_res = prf_res + h.finalize()
		seed = s1
	return prf_res

if __name__ == "__main__":
	start()