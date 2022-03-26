#!/usr/bin/env python3.6
'''
Author: Ravindra kumar and Jude K Anil
Function: Create a Certifying authority server and issue certificates to clients. 
Last Modified: 05-March-2022
Bugs: None
'''

import sys
import socket
import getopt
import os
import base64
import threading
from datetime import date
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

class IssueCertificate(threading.Thread):
    def __init__(self,clientsocket, clientAddress,outputfile):
        threading.Thread.__init__(self)
        self.csocket = clientsocket
        self.clientaddr = clientAddress
        self.outputfile = outputfile
    def run(self):
        with self.csocket:
            print(f"Connected to {self.clientaddr}")
            self.outputfile.write(f"\n*****************Connected to {self.clientaddr}*****************\n")
            self.outputfile.write(f"To {self.clientaddr}: Server is listening...\n")
            self.csocket.send("Server is listening...\n".encode())
            recdata = self.csocket.recv(2048)
            clientdata = recdata.decode("ascii").split("|")
            code = int(clientdata[0])
            if code == 301:
                self.outputfile.write(f"From {self.clientaddr}: Received 301 request.\n")
                clientpubkey = clientdata[1]
                encname = base64.b64decode(clientdata[-1])
                # capubkeyfilename = "capubkey.pem"
                caprivkeyfilename = "caprivkey.pem"
                # capubkeyfile = open(capubkeyfilename,'rb')
                caprivkeyfile = open(caprivkeyfilename,'rb')
                # capubkey = serialization.load_pem_public_key(capubkeyfile.read())
                caprivkey = serialization.load_pem_private_key(caprivkeyfile.read(),password = None)
                clientname = base64.b64decode(caprivkey.decrypt(encname,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None)))
                self.outputfile.write(f"{self.clientaddr}: Decrypted client's name: { clientname }\n")
                nonce = base64.b64encode(os.urandom(8))
                self.outputfile.write(f"{self.clientaddr}: Generated 8 byte nonce.\n")
                clientpubkey = clientpubkey.encode("ascii")
                issuedate = date.today()
                expdate = issuedate.replace(year=issuedate.year+1)
                self.outputfile.write(f"{self.clientaddr}: Certificate expire date is: {expdate}.\n")
                certificate = clientname+nonce+clientpubkey+str(issuedate).encode("ascii")+str(expdate).encode("ascii")
                self.outputfile.write(f"{self.clientaddr}: Generated client certificate.\n")
                # print("Certificate:",certificate)
                signhash = caprivkey.sign(certificate,padding.PSS(mgf=padding.MGF1(algorithm=hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
                self.outputfile.write(f"{self.clientaddr}: Generated Hash of certificate and Signed the Hash using CA's private key.\n")
                RSAclientpubkey = serialization.load_pem_public_key(clientpubkey)
                enchash = RSAclientpubkey.encrypt(signhash,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
                self.outputfile.write(f"{self.clientaddr}: Encrypted signed-hash using client's public key.\n")
                datatoclient = "302".encode("ascii")+"|".encode("ascii")+base64.b64encode(clientname)+"|".encode("ascii")+base64.b64encode(certificate) +"|".encode("ascii")+ base64.b64encode(enchash)
                self.outputfile.write(f"To {self.clientaddr}: Sent 302 information.\n")
                self.csocket.send(datatoclient)

def start():
    port = 60000
    ip = ''
    try:
        opts,args = getopt.getopt(sys.argv[1:],"p:o:",["portnumber=","outputfile="])
    except getopt.GetoptError as err:
        print(err)
        print("Syntax: ./main -p <portnumber> -o <outputfile>")
        sys.exit(2)
    for o,a in opts:
        if o in ('-p','--portnumber'):
            port = int(a)
        elif o in ('-o','--outputfile'):
            outFileName = a
        else:
            assert False, "unhandled option"
    outputfile = open(outFileName,'w')
    print("Server started...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as skt:
        skt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        outputfile.write(f"Opening Socket on given portnumber:{port} over all interfaces.\n")
        skt.bind((ip,port)) #open socket to listen on a port number over all interfaces. can use 0.0.0.0 also, same action.
        outputfile.write(f"Listening...\n")
        while True:
            skt.listen(1)
            clientsocket,clientaddr = skt.accept()
            newthread = IssueCertificate(clientsocket,clientaddr,outputfile)
            newthread.start()

    outputfile.close()

if __name__ == "__main__":
    start()
















































#from PySide2.QtWidgets import QApplication
#if __name__ == "__main__":
#    app = QApplication([])
#    # ...
#    sys.exit(app.exec_())



#class clientSocket:
#    """demonstration class only
#      - coded for clarity, not efficiency
#    """

#    def __init__(self, sock=None):
#        if sock is None:
#            self.sock = socket.socket(
#                            socket.AF_INET, socket.SOCK_STREAM)
#        else:
#            self.sock = sock

#    def connect(self, host, port):
#        self.sock.connect((host, port))

#    def mysend(self, msg):
#        totalsent = 0
#        while totalsent < MSGLEN:
#            sent = self.sock.send(msg[totalsent:])
#            if sent == 0:
#                raise RuntimeError("socket connection broken")
#            totalsent = totalsent + sent

#    def myreceive(self):
#        chunks = []
#        bytes_recd = 0
#        while bytes_recd < MSGLEN:
#            chunk = self.sock.recv(min(MSGLEN - bytes_recd, 2048))
#            if chunk == b'':
#                raise RuntimeError("socket connection broken")
#            chunks.append(chunk)
#            bytes_recd = bytes_recd + len(chunk)
#        return b''.join(chunks)

#class ServerSocket:
#    """demonstration class only
#      - coded for clarity, not efficiency
#    """

#    def __init__(self, sock=None):
#        if sock is None:
#            self.sock = socket.socket(
#                            socket.AF_INET, socket.SOCK_STREAM)
#        else:
#            self.sock = sock

#    def bind(self, host, port):
#        self.sock.bind((host, port))

