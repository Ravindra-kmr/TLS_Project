import argparse
import base64 
import time
import logging
import socket
from urllib import response
import sys
import os 

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from utils import log


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.FileHandler("k"))

private_key = rsa.generate_private_key(public_exponent=65537,
                               key_size=4096)

public_key = private_key.public_key()

time.sleep(1)


def verify_certificate(certificate):
    with open("ca_pub_key.pem", "rb") as key_file:
        ca_pub_key = serialization.load_pem_public_key(key_file.read())
    
    cert_data, cert_data_hash_signed = certificate

    digest = hashes.Hash(hashes.SHA256())
    digest.update(cert_data.encode('ascii'))
    cert_data_hash = digest.finalize()
    
    cert_data_hash_signed = base64.b64decode(cert_data_hash_signed)   

    try:
        ca_pub_key.verify(
                    cert_data_hash_signed,
                    cert_data_hash,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256())
    except InvalidSignature:
        print("Unable to verify signature!")
        return False
    
    return True


def receiver_protocol(args):

    print("Starting Receiver ...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"Connecting to {args.senderip} on port {args.senderport} ...")
        s.connect((args.senderip, args.senderport))
        print("Connection success!")
        input_file = args.inputfile.encode('ascii')
        sender_request = b"501" + b'|' + args.myname.encode("ascii")
        print(f"Sending: {sender_request}; Size:{len(sender_request)}")
        s.sendall(sender_request)
        sender_name = ""
        decryptor = None
        while True:
            data = s.recv(2048)
            print('Received', repr(data))
            if not data:
                if decryptor is not None:
                    with open(args.outfile, 'w') as g:
                        data = decryptor.finalize() 
                        g.write(data.decode("ascii"))
                
                break
            
            code, *rest = data.decode("ascii").split("|")
            if code == "502":
                sender_name = rest[0]
                sender_certificate = rest[1:]
                print(f"Sender-Name: {sender_name};\n Sender-Certificate:\n {sender_certificate}\n")
                if not verify_certificate(sender_certificate):
                    print("Unable to verify certificate")
                    sys.exit(0)
                else:
                    session_key = os.urandom(24) + os.urandom(16) 
                    with open(f"{sender_name}_pub_key.pem", "rb") as key_file:
                        sender_pub_key = serialization.load_pem_public_key(key_file.read())
                    
                    session_key_enc = sender_pub_key.encrypt(
                        session_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    msg = b'503' + b"|" + base64.b64encode(session_key_enc) + b"|" + input_file
                    cipher = Cipher(algorithms.AES(session_key[:24]), modes.CTR(session_key[24:]))
                    decryptor = cipher.decryptor()
            
                s.sendall(msg)
            
            elif sender_name != "" and code == "504":
                with open(args.outenc, 'w') as f:
                    f.write(rest[1])
                
                with open(args.outfile, 'w') as g:
                    data = decryptor.update(base64.b64decode(rest[1])) 
                    print(f"\nDECRYPTED_FILE_CONTENTS:\n\n{data}\n\n")
                    g.write(data.decode("ascii"))
            else:
                sys.exit(0)


def sender_protocol(args):
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', args.clientport))
        print(f"Start listening on port: {args.clientport}")
        s.listen()
        conn, addr = s.accept()
        print(f"Connected with: {addr}")
        recvr_name = ""
        with conn:
            while True:
                data = conn.recv(2048)
                print(f"Received: {data}")
                if not data:
                     break
                code, *rest = data.decode("ascii").split("|")
                if code == "501":
                    with open(f"{args.myname}_cert", "r") as f:
                        certificate = f.read()
                    
                    recvr_name = rest[0]
                    msg = b"502" + b"|" + args.myname.encode("ascii") + b"|" + certificate.encode("ascii") 
                    conn.sendall(msg)
                elif recvr_name != "" and code == "503":
                    session_key_enc = rest[0]
                    file_name = rest[1]
                    session_key = private_key.decrypt(
                                        base64.b64decode(session_key_enc),
                                        padding.OAEP(
                                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                            algorithm=hashes.SHA256(),
                                            label=None
                                        )
                                    )
                    cipher = Cipher(algorithms.AES(session_key[:24]), modes.CTR(session_key[24:]))
                    encryptor = cipher.encryptor()
                    msg = b"504" + b"|" + file_name.encode("ascii") + b"|"
                    with open(file_name, "r") as f:
                        while True:
                            data = f.read(512)
                            if not data:
                                break
                            print(f"\nFILE_CONTENTS:\n\n{data}\n\n")
                            
                            data = base64.b64encode(encryptor.update(data.encode("ascii")))
                            conn.sendall(msg + data)
                            
                        data = encryptor.finalize()
                        conn.sendall(base64.b64encode(msg + data))
                        conn.close()
                        sys.exit(0)

                else:
                    sys.exit(0)


def get_CA_certificate(args):

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"Connecting to CA at {args.caip} on port {args.caport} ...")
        s.connect((args.caip, args.caport))
        print("Connection success!")
        pub_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        
        with open("ca_pub_key.pem", "rb") as key_file:
            ca_pub_key = serialization.load_pem_public_key(key_file.read())

        name_enc = ca_pub_key.encrypt(
                        args.myname.encode('ascii'),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
        name_enc = base64.b64encode(name_enc)
        ca_request = b'301' + b'|' + pub_key_pem + b'|' + name_enc
        print(f"Sending: {ca_request}; Size: {len(ca_request)}")
        s.sendall(ca_request)
        response = s.recv(2048)
        print('Received', repr(response))
        code, name, cert_data, cert_data_hash_enc = response.decode('ascii').split('|')

        if code == "302":
            digest = hashes.Hash(hashes.SHA256())
            digest.update(cert_data.encode('ascii'))
            cert_data_hash = digest.finalize()

            cert_data_hash_enc = base64.b64decode(cert_data_hash_enc)
            
            cert_data_hash_signed = private_key.decrypt(
                                        cert_data_hash_enc,
                                        padding.OAEP(
                                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                            algorithm=hashes.SHA256(),
                                            label=None
                                        )
                                    )
            try:
                ca_pub_key.verify(
                            cert_data_hash_signed,
                            cert_data_hash,
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256())
            except InvalidSignature:
                print("Unable to verify signature!!")
                sys.exit(0)

            certificate = cert_data + "|" + base64.b64encode(cert_data_hash_signed).decode("ascii")
            with open(f"{name}_cert", 'w') as f:
                f.write(certificate)
    
    return 
    

parser = argparse.ArgumentParser()

parser.add_argument( '-n', '--myname',
                     help='Client will have this name',
                     required=True)

subparsers = parser.add_subparsers(title="mode", help='Mode help')

parser_R = subparsers.add_parser('R', help='Sets client to receiver mode')
parser_S = subparsers.add_parser('S', help='Sets client to sender mode')

parser_S.add_argument('-a', '--caip',
                     help='Sender will connect to CA at this ip-address',
                     required=True)

parser_S.add_argument('-p', '--caport',
                     help='Sender will connect to CA at this port address',
                     type=int,
                     required=True)

parser_S.add_argument('-q', '--clientport',
                     help='Sender will listen to other clients via this port',
                     type=int,
                     required=True)

parser_S.set_defaults(func=sender_protocol)

parser_R.add_argument('-i', '--inputfile',
                     help='Sender will send the encrypted contents of this file to the receiver',
                     required=True)

parser_R.add_argument('-d', '--senderip',
                     help='Receiver will connect to sender having this ip-address',
                     required=True)

parser_R.add_argument('-q', '--senderport',
                     help='Receiver will connect to the sender listening to this port',
                     type=int,
                     required=True)

parser_R.add_argument('-s', '--outenc',
                     help='Receiver will write the encrypted contents from the sender to this file',
                     required=True)

parser_R.add_argument('-o', '--outfile',
                     help='Receiver will write the decrypted contents from the sender to this file',
                     required=True)

parser_R.add_argument('-a', '--caip',
                     help='Receiver will connect to CA at this ip-address',
                     required=True)

parser_R.add_argument('-p', '--caport',
                     help='Receiver will connect to CA at this port address',
                     type=int,
                     required=True)

parser_R.set_defaults(func=receiver_protocol)

args = parser.parse_args()

with open(f"{args.myname}_pub_key.pem", "wb") as key_file:
    pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
    key_file.write(pem)

get_CA_certificate(args)

time.sleep(10)

args.func(args)




