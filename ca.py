import argparse
import logging
import socket
import base64
import signal
import sys
import threading
import datetime
import base64
import string
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from utils import log, GracefulSocketKiller


parser = argparse.ArgumentParser()

parser.add_argument('-p', '--portid',
                     help='CA listens to this port',
                     type=int,
                     required=True)

parser.add_argument('-o', '--outfilename',
                     help='CA writes diagnostics to this file',
                     required=True)

args = parser.parse_args()

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.FileHandler(args.outfilename))


private_key = rsa.generate_private_key(public_exponent=65537,
                               key_size=2048)

public_key = private_key.public_key()

print("Generated RSA keys")

with open("ca_pub_key.pem", "wb") as key_file:
    pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
    key_file.write(pem)

print("Finished writing public key to file")


@log(logger)
def run_CA(port):
    
    print("Starting CA ...")
    HOST = ''                 
    print("Press ctrl+c to exit...")
    
    current_threads = []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, port))
        # socket_killer = GracefulSocketKiller(s)
        print(f"Start listening on port: {port}")
        # while not socket_killer.kill_now:
        while True:
            s.listen(2)
            conn, addr = s.accept()
            print(f"Connected with: {addr}")
            t = threading.Thread(target=handle_client, args=[conn, addr])
            t.start()
            current_threads.append(t)


def handle_client(conn, addr):
    with conn:
        while True:
            data = conn.recv(2048)
            print(f"Received: {data}")
            if not data:
                    break

            code, client_pub_key, client_name_enc = data.decode(
                                                    'ascii').split('|')
            client_name = private_key.decrypt(
                        base64.b64decode(client_name_enc),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
            print(f"Code: {code}; Client Name: {client_name.decode('ascii')}")

            if code == "301":
                certificate = prepare_certificate(client_pub_key.encode('ascii'), client_name)
                msg = b"302" + b"|" + client_name + b'|' + certificate
                conn.sendall(msg)


@log(logger)
def prepare_certificate(client_pub_key, client_name):
    
    alphabet = string.ascii_letters + string.digits
    nonce = ''.join(secrets.choice(alphabet) for i in range(8)).encode('ascii')
    
    today = datetime.date.today()
    start_date = f"{today.year}-{today.month:02}-{today.day:02}"
    end_date = f"{today.year + 1}-{today.month:02}-{today.day:02}"
    
    cert_data = client_name + b'*' + \
                nonce + b'*' + \
                client_pub_key + b'*' + \
                start_date.encode("ascii") + b'*' + \
                end_date.encode("ascii")


    print(f"\nCert-Data:\n {cert_data}")
    
    digest = hashes.Hash(hashes.SHA256())
    digest.update(cert_data)
    cert_data_hash = digest.finalize()

    signature = private_key.sign(cert_data_hash,
                             padding.PSS(
                                 mgf=padding.MGF1(hashes.SHA256()),
                                 salt_length=padding.PSS.MAX_LENGTH),
                             hashes.SHA256())

    client_pub_key = serialization.load_pem_public_key(client_pub_key)
    # signature = base64.b64encode(signature)
    print(f"\nSize of signature: {len(signature)}\n")

    print(f"signature: {signature}")
    encrypted_sign = client_pub_key.encrypt(
                        signature,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None))
    
    certificate = cert_data + b'|' + base64.b64encode(encrypted_sign)
    print(f"\nSize of Certificate: {len(certificate)}\n")

    return certificate


def signal_handler(sig, frame):
    print('Exiting ...')
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    run_CA(args.portid)