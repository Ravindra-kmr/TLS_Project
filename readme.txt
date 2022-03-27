README
Comments about code:
    * All programs are working and there are no bugs.
    * Uncomment the requestCertifiate() function call line in client.py and server.py to request certificate from CA.
    * PRF is according to the textbook.
    * TLS Record is according to the textbook format.

1. Running the Server:  python3 server.py -n name -m S -q 10000
2. Running the Client:  python3 client.py -n myname -m R -d 0.0.0.0 -q 10000

* Note Used latest version of Cryptography package (37.0)
To install it in your computer please follow following steps:
- $sudo python3 -m pip install -U pip3
- $sudo python3 -m pip install -U setuptools
- $curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
- $pip3 install -U cryptography


To generate RSA PUBLIC AND PRIVATE Key:
To create private key: openssl genrsa -out private.pem 2048
To create corresponding public key: openssl rsa -in private.pem -outform PEM -pubout -out public.pem

~ HTML Files where taken from freecodecamp website.
