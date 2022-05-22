import sys, getopt
import random, string
from Crypto import Random
from Crypto.PublicKey import RSA

def main(argv):
    key_ln = None
    mode = None

    try:
        opts, args = getopt.getopt(argv,"l:m:", ["length=","mode="])
    except getopt.GetoptError:
        sys.exit(2)
    
    for opt,arg in opts:
        if opt == '--mode':
            mode = arg
        if opt == '-l':
            key_ln = int(arg)

    if mode == 'aes':
        print('key: ', ''.join(random.choices(string.ascii_letters + string.digits, k=(key_ln//8))))
        print('iv:  ', ''.join(random.choices(string.ascii_letters + string.digits, k=(16))))
    elif mode == 'rsa':        
        key = RSA.generate(2048)
        privateKey = key.exportKey('PEM')
        publicKey = key.publickey().exportKey('PEM')

        with open('publicKey.pem', 'wb') as f:
            f.write(publicKey)

        with open('privateKey.pem', 'wb') as f:
            f.write(privateKey)

        print('publicKey.pem and privateKey.pem created successfully!')



    

    



        



if __name__ == '__main__':
    main(sys.argv[1:])