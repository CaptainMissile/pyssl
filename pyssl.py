import sys, getopt
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
import binascii
from Crypto.Signature import pss
from Crypto import Random
from Crypto.PublicKey import RSA
import time
import random,string


# ECB NEEDS PADDING, CFB DOESNT
# CFB NEED IV, ECB DOESNT

def aes_encryption(inp_file,out_file, enc_mode, key, iv= None):
    enc_mode_lst = enc_mode.split('-')

    block_size = int(enc_mode_lst[1])
    mode = enc_mode_lst[2]

    key =  bytes(key, encoding= 'utf-8')
    iv =   bytes(iv, encoding= 'utf-8')

    plain_text_str = ""

    if out_file is not None:
        with open(inp_file, 'r') as f:
            plain_text_str = f.read()
    else:
        plain_text_str=hash

    plain_text_bytes = bytes(plain_text_str, encoding="utf-8")
    
    cipher_setup = ""

    if mode == 'cfb':
        cipher_setup = AES.new(key, AES.MODE_CFB, iv)
        ct_bytes = cipher_setup.encrypt(plain_text_bytes)
    elif mode == 'ecb':
        cipher_setup = AES.new(key, AES.MODE_ECB)
        ct_bytes = cipher_setup.encrypt(pad(plain_text_bytes, block_size))
        
    ct = b64encode(ct_bytes).decode('utf-8')
    

    with open(out_file, 'w') as f:
        f.write(ct)


def aes_decryption(inp_file,out_file, enc_mode, key, iv= None):
    enc_mode_lst = enc_mode.split('-')
    block_size = int(enc_mode_lst[1])
    mode = enc_mode_lst[2]

    key =  bytes(key, encoding= 'utf-8')
    iv =   bytes(iv, encoding= 'utf-8')

    cipher_text_str = ""
    
    if out_file is not None:
        with open(inp_file, 'r') as f:
            cipher_text_str = f.read()
    else:
        cipher_text_str = inp_file

    cipher_text_bytes = b64decode(bytes(cipher_text_str, encoding="utf-8"))
    
    if mode == 'cfb':
        cipher_setup = AES.new(key, AES.MODE_CFB, iv)
        plain_bytes = cipher_setup.decrypt(cipher_text_bytes)
    elif mode == 'ecb':
        cipher_setup = AES.new(key, AES.MODE_ECB)
        plain_bytes = unpad(cipher_setup.decrypt(cipher_text_bytes),block_size)
        
    print(plain_bytes)
    

    with open(out_file, 'w') as f:
        f.write(plain_bytes.decode("utf-8"))



def rsa_encryption(inp_file, out_file, key):
    public_key = open(key).read()
    RSApublicKey = RSA.importKey(public_key)
    rsa_setup = PKCS1_OAEP.new(RSApublicKey)

    plain_text_str = ""
    if out_file is not None:
        with open(inp_file, 'r') as f:
            plain_text_str = f.read()
    else:
        plain_text_str = inp_file

    plain_text_bytes = bytes(plain_text_str, encoding="utf-8")

    cipher = rsa_setup.encrypt(plain_text_bytes)

    ct = b64encode(cipher).decode('utf-8')
    
    if out_file is not None:
        with open(out_file, 'w') as f:
            f.write(ct)
    else:
        print(ct)


def rsa_decryption(inp_file, out_file, key):
    private_key = open(key).read()
    RSAprivateKey = RSA.importKey(private_key)
    rsa_setup = PKCS1_OAEP.new(RSAprivateKey)

    cipher_text_str = ""
    if out_file is not None:
        with open(inp_file, 'r') as f:
            cipher_text_str = f.read()
    else:
        cipher_text_str = inp_file

    cipher_text_bytes = b64decode(bytes(cipher_text_str, encoding="utf-8"))
    plain_text_bytes = rsa_setup.decrypt(cipher_text_bytes)

    if out_file is not None:
        with open(out_file, 'w') as f:
            f.write(plain_text_bytes.decode("utf-8"))
    else:
        print(plain_text_bytes.decode("utf-8"))


def create_rsa_signature(inp_file, signature_file, private_key):
    key = RSA.import_key(open(private_key).read())

    plain_text_str = ""
    with open(inp_file, 'r') as f:
        plain_text_str = f.read()

    plain_text_bytes = bytes(plain_text_str, encoding="utf-8")

    h = SHA256.new(plain_text_bytes)
    signature_bytes = pss.new(key).sign(h)

    signature = b64encode(signature_bytes).decode('utf-8')

    with open(signature_file, 'w') as f:
        f.write(signature)



    


def verify_rsa_signature(inp_file,sign_file, public_key):
    public_key = RSA.import_key(open(public_key).read())

    plain_text_str = ""
    with open(inp_file, 'r') as f:
        plain_text_str = f.read()

    plain_text_bytes = bytes(plain_text_str, encoding="utf-8")
    h = SHA256.new(plain_text_bytes)

    verifier = pss.new(public_key)
    try:
        signature_str = ""
        with open(sign_file, 'r') as f:
            signature_str = f.read()

        signature = b64decode(bytes(signature_str, encoding="utf-8"))

        verifier.verify(h, signature)
        print("The signature is authentic.")
    except (ValueError, TypeError):
        print("The signature is not authentic.")
    


def SHA256_Hash(inp_file):
    plain_text_str = ""
    with open(inp_file, 'r') as f:
        plain_text_str = f.read()

    plain_text_bytes = bytes(plain_text_str, encoding="utf-8")

    print(SHA256.new(plain_text_bytes).hexdigest())

    return SHA256.new(plain_text_bytes).hexdigest()


    


def main(argv):
    inp_file = "";out_file = "";key = "";iv = "";sign_file=""
    enc_mode = "";dec_mode = "";hash_mode = "";
    key_ln = None; gen_key=None; privateKey=None;publicKey=None

    opts, args = getopt.getopt(argv,"g:l:k:v:i:o:e:d:p:h:s:", ["gen_key=","length=",
                'key=','iv=','input=','output=','enc=','dec=','prun=','hash=','sign='])

    for opt, arg in opts:
        if opt in ('-i','--input'):
            inp_file = arg
        elif opt in ('-o', '--output'):
            out_file = arg
        elif opt in ('-s', '--sign'):
            sign_file = arg
        elif opt in ('-k','--key'):
            key = arg
        elif opt in ('-v','--iv'):
            iv = arg
        elif opt in ('-e', '--enc'):
            enc_mode = arg
        elif opt in ('-d', '--dec'):
            dec_mode = arg
        elif opt in ('-h', '--hash'):
            hash_mode = arg
        elif opt in ('-l', '--length'):
            key_ln = int(arg)
        elif opt in ('-g', '--gen_key'):
            gen_key = arg


    if len(enc_mode) > 0:
        if enc_mode.split('-')[0] == 'aes':
            aes_encryption(inp_file, out_file, enc_mode, key, iv)
        elif enc_mode.split('-')[0] == 'rsa':
            rsa_encryption(inp_file, out_file, key)
        elif enc_mode == 'create-rsa-signature':
            create_rsa_signature(inp_file,sign_file,key)
        elif enc_mode == 'verify-rsa-signature':
            verify_rsa_signature(inp_file ,sign_file,key)

    elif len(dec_mode) > 0:
        if dec_mode.split('-')[0] == 'aes':
            aes_decryption(inp_file, out_file, dec_mode, key, iv)
        if dec_mode.split('-')[0] == 'rsa':
            rsa_decryption(inp_file, out_file, key)
    elif hash_mode == 'SHA256':
            SHA256_Hash(inp_file)
    elif gen_key == 'aes':
        print('key: ', ''.join(random.choices(string.ascii_letters + string.digits, k=(key_ln//8))))
        print('iv:  ', ''.join(random.choices(string.ascii_letters + string.digits, k=(16))))
    elif gen_key == 'rsa':        
        key = RSA.generate(2048)
        privateKey = key.exportKey('PEM')
        publicKey = key.publickey().exportKey('PEM')

        with open('publicKey.pem', 'wb') as f:
            f.write(publicKey)
            print('Success! RSA Public Key for RSA File Created Successfully.')

        with open('privateKey.pem', 'wb') as f:
            f.write(privateKey)
            print('Success! RSA Private Key File Created Successfully.')
    

        
if __name__ == '__main__':
    main(sys.argv[1:])    


    # FOR AES TIME TEST
    # n = [16,64,96,128,256]
    # arr = []
    # for i in n:
    #     start_time = time.time()
    #     enc_mode = f'aes-{i}-ecb'
    #     key = ''.join(random.choices(string.ascii_letters + string.digits, k=16 ))
    #     iv = ''.join(random.choices(string.ascii_letters + string.digits, k=(16)))

    #     aes_encryption('plain.txt', 'out.txt', enc_mode , key, iv)
    #     arr.append(time.time()-start_time)
    
    # print(arr)

    # FOR RSA TIME TEST
    # n = [1024,1536,2048,2560,3072]
    # message=b"Hello darkness my old friend. I have come to talk with you again"
    # arr = []
    # for i in n:
    #     start_time = time.time()
    #     key = RSA.generate(i)
    #     privateKey = key.exportKey('PEM')
    #     publicKey = key.publickey().exportKey('PEM')

    #     RSApublicKey = RSA.importKey(publicKey)
    #     OAEP_cipher = PKCS1_OAEP.new(RSApublicKey)
    #     encryptedMsg = OAEP_cipher.encrypt(message)

    #     RSAprivateKey = RSA.importKey(privateKey)
    #     OAEP_cipher = PKCS1_OAEP.new(RSAprivateKey)

    #     decryptedMsg = OAEP_cipher.decrypt(encryptedMsg)
    #     arr.append(time.time()-start_time)
        
    # print(arr)



