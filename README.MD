# Security lab

## To Generate Key

The below will generate key 
__command__ : ```python3 gen_key.py --mode [option] -l [no_of_bits]```<br>
__example1__ :  ```python3 gen_key.py --mode aes -l 128```<br>
__example2__ : ```python3 gen_key.py --mode rsa -l 1024```<br>

## For AES (ECB/CFB 128/256):
__FOR ENCRYPTION Command__ : ```python3 pyssl.py -e [encryption options] -k [generated key] -v [generated iv] -i [input file] -o [output_file]```<br>
__FOR DECRYPTION Command__ : ```python3 pyssl.py -d [encryption options] -k [generated key] -v [generated iv] -i [input file] -o [output_file]```<br><br>
__For encryption example1__ :  ```python3 pyssl.py -e aes-256-cfb -k t7EQ9iArWRM7vq9WUKWJqGSL5ImT5zn3 -v gWCZ0LbzD8ByaKc0 -i plain.txt -o output.txt```<br>
__For decryption example1__ :  ```python3 pyssl.py -d aes-256-cfb -k t7EQ9iArWRM7vq9WUKWJqGSL5ImT5zn3 -v gWCZ0LbzD8ByaKc0 -i output.txt -o plain_back.txt```<br><br>

__For encrytption example2__ : ```python3 pyssl.py -e aes-128-ecb -k t7EQ9iArWRM7vq9W -i plain.txt -o output.txt```<br>
__For decrytption example2__ : ```python3 pyssl.py -d aes-128-ecb -k t7EQ9iArWRM7vq9W -i output.txt -o plain_back.txt```<br>

##  For RSA:
__FOR ENCRYPTION Command__ : ```python3 pyssl.py -e [encryption options] -k [public key file] -i [input file] -o [output_file]```<br>
__FOR DECRYPTION Command__ : ```python3 pyssl.py -d [encryption options] -k [private key file] -i [input file] -o [output_file]```<br><br>
__For encryption example1__ :  ```python3 pyssl.py -e rsa -k publicKey.pem -i rsa_plain.txt -o output.txt```<br>
__For decryption example1__ :  ```python3 pyssl.py -d rsa -k privateKey.pem -i output.txt -o plain_back.txt```<br><br>

FOR GENERATE KEY:<br>
>`NOTE: python3 gen_key.py --mode rsa -l 1024`. It will create two files. One for public key and another for private key

## For SHA256:
__TO HASH COMMAND__ : ```python3 pyssl.py -h SHA256 -i [input file]``` <br>
__example1__ : ```python3 pyssl.py -h SHA256 -i plain.txt```<br> <br>

## For Verify signature:
__CREATE SIGNATURE COMMAND__: ```python3 pyssl.py -e create-rsa-signature -i [input file] -s [signature output file] -k [private key file]```<br>
__VERIFY SIGNATURE COMMAND__: ```python3 pyssl.py -e verify-rsa-signature -i [input file] -s [signature output file] -k [public key file]```<br><br>

__create signature example__ : ```python3 pyssl.py -e create-rsa-signature -i rsa_plain.txt -s signature.txt -k privateKey.pem```<br>
__verify signature example__ : ```python3 pyssl.py -e create-rsa-signature -i rsa_plain.txt -s signature.txt -k publicKey.pem```
