from components.aes import Aes
from components.rsa import Rsa
import hashlib

def main():
    file = open("", "r").read()
    calcular_hash = hashlib.sha3_256(bytes(list(bytes(file, 'utf-8')))).digest()

    bia = Rsa()
    samuel = Aes()
    print("oi")

if __name__ == '__main__': 
    main()
