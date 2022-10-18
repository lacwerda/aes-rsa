from components.aes import Aes
from components.rsa import Rsa
import base64

def main():
    mensagem = open("files/test.txt", "r").read()

    bia, samuel = Aes(), Aes()

    cifra_mensagem, number_once = samuel.CtrEncryption(mensagem)
    
    """
    Escrita dos arquivos.
    """
    with open("files/nonce.txt", "w") as arquivo:
        arquivo.write(str(number_once))

    with open("files/mensagem_encrypted.txt", "wb") as arquivo:
        arquivo.write(base64.b64encode(cifra_mensagem))

    """
    Leitura dos arquivos
    """
    with open("files/mensagem_encrypted.txt", "rb") as arquivo:
        g = base64.b64decode(arquivo.read())

    with open("files/nonce.txt", "r") as arquivo:
        nonce = int(arquivo.read())

    mensagem_final = bia.CtrDecryption(g, nonce)

    print(mensagem_final)

if __name__ == '__main__': 
    main()
