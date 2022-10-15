from components.aes import Aes
from components.rsa import Rsa
import base64

def main():
    # mensagem = open("test.txt", "r").read()

    aesObject1, aesObject2 = Aes(), Aes()

    # cifraDaMensagem, numberOnce = aesObject1.CtrEncryption(mensagem)
    
    # # """
    # # Escrita dos arquivos.
    # # """
    # with open("nonce.txt", "w") as arquivo:
    #     arquivo.write(str(numberOnce))

    # with open("mensagem_encrypted.txt", "wb") as arquivo:
    #     arquivo.write(base64.b64encode(cifraDaMensagem))

    """
    Leitura dos arquivos
    """
    with open("mensagem_encrypted.txt", "rb") as arquivo:
        g = base64.b64decode(arquivo.read())

    with open("nonce.txt", "r") as arquivo:
        nonce = int(arquivo.read())

    aesObject2 = Aes()

    mensagemFinal = aesObject2.CtrDecryption(g, nonce)

    print(mensagemFinal)

if __name__ == '__main__': 
    main()
