from components.aes import Aes
import base64

def encode():
    mensagem = open("test.txt", "r").read()

    # aesObject1, aesObject2 = Aes(), Aes()
    aesObject1 = Aes()
    cifraDaMensagem, numberOnce = aesObject1.CtrEncryption(mensagem)
    print(f"cifraDaMensagem: {cifraDaMensagem}\n")
    k = base64.b64encode(cifraDaMensagem)
    print(f"{k}\n")
    print(f"{base64.b64decode(k)}\n")
    
    # """
    # Escrita dos arquivos.
    # """
    with open("nonce.txt", "w") as arquivo:
        arquivo.write(str(numberOnce))

    with open("key.txt", "w") as arquivo:
        arquivo.write(str(aesObject1.key))

    with open("mensagem_encrypted.txt", "wb") as arquivo:
        arquivo.write(base64.b64encode(cifraDaMensagem))

    """
    Leitura dos arquivos
    """
    # with open("mensagem_encrypted.txt", "rb") as arquivo:
    #     z = arquivo.read()
    #     print(f"{z}\n")
    #     g = base64.b64decode(z)
    #     print(f"{g}\n")

    # with open("nonce.txt", "r") as arquivo:
    #     nonce = int(arquivo.read())

    # with open("nonce.txt", "r") as arquivo:
    #     key = int(arquivo.read())

    # aesObject2 = Aes()

    # mensagemFinal = aesObject2.CtrDecryption(g, nonce)

    # print(mensagemFinal)

encode()