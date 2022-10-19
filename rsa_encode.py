from components.rsa import Rsa

def main():
    mensagem = open("files/test.txt", "r").read()

    if len(mensagem) > 186:
        mensagem = mensagem[:186]

    bia = Rsa()

    mensagem_cifrada = bia.OAEPEncryption(bia.publicKey, bytes(mensagem, 'utf-8'))

    """
    Leitura dos arquivos
    """
    # with open("files/mensagem_encrypted.txt", "rb") as arquivo:
    #     mensagem_cifrada = base64.b64decode(arquivo.read())

    # with open("files/nonce.txt", "r") as arquivo:
    #     nonce = int(arquivo.read())

    mensagem_final = bia.OAEPDecryption(bia.privateKey, mensagem_cifrada).decode("utf-8")

    assert mensagem_final == mensagem

    print(mensagem_final)

if __name__ == '__main__': 
    main()
