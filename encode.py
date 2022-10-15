from components.aes import Aes
from components.rsa import Rsa

def main():
    mensagem = open("test.txt", "r").read()
    # mensagem = "bia bia"

    pabllo = Rsa()
    aesObject1 = Aes()
    aesObject2 = Aes()

    cifraDaMensagem, numberOnce = aesObject1.CtrEncryption(mensagem)
    nonceEncrypted = pabllo.OAEPEncryption(pabllo.publicKey, numberOnce.to_bytes(16, "big"))

    nonceDecrypted = pabllo.OAEPDecryption(pabllo.privateKey, nonceEncrypted)
    mensagemFinal = aesObject2.CtrDecryption(cifraDaMensagem, int.from_bytes(nonceDecrypted, 'big'))
    print(mensagemFinal)

    assert mensagem == mensagemFinal

if __name__ == '__main__': 
    main()
