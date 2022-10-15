from aes import Aes
from rsa import Rsa
import hashlib
import base64
from pickle import dumps, loads

print("[SEGURANÇA COMPUTACIONAL 2022.1]".center(100))
print()

mensagem = ("E Deus criou as grandes baleias, e todo o réptil de alma vivente " +
            "que as águas abundantemente produziram conforme as suas espécies; " +
            "e toda a ave de asas conforme a sua espécie; e viu Deus que era bom.")

print(f"Mensagem utilizada para testagem:\n\n  {mensagem}\n")

input("[Aperte ENTER para continuar.]\n")

print("PARTE I: Geração de chaves")
print(f"Geração de p e q primos com no mínimo de 1024 bits:\n")

anitta, pabllo = Rsa(), Rsa()
aesObject, rsaObject = Aes(), Rsa()

print(f" anitta.p:\n\n{anitta.p}\n")
input("[Aperte ENTER para continuar.]\n")

print(f" anitta.q:\n\n{anitta.q}\n")
input("[Aperte ENTER para continuar.]\n")

print(f" pabllo.p:\n\n{pabllo.p}\n")
input("[Aperte ENTER para continuar.]\n")

print(f" pabllo.q:\n\n{pabllo.q}\n")
input("[Aperte ENTER para continuar.]\n")

print("Geração de chaves públicas e privadas:\n")

print(f" anitta.privateKey:\n\n{anitta.privateKey}\n")
input("[Aperte ENTER para continuar.]\n")

print(f" anitta.publicKey:\n\n{anitta.publicKey}\n")
input("[Aperte ENTER para continuar.]\n")

print(f" pabllo.privateKey:\n\n{pabllo.privateKey}\n")
input("[Aperte ENTER para continuar.]\n")

print(f" pabllo.publicKey:\n\n{pabllo.publicKey}\n")
input("[Aperte ENTER para continuar.]\n")

print("PARTE II: Cifra simétrica\n")

calcular_hash = hashlib.sha3_256(bytes(list(bytes(mensagem, 'utf-8')))).digest()

hashEncriptado = rsaObject.RsaEncryptionDecryption(list(calcular_hash), anitta.privateKey)
cifraDaMensagem, numberOnce = aesObject.CtrEncryption(mensagem)

print(f" Texto criptografado com AES modo CTR:\n{cifraDaMensagem}\n")
print(f" Nonce utilizado no AES modo CTR: {numberOnce}\n")
input("[Aperte ENTER para continuar.]\n")

print("PARTE III: Geração da assinatura\n")
print("Escrita de hash, criptograma e chave da sessão em Base64...\n")

keyAesObject = aesObject.key.to_bytes(16, "big")
chaveCifrada = pabllo.OAEPEncryption(pabllo.publicKey, keyAesObject)

print("Feito!\n")
input("[Aperte ENTER para continuar.]\n")

"""
Escrita do hash, criptograma e chave da sessão codificados na base 64 em
arquivos .txt.
"""
with open("cifraDaMensagem.txt", "wb") as arquivo:
    arquivo.write(base64.b64encode(cifraDaMensagem))
with open("hash.txt", "wb") as arquivo:
    arquivo.write(base64.b64encode(dumps(hashEncriptado)))
with open("chaveCifradaDaSessao.txt", "wb") as arquivo:
    arquivo.write(base64.b64encode(dumps(chaveCifrada)))

print("Checar os arquivos:")
print("  - cifraDaMensagem.txt")
print("  - hash.txt")
print("  - chaveCifradaDaSessao.txt")
print()
input("[Aperte ENTER para continuar.]\n")

print("PARTE IV: Verificação\n")
print("Leitura de arquivos e verificação dos resultados em relação ao valor original:\n")

"""
Leitura dos arquivos.
"""
with open("hash.txt", "rb") as arquivo:
    hashBase64 = loads(base64.b64decode(arquivo.read()))
with open("cifraDaMensagem.txt", "rb") as arquivo:
    cifraMensagemBase64 = base64.b64decode(arquivo.read())
with open("chaveCifradaDaSessao.txt", "rb") as arquivo:
    chaveDaSessaoBase64 = loads(base64.b64decode(arquivo.read()))

assert hashBase64 == hashEncriptado
print(f"assert hashBase64 == hashEncriptado [\u2713]")

assert cifraMensagemBase64 == cifraDaMensagem
print(f"assert cifraMensagemBase64 == cifraDaMensagem [\u2713]")

assert chaveDaSessaoBase64 == chaveCifrada
print(f"assert chaveDaSessaoBase64 == chaveCifrada [\u2713]")

print()
input("[Aperte ENTER para continuar.]\n")

print("Decifração da chave, da mensagem e da assinatura..\n")

chaveDaSessaoDecifrada = pabllo.OAEPDecryption(pabllo.privateKey, chaveDaSessaoBase64)
hashDecriptado = rsaObject.RsaEncryptionDecryption(hashBase64, anitta.publicKey)
aesObject.key = int.from_bytes(chaveDaSessaoDecifrada, 'big')

mensagemFinal = aesObject.CtrDecryption(cifraMensagemBase64, numberOnce)
bytesHashDecriptado = bytes(hashDecriptado)

print("Comparação do hash decriptado e do novo hash sha3_256 gerado:\n")
print(f" Hash Decriptado:\n{hashDecriptado}\n")
print(f" Bytes do Hash Decriptado:\n{bytesHashDecriptado}\n")
input("[Aperte ENTER para continuar.]\n")

novoHash = hashlib.sha3_256(bytes(mensagemFinal, 'utf-8')).digest()
print(f"Bytes do novo hash gerado:\n{novoHash}\n")

assert novoHash == bytesHashDecriptado

print(f"assert novoHash == bytesHashDecriptado [\u2713]\n")
input("[Aperte ENTER para continuar.]\n")

print(f" Mensagem decifrada:\n\n{mensagemFinal}\n")

assert mensagem == mensagemFinal
print(f"assert mensagem == mensagemFinal [\u2713]\n")