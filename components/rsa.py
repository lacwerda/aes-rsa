"""
Implementação da cifração e decifração RSA com OAEP.
"""
import hashlib
from components.KeyGen import primeKeyGeneration, RandomE
from egcd import egcd

class Rsa:
    def __init__(self, pQ = []):
        """
        Inicialização da classe Rsa e geração de chaves com o valores de p e q.
        """
        while len(pQ) < 2:
            number = primeKeyGeneration(1024)
            if number not in pQ:
                pQ.append(number)

        self.p, self.q = pQ
        self.E = RandomE((self.p - 1) * (self.q - 1))
        self.d = egcd(self.E, (self.p - 1) * (self.q - 1))[1]

        if self.d < 0:
            self.d += (self.p - 1) * (self.q - 1)
        
        self.publicKey = (self.p * self.q, self.E)
        self.privateKey = (self.p * self.q, self.d)

    def RsaEncryptionDecryption(self, input_bytes, cipher):
        """
        Cifração e decifração RSA.
        """
        return [pow(i, cipher[1], cipher[0]) for i in input_bytes]

    def mask(self, inputString, size, hashFunction=hashlib.sha3_256):
        """
        Gera uma bitmask.
        """
        contador, final = 0, b''
        while size > len(final):
            final += hashFunction(inputString + contador.to_bytes(4, 'big')).digest()
            contador = contador + 1
        final = final[:size]
        return final

    def OAEPEncryption(self, cipher, mensagem, seed = primeKeyGeneration(256)):
        """
        Realização de OAEP para cifração na mensagem atribuída como parâmetro.
        """
        sizeRSA, hashOutLen = 256, 32
        seed, lableHash = seed.to_bytes(32, 'big'), hashlib.sha3_256(b'')
        ps = (0).to_bytes(sizeRSA - len(mensagem) - 2*hashOutLen - 2, "big")

        dataBlock = lableHash.digest() + ps + (1).to_bytes(1, "big") + mensagem
        dataBlockMask = self.mask(seed, sizeRSA - hashOutLen - 1)
        maskedDataBlock = bytes(a ^ b for a, b in zip(dataBlock, dataBlockMask))
        seedMask = self.mask(maskedDataBlock, hashOutLen)
        maskedSeed = bytes(a ^ b for a, b in zip(seed, seedMask))
        
        encriptedMessage = (0).to_bytes(1, "big") + maskedSeed + maskedDataBlock
        return self.RsaEncryptionDecryption(list(encriptedMessage), cipher)

    def OAEPDecryption(self, cipher, criptograma):
        """
        Realização de OAEP para decifração na mensagem atribuída como parâmetro.
        """
        sizeRSA, hashOutLen = 256, 32
        final  = self.RsaEncryptionDecryption(list(criptograma), cipher)
        encriptedMessage = bytes(final)
        maskedDataBlock, y = encriptedMessage[-(sizeRSA - hashOutLen - 1) :], encriptedMessage[0]

        seed = bytes(first ^ second for first, second in zip(encriptedMessage[1 : hashOutLen + 1],
                                           self.mask(maskedDataBlock, hashOutLen)))
        dataBlockMask = self.mask(seed, sizeRSA - hashOutLen - 1)
        dataBlock = bytes(first ^ second for first, second in zip(maskedDataBlock, dataBlockMask))

        lableHash, messagePadding = dataBlock[: hashOutLen], dataBlock[hashOutLen :]
        for caracter in range(len(messagePadding)):
            if messagePadding[caracter] == 1:
                break
        return messagePadding[caracter + 1:]
