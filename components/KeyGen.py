import random
from egcd import egcd
import secrets

dice = random.SystemRandom()

def auxMillerRabin(number, witness): # n, a
    """
    Função auxiliar para performar o teste de primalidade de Miller-Rabin.
    """
    exponent = number - 1
    while not exponent % 2:
        exponent >>= 1

    if pow(witness, exponent, number) == 1:
        return True
    
    while exponent < number-1:
        if pow(witness, exponent, number) == number - 1:
            return True
        exponent <<= 1
    return False

def MillerRabin(number, number_of_witnesses=40):
    """
    Função que performa o teste de primalidade de Miller-Rabin.
    """
    for _ in range(number_of_witnesses):
        witness = dice.randrange(2, number-1)
        if not auxMillerRabin(number, witness):
            return False
    return True

def primeKeyGeneration(bits=1024):
    """
    Geração de número primo que utliza o teste de Miller-Rabin para provar sua
    primalidade.
    """
    number = dice.getrandbits(bits)
    if not number%2:
        number += 1
    while not MillerRabin(number):
        number += 2
    return number

def RandomE(maxi):
    """
    Gera um número maior que 1024 bits e menor que o parâmtro maxi.
    """
    numberE = secrets.randbelow(maxi)
    while egcd(maxi, numberE)[0] != 1:
        numberE = secrets.randbelow(maxi)
    return numberE
