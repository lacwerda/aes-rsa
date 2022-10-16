from components.KeyGen import primeKeyGeneration
import numpy as np

class Aes:
    """
    Implementação da cifra AES.
    """
    def __init__(self, key = primeKeyGeneration(bits=128)):
        self.bytes = 16
        self.num_keys = 10

        try:
            key.to_bytes(self.bytes, 'big')
        except:
            raise

        self.key = key
        self.substitution_box = [[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
                                 [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
                                 [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
                                 [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
                                 [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
                                 [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
                                 [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
                                 [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
                                 [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
                                 [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
                                 [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
                                 [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
                                 [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
                                 [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
                                 [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
                                 [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]]
        self.pastNumberOnces = {}

    def SBoxTransformation(self, atual):
        """
        Transforma a matriz baseando-se na matriz de Substitution Box.
        """
        for row in range(4):
            for column in range(4):
                atual[row][column] = (self.substitution_box[atual[row][column] >> 4]
                                                           [atual[row][column] & 0x0F])
        return atual

    def MoveRows(self, atual):
        """
        Desloca cada uma das fileiras de 0 a 3 posições para a esquerda até que
        pare na posição designada.
        """
        for i in range(4):
            atual[i] = atual[i][i:] + atual[i][:i]
        return atual

    def GaloisMultiplication(self, a, b):
        """
        Multiplicação de A por B no corpo de Galois.
        """
        if b not in [1, 2, 3]:
            raise Exception("Valor de b inválido!")

        if b in [1]:
            return a
        aux = (a << 1) & 0x0ff
        if b in [2]:
            if a < 128:
                return aux
            return aux ^ 0x01b
        return self.GaloisMultiplication(a, 2) ^ a
    
    def ShuffleColumns(self, atual):
        """
        Summary.
        """
        for i in range(4):
            aux = [
            (self.GaloisMultiplication(atual[0][i], 2) ^
            self.GaloisMultiplication(atual[1][i], 3) ^
            self.GaloisMultiplication(atual[2][i], 1) ^
            self.GaloisMultiplication(atual[3][i], 1)),

            (self.GaloisMultiplication(atual[0][i], 1) ^
            self.GaloisMultiplication(atual[1][i], 2) ^
            self.GaloisMultiplication(atual[2][i], 3) ^
            self.GaloisMultiplication(atual[3][i], 1)),

            (self.GaloisMultiplication(atual[0][i], 1) ^
            self.GaloisMultiplication(atual[1][i], 1) ^
            self.GaloisMultiplication(atual[2][i], 2) ^
            self.GaloisMultiplication(atual[3][i], 3)),

            (self.GaloisMultiplication(atual[0][i], 3) ^
            self.GaloisMultiplication(atual[1][i], 1) ^
            self.GaloisMultiplication(atual[2][i], 1) ^
            self.GaloisMultiplication(atual[3][i], 2))
            ]

            for row in range(4):
                atual[row][i] = aux[row]
        return atual

    def AddRoundKey(self, atual, round_key_matrix):
        """
        Realiza a operação XOR em um elemento da matrix de Round Keys.
        """
        for row in range(4):
            for column in range(4):
                atual[row][column] = atual[row][column] ^ round_key_matrix[row][column]
        return atual

    @staticmethod
    def transpose_matrix(matrix):
        """
        Retorna a transposta da matriz fornecida como parâmetro.
        """
        columns, rows, list_of_columns = len(matrix[0]), len(matrix), []
        for column in range(columns):
            list_of_columns.append([matrix[row][column] for row in range(rows)])
        return list_of_columns
    
    def __int128_to_matrix4x4(self, n):
        """
        Transforma um número de 128 bits em uma matriz de 4x4 bytes.
        """
        b = np.array(list(n.to_bytes(self.bytes, 'big')))
        b.shape = (4, 4)
        return b.transpose()

    @staticmethod
    def xorBitwise(a, b):
        assert len(a) == len(b)
        return [a[index]^b[index] for index in range(len(a))]

    @staticmethod
    def returnColumn(matrix, colNumber):
        rows = len(matrix)
        return [matrix[row][colNumber] for row in range(rows)]
    
    def RoundKeyGenerator(self, key, iterations=10):
        """
        Gerador de Round Keys.
        """
        matrix_of_bytes = self.__int128_to_matrix4x4(key)
        keys, RoundConstants = [matrix_of_bytes], [[0] * 10] * 4
        RoundConstants[0] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

        for i in range(1, iterations+1):
            first_collumn = self.returnColumn(keys[i-1], 0)

            aux = [keys[i-1][(o+1) % len(keys[i-1])][:] for o in range(len(keys[i-1]))]
            last_collumn_op = self.SBoxTransformation(aux)
            last_collumn_op = self.returnColumn(last_collumn_op, -1)
            
            col0 = self.xorBitwise(self.xorBitwise(first_collumn, last_collumn_op),
                                   self.returnColumn(RoundConstants, i-1))
            col1 = self.xorBitwise(col0, self.returnColumn(keys[i-1], 1))
            col2 = self.xorBitwise(col1, self.returnColumn(keys[i-1], 2))
            col3 = self.xorBitwise(col2, self.returnColumn(keys[i-1], 3))
            
            keys.append(self.transpose_matrix([col0, col1, col2, col3]))
        return keys

    def AesEncryption(self, mensagem : list , iterations=10):
        """
        Realiza o ciframento AES em uma mensagem.
        """
        roundKeys = self.RoundKeyGenerator(self.key)
        mensagem = self.AddRoundKey(mensagem, roundKeys[0])
        for i in range(self.num_keys - 1):
            mensagem = self.ShuffleColumns(self.MoveRows(self.SBoxTransformation(mensagem)))
            mensagem = self.AddRoundKey(mensagem, roundKeys[i+1])

        mensagem = self.MoveRows(self.SBoxTransformation(mensagem))
        return self.AddRoundKey(mensagem, roundKeys[iterations])

    def CtrMaskOperations(self, texto, enc_or_dec):
        if enc_or_dec:
            numberOfBytes = np.array(list(bytes(texto, 'utf-8')))
        else:
            numberOfBytes = np.array(list(texto))

        EnDecText = numberOfBytes[: len(numberOfBytes) - (len(numberOfBytes) % 16)]
        EnDecText.shape = (int(len(EnDecText) / 16), 16)
        textoFinal = numberOfBytes[-(len(numberOfBytes) % 16) :]
        return EnDecText, textoFinal

    def CtrEncryption(self, texto, numberOnce = None):
        """
        Encriptação em modo Counter (CTR).
        """
        if not numberOnce:
            numberOnce = primeKeyGeneration(96)

        while numberOnce in self.pastNumberOnces:
            numberOnce = primeKeyGeneration(96)

        self.pastNumberOnces[numberOnce], y = True, (numberOnce << 32) + 1

        textoDecifrado, plainTextFinal = self.CtrMaskOperations(texto, enc_or_dec=1)
        criptograma = []

        for letra in textoDecifrado:
            counterBlock = self.__int128_to_matrix4x4(y).tolist()

            encript = self.AesEncryption(counterBlock)
            encript = np.array(encript)

            criptograma.append(np.bitwise_xor(letra, encript.transpose().flatten()))
            y += 1

        if len(plainTextFinal) != 128:
            counterBlock = self.__int128_to_matrix4x4(y).tolist()

            encript = self.AesEncryption(counterBlock)
            encript = np.array(encript)

            truncamento = encript.transpose().flatten()[: len(plainTextFinal)]
            criptograma.append(np.bitwise_xor(plainTextFinal, truncamento))

        bytesSaida = b""
        for caracterByte in criptograma:
            bytesSaida = bytesSaida + bytes(list(caracterByte))
        return [bytesSaida, numberOnce]

    def CtrDecryption(self, criptograma, numberOnce):
        """
        Decriptação em modo Counter (CTR).
        """
        textoCriptografado, textoCriptografadoFinal = self.CtrMaskOperations(criptograma, enc_or_dec=0)
        y, textoDecifrado = (numberOnce << 32) + 1, []

        for i in textoCriptografado:
            counterBlock = self.__int128_to_matrix4x4(y).tolist()

            encript = self.AesEncryption(counterBlock)
            encript = np.array(encript)

            textoDecifrado += list(np.bitwise_xor(i, encript.transpose().flatten()))
            y += 1

        if len(textoCriptografadoFinal) != 128:
            counterBlock = self.__int128_to_matrix4x4(y).tolist()

            encript = self.AesEncryption(counterBlock)
            encript = np.array(encript)

            truncamento = encript.transpose().flatten()[: len(textoCriptografadoFinal)]
            textoDecifrado += list(np.bitwise_xor(textoCriptografadoFinal, truncamento))
        return bytes(textoDecifrado).decode("utf-8")
