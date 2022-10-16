from components.aes import Aes
import numpy as np

class TestAes:
    def test_MoveRows(self):
        teste = np.array([[1, 2, 3, 4],
                        [5, 6, 7, 8 ],
                        [9, 10, 11, 12],
                        [13, 14, 15, 16]])

        correct_result = np.array([[1, 2, 3, 4],
                        [ 6, 7, 8, 5],
                        [11, 12, 9, 10],
                        [16, 13, 14, 15]])

        aes = Aes()
        result = aes.MoveRows(teste)
        assert np.array_equal(result, correct_result)

    def test_SubBytes(self):
        teste = np.array([
                [0x19, 0xA0, 0x9A, 0xE9],
                [0x3D, 0xF4, 0xC6, 0xF8],
                [0xE3, 0xE2, 0x8D, 0x48],
                [0xBE, 0x2B, 0x2A, 0x08],
                ])

        correct_result = np.array([
                [0xD4, 0xE0, 0xB8, 0x1E],
                [0x27, 0xBF, 0xB4, 0x41],
                [0x11, 0x98, 0x5D, 0x52],
                [0xAE, 0xF1, 0xE5, 0x30],
                ])
        
        aes = Aes()
        result = aes.SubBytes(teste)
        assert np.array_equal(result, correct_result)

    def test_ShuffleColumns(self):
        aes = Aes()

        teste = np.array([
        [0xd4, 0xe0, 0xb8, 0x1e],
        [0xbf, 0xb4, 0x41, 0x27],
        [0x5d, 0x52, 0x11, 0x98],
        [0x30, 0xae, 0xf1, 0xe5]
        ])

        correct_result = np.array([
        [0x04, 0xe0, 0x48, 0x28],
        [0x66, 0xcb, 0xf8, 0x06],
        [0x81, 0x19, 0xd3, 0x26],
        [0xe5, 0x9a, 0x7a, 0x4c]
        ])

        result = aes.ShuffleColumns(teste)
        assert np.array_equal(result, correct_result)

    def test_AddRoundKey(self):
        teste1= np.array([
                [0x04, 0xe0, 0x48, 0x28],
                [0x66, 0xcb, 0xf8, 0x06],
                [0x81, 0x19, 0xd3, 0x26],
                [0xe5, 0x9a, 0x7a, 0x4c]
                ])

        teste2=np.array([
                [0xa0, 0x88, 0x23, 0x2a],
                [0xfa, 0x54, 0xa3, 0x6c],
                [0xfe, 0x2c, 0x39, 0x76],
                [0x17, 0xb1, 0x39, 0x05]
                ])

        correct_result= np.array([
                [0xa4, 0x68, 0x6b, 0x02],
                [0x9c, 0x9f, 0x5b, 0x6a],
                [0x7f, 0x35, 0xea, 0x50],
                [0xf2, 0x2b, 0x43, 0x49]
                ])

        
        aes = Aes()
        result = aes.AddRoundKey(teste1, teste2)
        assert np.array_equal(result, correct_result)

    def test_AesEncryption(self):
        message = np.array([
                [0x32, 0x88, 0x31, 0xe0],
                [0x43, 0x5a, 0x31, 0x37],
                [0xf6, 0x30, 0x98, 0x07],
                [0xa8, 0x8d, 0xa2, 0x34]
                ])

        correct_result = np.array([
                        [0x39, 0x02, 0xdc, 0x19],
                        [0x25, 0xdc, 0x11, 0x6a],
                        [0x84, 0x09, 0x85, 0x0b],
                        [0x1d, 0xfb, 0x97, 0x32]
                        ])
        key = 57811460909138771071931939740208549692

        aes = Aes(key=key)

        result = aes.AesEncryption(message)

        print("Correto\n", correct_result)
        print("\nObtido\n", result)

        assert np.array_equal(result, correct_result)
        

    def test_RoundKeyGenerator(self):
        teste = 57811460909138771071931939740208549692 
        #teste2 = 213979707136699034080426665618942227973
        correct_result1 = np.array([
                        [0xa0,0x88,0x23,0x2a],
                        [0xfa,0x54,0xa3,0x6c],
                        [0xfe,0x2c,0x39,0x76],
                        [0x17,0xb1,0x39,0x05],
                        ])

        correct_result2 = np.array([
                        [0xf2, 0x7a, 0x59, 0x73],
                        [0xc2, 0x96, 0x35, 0x59],
                        [0x95, 0xb9, 0x80, 0xf6],
                        [0xf2, 0x43, 0x7a, 0x7f],
                        ])

        aes = Aes()
        result = aes.RoundKeyGenerator(teste, iterations=3)
        
        print("Correto\n", correct_result2)
        print("\nObtido\n", result[2])
        #print("\nkey0\n", result[0])
        assert np.array_equal(result[1], correct_result1)
        assert np.array_equal(result[2], correct_result2)

    def test_GaloisMultiplication(self):
        aes = Aes()
        
        # testes com b valendo 1
        teste = aes.GaloisMultiplication(0x57, 0x1)
        assert teste == 0x57
        teste = aes.GaloisMultiplication(185, 1)
        assert teste == 185
        teste = aes.GaloisMultiplication(105, 1)
        assert teste == 105
        teste = aes.GaloisMultiplication(255, 1)
        assert teste == 255

        # testes com b valendo 2
        teste = aes.GaloisMultiplication(0x57, 0x2)
        assert teste == 0xAE
        teste = aes.GaloisMultiplication(185, 2)
        assert teste == 105
        teste = aes.GaloisMultiplication(200, 2)
        assert teste == 139
        teste = aes.GaloisMultiplication(90, 2)
        assert teste == 180
        teste = aes.GaloisMultiplication(0, 2)
        assert teste == 0
        teste = aes.GaloisMultiplication(1, 2)
        assert teste == 2
        teste = aes.GaloisMultiplication(2, 2)
        assert teste == 4
        teste = aes.GaloisMultiplication(255, 2)
        assert teste == 229
        teste = aes.GaloisMultiplication(128, 2)
        assert teste == 27

        # testes com b valendo 3
        teste = aes.GaloisMultiplication(5, 3)
        assert teste == 15
        teste = aes.GaloisMultiplication(40, 3)
        assert teste == 120
        teste = aes.GaloisMultiplication(170, 3)
        assert teste == 229
        teste = aes.GaloisMultiplication(203, 3)
        assert teste == 70
        teste = aes.GaloisMultiplication(255, 3)
        assert teste == 26
        teste = aes.GaloisMultiplication(176, 3)
        assert teste == 203
        teste = aes.GaloisMultiplication(6, 3)
        assert teste == 10
    
    def test_CtrEncryption(self):
        message = "Single block msg"
        key = 231827352951625350095415684694321656734
        nonce = 885443715538058477568
        correct_result = np.array([0xE4, 0x09, 0x5D, 0x4F, 0xB7, 0xA7, 0xB3, 0x79, 0x2D, 0x61, 0x75, 0xA3, 0x26, 0x13, 0x11, 0xB8])
        
        aes = Aes(key=key)
        result = aes.CtrEncryption(message, nonce)[0]

        print("Correto\n", correct_result)
        print("\nObtido\n", result)

        assert np.array_equal(result[0], correct_result)
        

    def test_CtrDecryption(self):
        correct_result = "Single block msg"
        key = 231827352951625350095415684694321656734
        nonce = 885443715538058477568
        cripto = [np.array([0xE4, 0x09, 0x5D, 0x4F, 0xB7, 0xA7, 0xB3, 0x79, 0x2D, 0x61, 0x75, 0xA3, 0x26, 0x13, 0x11, 0xB8])]
        
        aes = Aes(key=key)
        result = aes.CtrDecryption(cripto, nonce)

        print("Correto\n", correct_result)
        print("\nObtido\n", result)

        assert result == correct_result

    def test_CtrEncryptionDecryption(self):
        # message = "Single block msg"
        message = ("E fez Deus a expansão, e fez separação entre as águas que " +
                    "estavam debaixo da expansão e as águas que estavam sobre a " +
                    "expansão; e assim foi.")
        # key = 231827352951625350095415684694321656734
        nonce = 48
        correct_result = np.array([0xE4, 0x09, 0x5D, 0x4F, 0xB7, 0xA7, 0xB3, 0x79, 0x2D, 0x61, 0x75, 0xA3, 0x26, 0x13, 0x11, 0xB8])
        
        aes = Aes()
        ct, n = aes.CtrEncryption(message, nonce)

        pt = aes.CtrDecryption(ct, n)

        print("Correto\n", message)
        print("\nObtido\n", pt)

        assert pt == message
 
k = TestAes()
k.test_CtrDecryption()