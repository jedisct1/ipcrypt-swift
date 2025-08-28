import Foundation

struct AESXTS {
    static func xorData(_ a: Data, _ b: Data) -> Data {
        guard a.count == b.count else { return Data() }
        return Data(zip(a, b).map { $0 ^ $1 })
    }

    static func encrypt(key: Data, tweak: Data, plaintext: Data) -> Data {
        guard key.count == 32 && tweak.count == 16 && plaintext.count == 16 else {
            return Data()
        }

        let k1 = Data(key[0..<16])
        let k2 = Data(key[16..<32])

        let et = AESCore.encryptBlock(tweak, key: k2)

        let xored = xorData(plaintext, et)
        let encrypted = AESCore.encryptBlock(xored, key: k1)

        return xorData(encrypted, et)
    }

    static func decrypt(key: Data, tweak: Data, ciphertext: Data) -> Data {
        guard key.count == 32 && tweak.count == 16 && ciphertext.count == 16 else {
            return Data()
        }

        let k1 = Data(key[0..<16])
        let k2 = Data(key[16..<32])

        let et = AESCore.encryptBlock(tweak, key: k2)

        let xored = xorData(ciphertext, et)
        let decrypted = AESCore.decryptBlock(xored, key: k1)

        return xorData(decrypted, et)
    }
}
