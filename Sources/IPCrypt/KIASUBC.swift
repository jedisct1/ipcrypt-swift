import Foundation

enum KIASUBC {
    static func padTweak(_ tweak: Data) -> Data {
        guard tweak.count == 8 else { return Data(count: 16) }

        var paddedTweak = Data(count: 16)
        for i in 0..<4 {
            paddedTweak[i * 4] = tweak[i * 2]
            paddedTweak[i * 4 + 1] = tweak[i * 2 + 1]
            paddedTweak[i * 4 + 2] = 0
            paddedTweak[i * 4 + 3] = 0
        }
        return paddedTweak
    }

    static func xorData(_ a: Data, _ b: Data) -> Data {
        guard a.count == b.count else { return Data() }
        return Data(zip(a, b).map { $0 ^ $1 })
    }

    static func encrypt(key: Data, tweak: Data, plaintext: Data) -> Data {
        guard key.count == 16, tweak.count == 8, plaintext.count == 16 else {
            return Data()
        }

        let roundKeys = AESCore.expandKey(key)
        let paddedTweak = padTweak(tweak)

        var state = xorData(plaintext, xorData(roundKeys[0], paddedTweak))

        for i in 1..<10 {
            AESCore.subBytes(&state)
            AESCore.shiftRows(&state)
            AESCore.mixColumns(&state)
            state = xorData(state, xorData(roundKeys[i], paddedTweak))
        }

        AESCore.subBytes(&state)
        AESCore.shiftRows(&state)
        state = xorData(state, xorData(roundKeys[10], paddedTweak))

        return state
    }

    static func decrypt(key: Data, tweak: Data, ciphertext: Data) -> Data {
        guard key.count == 16, tweak.count == 8, ciphertext.count == 16 else {
            return Data()
        }

        let roundKeys = AESCore.expandKey(key)
        let paddedTweak = padTweak(tweak)

        var state = xorData(ciphertext, xorData(roundKeys[10], paddedTweak))
        AESCore.invShiftRows(&state)
        AESCore.invSubBytes(&state)

        for i in (1..<10).reversed() {
            state = xorData(state, xorData(roundKeys[i], paddedTweak))
            AESCore.invMixColumns(&state)
            AESCore.invShiftRows(&state)
            AESCore.invSubBytes(&state)
        }

        state = xorData(state, xorData(roundKeys[0], paddedTweak))

        return state
    }
}
