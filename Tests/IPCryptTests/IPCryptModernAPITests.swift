import XCTest
import Foundation
@testable import IPCrypt

/// Tests for the modern, idiomatic IPCrypt API
final class IPCryptModernAPITests: XCTestCase {
    // MARK: - Key Tests

    func testKeyCreation() throws {
        // Test valid key creation
        let key16 = try IPCrypt.Key(hexString: "0123456789abcdeffedcba9876543210", mode: .deterministic)
        XCTAssertEqual(key16.data.count, 16)
        XCTAssertEqual(key16.mode, .deterministic)

        let key32 = try IPCrypt.Key(
            hexString: "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301",
            mode: .ndx
        )
        XCTAssertEqual(key32.data.count, 32)
        XCTAssertEqual(key32.mode, .ndx)

        // Test invalid key length
        XCTAssertThrowsError(try IPCrypt.Key(hexString: "0123456789abcdef", mode: .deterministic)) { error in
            guard case IPCrypt.Error.invalidKeyLength(expected: 16, actual: 8) = error else {
                XCTFail("Wrong error type")
                return
            }
        }
    }

    func testRandomKeyGeneration() {
        let deterministicKey = IPCrypt.Key.random(for: .deterministic)
        XCTAssertEqual(deterministicKey.data.count, 16)

        let ndKey = IPCrypt.Key.random(for: .nd)
        XCTAssertEqual(ndKey.data.count, 16)

        let ndxKey = IPCrypt.Key.random(for: .ndx)
        XCTAssertEqual(ndxKey.data.count, 32)

        // Ensure keys are different
        let key1 = IPCrypt.Key.random(for: .deterministic)
        let key2 = IPCrypt.Key.random(for: .deterministic)
        XCTAssertNotEqual(key1.data, key2.data)
    }

    // MARK: - Deterministic Mode Tests

    func testDeterministicEncryption() throws {
        let key = try IPCrypt.Key(hexString: "0123456789abcdeffedcba9876543210", mode: .deterministic)

        let encrypted = try IPCrypt.encrypt("192.0.2.1", with: key)
        XCTAssertEqual(encrypted.mode, .deterministic)
        XCTAssertNil(encrypted.tweak)
        XCTAssertEqual(encrypted.data.count, 16)
        XCTAssertNotNil(encrypted.ipString)

        // Test round-trip
        let decrypted = try IPCrypt.decrypt(encrypted, with: key)
        XCTAssertEqual(decrypted, "192.0.2.1")
    }

    func testDeterministicWithTestVectors() throws {
        let testVectors = [
            ("0.0.0.0", "0123456789abcdeffedcba9876543210", "bde9:6789:d353:824c:d7c6:f58a:6bd2:26eb"),
            ("255.255.255.255", "1032547698badcfeefcdab8967452301", "aed2:92f6:ea23:58c3:48fd:8b8:74e8:45d8"),
            ("192.0.2.1", "2b7e151628aed2a6abf7158809cf4f3c", "1dbd:c1b9:fff1:7586:7d0b:67b4:e76e:4777")
        ]

        for (ip, keyHex, expectedIP) in testVectors {
            let key = try IPCrypt.Key(hexString: keyHex, mode: .deterministic)
            let encrypted = try IPCrypt.encrypt(ip, with: key)
            XCTAssertEqual(encrypted.ipString, expectedIP, "Failed for IP: \(ip)")

            let decrypted = try IPCrypt.decrypt(encrypted, with: key)
            XCTAssertEqual(decrypted, ip)
        }
    }

    // MARK: - Non-Deterministic Mode Tests

    func testNDEncryption() throws {
        let key = try IPCrypt.Key(hexString: "0123456789abcdeffedcba9876543210", mode: .nd)

        // Test with random tweak
        let encrypted1 = try IPCrypt.encrypt("192.0.2.1", with: key)
        XCTAssertEqual(encrypted1.mode, .nd)
        XCTAssertEqual(encrypted1.data.count, 24)
        XCTAssertEqual(encrypted1.tweak?.count, 8)

        // Test that random tweaks produce different outputs
        let encrypted2 = try IPCrypt.encrypt("192.0.2.1", with: key)
        XCTAssertNotEqual(encrypted1.data, encrypted2.data)
        XCTAssertNotEqual(encrypted1.tweak, encrypted2.tweak)

        // But decryption works for both
        let decrypted1 = try IPCrypt.decrypt(encrypted1, with: key)
        let decrypted2 = try IPCrypt.decrypt(encrypted2, with: key)
        XCTAssertEqual(decrypted1, "192.0.2.1")
        XCTAssertEqual(decrypted2, "192.0.2.1")
    }

    func testNDWithSpecificTweak() throws {
        let key = try IPCrypt.Key(hexString: "0123456789abcdeffedcba9876543210", mode: .nd)
        let tweak = Data(hexString: "08e0c289bff23b7c")!

        let encrypted = try IPCrypt.encrypt("0.0.0.0", with: key, tweak: tweak)
        XCTAssertEqual(encrypted.tweak, tweak)
        XCTAssertEqual(encrypted.hexString, "08e0c289bff23b7cb349aadfe3bcef56221c384c7c217b16")

        let decrypted = try IPCrypt.decrypt(encrypted, with: key)
        XCTAssertEqual(decrypted, "0.0.0.0")
    }

    // MARK: - NDX Mode Tests

    func testNDXEncryption() throws {
        let key = try IPCrypt.Key(
            hexString: "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301",
            mode: .ndx
        )

        // Test with random tweak
        let encrypted = try IPCrypt.encrypt("192.0.2.1", with: key)
        XCTAssertEqual(encrypted.mode, .ndx)
        XCTAssertEqual(encrypted.data.count, 32)
        XCTAssertEqual(encrypted.tweak?.count, 16)

        // Test round-trip
        let decrypted = try IPCrypt.decrypt(encrypted, with: key)
        XCTAssertEqual(decrypted, "192.0.2.1")
    }

    func testNDXWithSpecificTweak() throws {
        let key = try IPCrypt.Key(
            hexString: "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301",
            mode: .ndx
        )
        let tweak = Data(hexString: "21bd1834bc088cd2b4ecbe30b70898d7")!

        let encrypted = try IPCrypt.encrypt("0.0.0.0", with: key, tweak: tweak)
        XCTAssertEqual(encrypted.tweak, tweak)
        XCTAssertEqual(encrypted.hexString, "21bd1834bc088cd2b4ecbe30b70898d782db0d4125fdace61db35b8339f20ee5")

        let decrypted = try IPCrypt.decrypt(encrypted, with: key)
        XCTAssertEqual(decrypted, "0.0.0.0")
    }

    // MARK: - Error Handling Tests

    func testErrorHandling() throws {
        // Test invalid IP address
        let key = IPCrypt.Key.random(for: .deterministic)
        XCTAssertThrowsError(try IPCrypt.encrypt("not.an.ip", with: key)) { error in
            guard case IPCrypt.Error.invalidIPAddress = error else {
                XCTFail("Wrong error type")
                return
            }
        }

        // Test wrong key mode for decryption
        let ndKey = IPCrypt.Key.random(for: .nd)
        let deterministicKey = IPCrypt.Key.random(for: .deterministic)
        let encrypted = try IPCrypt.encrypt("192.0.2.1", with: ndKey)

        XCTAssertThrowsError(try IPCrypt.decrypt(encrypted, with: deterministicKey)) { error in
            guard case IPCrypt.Error.invalidDataLength = error else {
                XCTFail("Wrong error type")
                return
            }
        }

        // Test invalid tweak length
        let ndxKey = IPCrypt.Key.random(for: .ndx)
        let shortTweak = Data(count: 8)

        XCTAssertThrowsError(try IPCrypt.encrypt("192.0.2.1", with: ndxKey, tweak: shortTweak)) { error in
            guard case IPCrypt.Error.invalidTweakLength(expected: 16, actual: 8) = error else {
                XCTFail("Wrong error type")
                return
            }
        }
    }

    // MARK: - IPv6 Tests

    func testIPv6Support() throws {
        let key = IPCrypt.Key.random(for: .deterministic)
        let ipv6 = "2001:db8::1"

        let encrypted = try IPCrypt.encrypt(ipv6, with: key)
        let decrypted = try IPCrypt.decrypt(encrypted, with: key)

        XCTAssertEqual(decrypted, ipv6)
    }

    // MARK: - Performance Tests

    func testBatchEncryption() throws {
        let key = IPCrypt.Key.random(for: .deterministic)
        let ips = (0..<100).map { "192.168.1.\($0)" }

        measure {
            for ip in ips {
                _ = try? IPCrypt.encrypt(ip, with: key)
            }
        }
    }

    // MARK: - Convenience API Tests

    func testDecryptWithData() throws {
        let key = try IPCrypt.Key(hexString: "0123456789abcdeffedcba9876543210", mode: .nd)
        let encryptedData = Data(hexString: "08e0c289bff23b7cb349aadfe3bcef56221c384c7c217b16")!

        let decrypted = try IPCrypt.decrypt(data: encryptedData, with: key)
        XCTAssertEqual(decrypted, "0.0.0.0")
    }
}
