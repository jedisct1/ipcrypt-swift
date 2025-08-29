import Foundation
@testable import IPCrypt
import XCTest

// MARK: - TestVector

// Test vector structure
struct TestVector: Codable {
    enum CodingKeys: String, CodingKey {
        case variant
        case key
        case ip
        case encryptedIp = "encrypted_ip"
        case tweak
        case output
    }

    let variant: String
    let key: String
    let ip: String
    let encryptedIp: String?
    let tweak: String?
    let output: String?
}

// MARK: - IPCryptTests

/// Tests for IPCrypt implementation
final class IPCryptTests: XCTestCase {
    // MARK: Internal

    // MARK: - Key Tests

    func testKeyCreation() throws {
        // Test valid key creation
        let key16 = try IPCrypt.Key(hexString: "0123456789abcdeffedcba9876543210", mode: .deterministic)
        XCTAssertEqual(key16.data.count, 16)
        XCTAssertEqual(key16.mode, .deterministic)

        let key32 = try IPCrypt.Key(
            hexString: "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301",
            mode: .ndx)
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

    // MARK: - Test Vectors from JSON

    private func loadTestVectors() throws -> [TestVector] {
        let url = Bundle.module.url(forResource: "test_vectors", withExtension: "json")!
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode([TestVector].self, from: data)
    }

    func testAllTestVectors() throws {
        let vectors = try loadTestVectors()

        for (index, vector) in vectors.enumerated() {
            switch vector.variant {
            case "ipcrypt-deterministic":
                try testDeterministicVector(vector, index: index)
            case "ipcrypt-nd":
                try testNDVector(vector, index: index)
            case "ipcrypt-ndx":
                try testNDXVector(vector, index: index)
            default:
                XCTFail("Unknown variant: \(vector.variant)")
            }
        }
    }

    // MARK: - Deterministic Mode Tests

    func testDeterministicEncryption() throws {
        let key = try IPCrypt.Key(hexString: "0123456789abcdeffedcba9876543210", mode: .deterministic)

        // Test IPv4
        let ipv4 = "192.0.2.1"
        let encrypted = try IPCrypt.encrypt(ipv4, with: key)
        XCTAssertEqual(encrypted.mode, .deterministic)

        let decrypted = try IPCrypt.decrypt(encrypted, with: key)
        XCTAssertEqual(decrypted, ipv4)

        // Test IPv6
        let ipv6 = "2001:db8::1"
        let encryptedv6 = try IPCrypt.encrypt(ipv6, with: key)
        XCTAssertEqual(encryptedv6.mode, .deterministic)

        let decryptedv6 = try IPCrypt.decrypt(encryptedv6, with: key)
        XCTAssertEqual(decryptedv6, ipv6)
    }

    func testDeterministicWithTestVectors() throws {
        // Run all test vectors from JSON file
        try testAllTestVectors()
    }

    // MARK: - Non-Deterministic Mode Tests

    func testNDEncryption() throws {
        let key = try IPCrypt.Key(hexString: "0123456789abcdeffedcba9876543210", mode: .nd)

        // Test with random tweak
        let encrypted1 = try IPCrypt.encrypt("192.0.2.1", with: key)
        XCTAssertEqual(encrypted1.mode, .nd)
        XCTAssertEqual(encrypted1.data.count, 24)

        let encrypted2 = try IPCrypt.encrypt("192.0.2.1", with: key)
        XCTAssertEqual(encrypted2.mode, .nd)
        XCTAssertEqual(encrypted2.data.count, 24)

        // Different tweaks should produce different outputs
        XCTAssertNotEqual(encrypted1.data, encrypted2.data)

        // Both should decrypt to the same IP
        let decrypted1 = try IPCrypt.decrypt(encrypted1, with: key)
        let decrypted2 = try IPCrypt.decrypt(encrypted2, with: key)
        XCTAssertEqual(decrypted1, "192.0.2.1")
        XCTAssertEqual(decrypted2, "192.0.2.1")
    }

    func testNDWithSpecificTweak() throws {
        let key = try IPCrypt.Key(hexString: "0123456789abcdeffedcba9876543210", mode: .nd)
        let tweak = Data(hexString: "08e0c289bff23b7c")!

        let ip = "0.0.0.0"
        let encrypted = try IPCrypt.encrypt(ip, with: key, tweak: tweak)

        // This should match test vector
        XCTAssertEqual(encrypted.data.hexString, "08e0c289bff23b7cb349aadfe3bcef56221c384c7c217b16")

        let decrypted = try IPCrypt.decrypt(encrypted, with: key)
        XCTAssertEqual(decrypted, ip)
    }

    // MARK: - Non-Deterministic Extended Mode Tests

    func testNDXEncryption() throws {
        let key = try IPCrypt.Key(
            hexString: "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301",
            mode: .ndx)

        // Test with random tweak
        let encrypted1 = try IPCrypt.encrypt("192.0.2.1", with: key)
        XCTAssertEqual(encrypted1.mode, .ndx)
        XCTAssertEqual(encrypted1.data.count, 32)

        let encrypted2 = try IPCrypt.encrypt("192.0.2.1", with: key)
        XCTAssertEqual(encrypted2.mode, .ndx)
        XCTAssertEqual(encrypted2.data.count, 32)

        // Different tweaks should produce different outputs
        XCTAssertNotEqual(encrypted1.data, encrypted2.data)

        // Both should decrypt to the same IP
        let decrypted1 = try IPCrypt.decrypt(encrypted1, with: key)
        let decrypted2 = try IPCrypt.decrypt(encrypted2, with: key)
        XCTAssertEqual(decrypted1, "192.0.2.1")
        XCTAssertEqual(decrypted2, "192.0.2.1")
    }

    func testNDXWithSpecificTweak() throws {
        let key = try IPCrypt.Key(
            hexString: "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301",
            mode: .ndx)
        let tweak = Data(hexString: "21bd1834bc088cd2b4ecbe30b70898d7")!

        let ip = "0.0.0.0"
        let encrypted = try IPCrypt.encrypt(ip, with: key, tweak: tweak)

        // This should match test vector
        XCTAssertEqual(encrypted.data.hexString, "21bd1834bc088cd2b4ecbe30b70898d782db0d4125fdace61db35b8339f20ee5")

        let decrypted = try IPCrypt.decrypt(encrypted, with: key)
        XCTAssertEqual(decrypted, ip)
    }

    // MARK: - IPv6 Support Tests

    func testIPv6Support() throws {
        let key = try IPCrypt.Key(hexString: "0123456789abcdeffedcba9876543210", mode: .deterministic)

        let ipv6 = "2001:db8:85a3::8a2e:370:7334"
        let encrypted = try IPCrypt.encrypt(ipv6, with: key)

        // Should match test vector
        XCTAssertEqual(encrypted.ipString, "1eef:2352:64c8:18e6:6456:1373:f615:5032")

        let decrypted = try IPCrypt.decrypt(encrypted, with: key)
        XCTAssertEqual(decrypted, ipv6)
    }

    // MARK: - Error Handling Tests

    func testErrorHandling() throws {
        // Test invalid key lengths
        XCTAssertThrowsError(try IPCrypt.Key(hexString: "0123", mode: .deterministic))
        XCTAssertThrowsError(try IPCrypt.Key(hexString: "0123", mode: .ndx))

        // Test invalid hex strings
        XCTAssertThrowsError(try IPCrypt.Key(hexString: "not_hex", mode: .deterministic))

        // Test invalid IP addresses
        XCTAssertThrowsError(try IPAddress("not.an.ip"))
        XCTAssertThrowsError(try IPAddress("256.256.256.256"))
    }

    // MARK: - Convenience API Tests

    func testDecryptWithData() throws {
        let key = try IPCrypt.Key(hexString: "0123456789abcdeffedcba9876543210", mode: .deterministic)

        // Create encrypted data directly
        let encrypted = try IPCrypt.encrypt("192.0.2.1", with: key)

        // Decrypt using the data directly
        let decrypted = try IPCrypt.decrypt(data: encrypted.data, with: key)
        XCTAssertEqual(decrypted, "192.0.2.1")
    }

    // MARK: - Batch Processing Tests

    func testBatchEncryption() throws {
        let key = try IPCrypt.Key(hexString: "0123456789abcdeffedcba9876543210", mode: .deterministic)

        let ips = [
            "192.0.2.1",
            "192.0.2.2",
            "192.0.2.3",
            "10.0.0.1",
            "10.0.0.2"
        ]

        measure {
            for _ in 0..<1000 {
                for ip in ips {
                    _ = try! IPCrypt.encrypt(ip, with: key)
                }
            }
        }
    }

    // MARK: Private

    private func testDeterministicVector(_ vector: TestVector, index: Int) throws {
        let key = try IPCrypt.Key(hexString: vector.key, mode: .deterministic)

        let encrypted = try IPCrypt.encrypt(vector.ip, with: key)
        XCTAssertEqual(encrypted.ipString, vector.encryptedIp!,
                       "Vector \(index + 1): Deterministic encryption failed for \(vector.ip)")

        let decrypted = try IPCrypt.decrypt(encrypted, with: key)
        XCTAssertEqual(decrypted, vector.ip,
                       "Vector \(index + 1): Deterministic decryption failed for \(vector.ip)")
    }

    private func testNDVector(_ vector: TestVector, index: Int) throws {
        let key = try IPCrypt.Key(hexString: vector.key, mode: .nd)

        if let tweakHex = vector.tweak, let outputHex = vector.output {
            let tweak = Data(hexString: tweakHex)!
            let result = try IPCrypt.encrypt(vector.ip, with: key, tweak: tweak)

            XCTAssertEqual(result.data.hexString, outputHex.lowercased(),
                           "Vector \(index + 1): ND encryption failed for \(vector.ip)")

            let decrypted = try IPCrypt.decrypt(result, with: key)
            XCTAssertEqual(decrypted, vector.ip,
                           "Vector \(index + 1): ND decryption failed for \(vector.ip)")
        }
    }

    private func testNDXVector(_ vector: TestVector, index: Int) throws {
        let key = try IPCrypt.Key(hexString: vector.key, mode: .ndx)

        if let tweakHex = vector.tweak, let outputHex = vector.output {
            let tweak = Data(hexString: tweakHex)!
            let result = try IPCrypt.encrypt(vector.ip, with: key, tweak: tweak)

            XCTAssertEqual(result.data.hexString, outputHex.lowercased(),
                           "Vector \(index + 1): NDX encryption failed for \(vector.ip)")

            let decrypted = try IPCrypt.decrypt(result, with: key)
            XCTAssertEqual(decrypted, vector.ip,
                           "Vector \(index + 1): NDX decryption failed for \(vector.ip)")
        }
    }
}
