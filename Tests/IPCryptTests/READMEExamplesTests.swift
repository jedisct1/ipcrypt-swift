import Foundation
@testable import IPCrypt
import XCTest

/// Tests to verify all README examples work correctly
final class READMEExamplesTests: XCTestCase {
    // MARK: - Quick Start Example

    func testQuickStartExample() throws {
        // From README: Quick Start
        let key = IPCrypt.Key.random(for: .deterministic)
        let encrypted = try IPCrypt.encrypt("192.0.2.1", with: key)
        print("Encrypted: \(encrypted.ipString ?? encrypted.data.hexString)")

        // Decrypt it back
        let original = try IPCrypt.decrypt(encrypted, with: key)
        print("Original: \(original)")

        XCTAssertEqual(original, "192.0.2.1")
    }

    // MARK: - Creating Keys Examples

    func testKeyCreationExamples() throws {
        // From hex string (16 bytes for deterministic/nd, 32 bytes for ndx)
        let key16 = try IPCrypt.Key(
            hexString: "0123456789abcdeffedcba9876543210",
            mode: .deterministic)
        XCTAssertEqual(key16.data.count, 16)

        let key32 = try IPCrypt.Key(
            hexString: "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301",
            mode: .ndx)
        XCTAssertEqual(key32.data.count, 32)

        // Generate random keys
        let randomKey = IPCrypt.Key.random(for: .nd)
        XCTAssertEqual(randomKey.data.count, 16)

        // From raw data
        let keyData = Data(repeating: 0x42, count: 16)
        let key = try IPCrypt.Key(data: keyData, mode: .deterministic)
        XCTAssertEqual(key.data.count, 16)
    }

    // MARK: - Deterministic Mode Example

    func testDeterministicModeExample() throws {
        let key = IPCrypt.Key.random(for: .deterministic)

        // Same input always produces same output
        let encrypted1 = try IPCrypt.encrypt("10.0.0.1", with: key)
        let encrypted2 = try IPCrypt.encrypt("10.0.0.1", with: key)
        XCTAssertEqual(encrypted1.data, encrypted2.data)

        // Format-preserving: encrypted IPv4 remains valid IP
        XCTAssertNotNil(encrypted1.ipString)
        print(encrypted1.ipString!) // e.g., "a1b2:c3d4:e5f6:..."
    }

    // MARK: - Non-Deterministic Mode (ND) Example

    func testNDModeExample() throws {
        let key = IPCrypt.Key.random(for: .nd)

        // Same input produces different outputs
        let encrypted1 = try IPCrypt.encrypt("10.0.0.1", with: key)
        let encrypted2 = try IPCrypt.encrypt("10.0.0.1", with: key)
        XCTAssertNotEqual(encrypted1.data, encrypted2.data)

        // Output is 24 bytes: 8-byte tweak + 16-byte ciphertext
        XCTAssertEqual(encrypted1.data.count, 24)
        print(encrypted1.data.hexString) // e.g., "08e0c289bff23b7c..."

        // Use specific tweak for reproducibility
        let tweak = Data(hexString: "08e0c289bff23b7c")!
        let encrypted = try IPCrypt.encrypt("10.0.0.1", with: key, tweak: tweak)
        XCTAssertEqual(encrypted.data.count, 24)
    }

    // MARK: - Non-Deterministic Extended Mode (NDX) Example

    func testNDXModeExample() throws {
        let key = IPCrypt.Key.random(for: .ndx)

        // Output is 32 bytes: 16-byte tweak + 16-byte ciphertext
        let encrypted = try IPCrypt.encrypt("10.0.0.1", with: key)
        print("Size: \(encrypted.data.count) bytes")
        print("Hex: \(encrypted.data.hexString)")

        XCTAssertEqual(encrypted.data.count, 32)
    }

    // MARK: - Decryption Examples

    func testDecryptionExamples() throws {
        let key = IPCrypt.Key.random(for: .nd)
        let encrypted = try IPCrypt.encrypt("192.0.2.1", with: key)

        // Method 1: Decrypt using EncryptedIP object
        let decrypted = try IPCrypt.decrypt(encrypted, with: key)
        XCTAssertEqual(decrypted, "192.0.2.1")

        // Method 2: Decrypt from raw data
        let encryptedData = encrypted.data
        let decrypted2 = try IPCrypt.decrypt(data: encryptedData, with: key)
        XCTAssertEqual(decrypted2, "192.0.2.1")
    }

    // MARK: - Error Handling Example

    func testErrorHandlingExample() throws {
        let keyString = "not_valid_hex"
        let ipAddress = "192.0.2.1"

        do {
            let key = try IPCrypt.Key(hexString: keyString, mode: .deterministic)
            let result = try IPCrypt.encrypt(ipAddress, with: key)
            // Use result...
            XCTFail("Should have thrown error")
        } catch let IPCrypt.Error.invalidKeyLength(expected, actual) {
            print("Key length error: expected \(expected), got \(actual)")
        } catch let IPCrypt.Error.invalidTweakLength(expected, actual) {
            print("Tweak length error: expected \(expected), got \(actual)")
        } catch let IPCrypt.Error.invalidIPAddress(address) {
            print("Invalid IP address: \(address)")
        } catch let IPCrypt.Error.invalidDataLength(expected, actual) {
            print("Data length error: expected \(expected), got \(actual)")
        } catch let IPCrypt.Error.invalidHexString(hex) {
            print("Invalid hex string: \(hex)")
            XCTAssertEqual(hex, keyString)
        } catch {
            print("Unexpected error: \(error)")
        }
    }

    // MARK: - IPv6 Support Example

    func testIPv6SupportExample() throws {
        let key = IPCrypt.Key.random(for: .deterministic)

        // Works with both IPv4 and IPv6
        let ipv4Encrypted = try IPCrypt.encrypt("192.168.1.1", with: key)
        let ipv6Encrypted = try IPCrypt.encrypt("2001:db8::1", with: key)

        // IPv4 addresses are internally converted to IPv4-mapped IPv6
        // This is transparent to the user
        XCTAssertNotNil(ipv4Encrypted.ipString)
        XCTAssertNotNil(ipv6Encrypted.ipString)

        // Verify decryption works
        let ipv4Decrypted = try IPCrypt.decrypt(ipv4Encrypted, with: key)
        let ipv6Decrypted = try IPCrypt.decrypt(ipv6Encrypted, with: key)

        XCTAssertEqual(ipv4Decrypted, "192.168.1.1")
        XCTAssertEqual(ipv6Decrypted, "2001:db8::1")
    }

    // MARK: - Codable Integration Example

    func testCodableIntegrationExample() throws {
        struct SecureLogEntry: Codable {
            let timestamp: Date
            let action: String
            let encryptedIP: String

            init(ip: String, action: String, key: IPCrypt.Key) throws {
                timestamp = Date()
                self.action = action
                let encrypted = try IPCrypt.encrypt(ip, with: key)
                encryptedIP = encrypted.data.hexString
            }

            func decryptIP(with key: IPCrypt.Key) throws -> String {
                guard let data = Data(hexString: encryptedIP) else {
                    throw IPCrypt.Error.invalidHexString(encryptedIP)
                }
                return try IPCrypt.decrypt(data: data, with: key)
            }
        }

        // Usage
        let key = IPCrypt.Key.random(for: .nd)
        let entry = try SecureLogEntry(ip: "192.0.2.1", action: "LOGIN", key: key)

        // Serialize to JSON
        let json = try JSONEncoder().encode(entry)

        // Deserialize and decrypt
        let decoded = try JSONDecoder().decode(SecureLogEntry.self, from: json)
        let originalIP = try decoded.decryptIP(with: key)

        XCTAssertEqual(originalIP, "192.0.2.1")
    }

    // MARK: - Batch Processing Example

    @available(macOS 10.15, iOS 13.0, *)
    func testBatchProcessingExample() async throws {
        func encryptBatch(_ ips: [String], with key: IPCrypt.Key) async throws -> [IPCrypt.EncryptedIP] {
            try await withThrowingTaskGroup(of: IPCrypt.EncryptedIP.self) { group in
                for ip in ips {
                    group.addTask {
                        try IPCrypt.encrypt(ip, with: key)
                    }
                }

                var results: [IPCrypt.EncryptedIP] = []
                for try await result in group {
                    results.append(result)
                }
                return results
            }
        }

        // Test the batch function
        let key = IPCrypt.Key.random(for: .deterministic)
        let ips = ["192.0.2.1", "192.0.2.2", "192.0.2.3"]

        let encrypted = try await encryptBatch(ips, with: key)
        XCTAssertEqual(encrypted.count, 3)

        // Verify we can decrypt them all
        for encryptedIP in encrypted {
            let decrypted = try IPCrypt.decrypt(encryptedIP, with: key)
            XCTAssertTrue(ips.contains(decrypted))
        }
    }

    // MARK: - SwiftUI ViewModel Example

    @available(iOS 13.0, macOS 10.15, *)
    func testSwiftUIViewModelExample() throws {
        class IPEncryptionViewModel: ObservableObject {
            @Published var inputIP = ""
            @Published var outputText = ""
            @Published var errorMessage: String?

            private let key = IPCrypt.Key.random(for: .deterministic)

            func encrypt() {
                do {
                    let encrypted = try IPCrypt.encrypt(inputIP, with: key)
                    outputText = encrypted.ipString ?? encrypted.data.hexString
                    errorMessage = nil
                } catch {
                    outputText = ""
                    errorMessage = error.localizedDescription
                }
            }

            func decrypt() {
                do {
                    let data = Data(hexString: inputIP) ?? Data()
                    outputText = try IPCrypt.decrypt(data: data, with: key)
                    errorMessage = nil
                } catch {
                    outputText = ""
                    errorMessage = error.localizedDescription
                }
            }
        }

        // Test the view model
        let viewModel = IPEncryptionViewModel()

        // Test encryption
        viewModel.inputIP = "192.0.2.1"
        viewModel.encrypt()
        XCTAssertFalse(viewModel.outputText.isEmpty)
        XCTAssertNil(viewModel.errorMessage)

        // Test invalid IP
        viewModel.inputIP = "not.an.ip"
        viewModel.encrypt()
        XCTAssertTrue(viewModel.outputText.isEmpty)
        XCTAssertNotNil(viewModel.errorMessage)
    }

    // MARK: - CLI Examples (Testing Expected Outputs)

    func testCLIExampleOutputs() throws {
        // Test deterministic encryption matches README example
        let key = try IPCrypt.Key(hexString: "2b7e151628aed2a6abf7158809cf4f3c", mode: .deterministic)
        let encrypted = try IPCrypt.encrypt("192.0.2.1", with: key)
        XCTAssertEqual(encrypted.ipString, "1dbd:c1b9:fff1:7586:7d0b:67b4:e76e:4777")

        // Test ND mode with specific tweak
        let ndKey = try IPCrypt.Key(hexString: "0123456789abcdeffedcba9876543210", mode: .nd)
        let tweak = Data(hexString: "08e0c289bff23b7c")!
        let ndEncrypted = try IPCrypt.encrypt("0.0.0.0", with: ndKey, tweak: tweak)
        XCTAssertEqual(ndEncrypted.data.hexString, "08e0c289bff23b7cb349aadfe3bcef56221c384c7c217b16")

        // Test decryption
        let decrypted = try IPCrypt.decrypt(ndEncrypted, with: ndKey)
        XCTAssertEqual(decrypted, "0.0.0.0")
    }

    // MARK: - API Reference Examples

    func testAPIReferenceExamples() throws {
        // Test Mode enum
        let mode: IPCrypt.Mode = .deterministic
        XCTAssertEqual(mode.keyLength, 16)
        XCTAssertEqual(mode.outputLength, 16)

        // Test Key struct
        let key = try IPCrypt.Key(
            hexString: "0123456789abcdeffedcba9876543210",
            mode: .deterministic)
        XCTAssertEqual(key.data.count, 16)
        XCTAssertEqual(key.mode, .deterministic)

        // Test EncryptedIP struct
        let encrypted = try IPCrypt.encrypt("192.0.2.1", with: key)
        XCTAssertEqual(encrypted.mode, .deterministic)
        XCTAssertEqual(encrypted.data.count, 16)
        XCTAssertNil(encrypted.tweak)
        XCTAssertEqual(encrypted.ciphertext, encrypted.data)
        XCTAssertNotNil(encrypted.ipString)

        // Test Error enum
        let error = IPCrypt.Error.invalidKeyLength(expected: 16, actual: 8)
        XCTAssertNotNil(error.errorDescription)
    }
}
