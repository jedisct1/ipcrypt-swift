import Foundation
import IPCrypt

/// Example usage of the IPCrypt Swift library demonstrating idiomatic patterns
enum IPCryptExamples {

    // MARK: - Basic Usage

    static func basicUsage() throws {
        // Create a key for deterministic encryption
        let key = try IPCrypt.Key(
            hexString: "0123456789abcdeffedcba9876543210",
            mode: .deterministic
        )

        // Encrypt an IP address
        let encrypted = try IPCrypt.encrypt("192.0.2.1", with: key)
        print("Encrypted IP: \(encrypted.ipString ?? encrypted.hexString)")

        // Decrypt it back
        let original = try IPCrypt.decrypt(encrypted, with: key)
        print("Original IP: \(original)")
    }

    // MARK: - Working with Different Modes

    static func differentModes() throws {
        let testIP = "192.168.1.1"

        // Deterministic mode - always same output for same input
        let detKey = IPCrypt.Key.random(for: .deterministic)
        let det1 = try IPCrypt.encrypt(testIP, with: detKey)
        let det2 = try IPCrypt.encrypt(testIP, with: detKey)
        assert(det1.data == det2.data, "Deterministic should be consistent")

        // ND mode - different output each time due to random tweak
        let ndKey = IPCrypt.Key.random(for: .nd)
        let nd1 = try IPCrypt.encrypt(testIP, with: ndKey)
        let nd2 = try IPCrypt.encrypt(testIP, with: ndKey)
        assert(nd1.data != nd2.data, "ND should use different tweaks")
        assert(nd1.tweak != nd2.tweak, "Tweaks should differ")

        // NDX mode - even more security with larger tweak
        let ndxKey = IPCrypt.Key.random(for: .ndx)
        let ndx = try IPCrypt.encrypt(testIP, with: ndxKey)
        print("NDX output size: \(ndx.data.count) bytes")
    }

    // MARK: - Error Handling

    static func errorHandling() {
        do {
            // This will throw an error - wrong key size
            _ = try IPCrypt.Key(
                hexString: "0123456789abcdef", // Only 8 bytes
                mode: .deterministic // Needs 16 bytes
            )
        } catch IPCrypt.Error.invalidKeyLength(let expected, let actual) {
            print("Key length error: expected \(expected), got \(actual)")
        } catch {
            print("Unexpected error: \(error)")
        }

        // Using Result type for cleaner error handling
        let result = Result {
            try IPCrypt.Key(hexString: "not-hex", mode: .deterministic)
        }

        switch result {
        case .success(let key):
            print("Created key: \(key)")
        case .failure(IPCrypt.Error.invalidHexString(let hex)):
            print("Invalid hex: \(hex)")
        case .failure(let error):
            print("Other error: \(error)")
        }
    }

    // MARK: - Batch Processing

    static func batchProcessing() throws {
        let key = IPCrypt.Key.random(for: .nd)

        // Process multiple IPs efficiently
        let ips = ["192.168.1.1", "10.0.0.1", "172.16.0.1"]

        let encrypted = try ips.map { ip in
            try IPCrypt.encrypt(ip, with: key)
        }

        let decrypted = try encrypted.map { enc in
            try IPCrypt.decrypt(enc, with: key)
        }

        assert(ips == decrypted, "Round-trip should preserve IPs")
    }

    // MARK: - Integration with Codable

    struct SecureLogEntry: Codable {
        let timestamp: Date
        let encryptedIP: String
        let action: String

        init(ip: String, action: String, key: IPCrypt.Key) throws {
            self.timestamp = Date()
            self.action = action

            // Encrypt the IP and store as hex
            let encrypted = try IPCrypt.encrypt(ip, with: key)
            self.encryptedIP = encrypted.hexString
        }

        func decryptIP(with key: IPCrypt.Key) throws -> String {
            guard let data = Data(hexString: encryptedIP) else {
                throw IPCrypt.Error.invalidHexString(encryptedIP)
            }
            return try IPCrypt.decrypt(data: data, with: key)
        }
    }

    static func codableIntegration() throws {
        let key = IPCrypt.Key.random(for: .nd)

        // Create secure log entry
        let entry = try SecureLogEntry(
            ip: "192.0.2.1",
            action: "LOGIN",
            key: key
        )

        // Encode to JSON
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let json = try encoder.encode(entry)
        print("JSON: \(String(data: json, encoding: .utf8)!)")

        // Decode and decrypt
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(SecureLogEntry.self, from: json)
        let originalIP = try decoded.decryptIP(with: key)
        print("Decrypted IP: \(originalIP)")
    }

    // MARK: - Async/Await Support

    @available(macOS 10.15, iOS 13.0, *)
    static func asyncProcessing() async throws {
        let key = IPCrypt.Key.random(for: .ndx)

        // Process IPs concurrently
        let ips = (1...100).map { "192.168.1.\($0)" }

        let encrypted = try await withThrowingTaskGroup(of: IPCrypt.EncryptedIP.self) { group in
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

        print("Encrypted \(encrypted.count) IPs concurrently")
    }

    // MARK: - SwiftUI Integration Example

    @available(macOS 10.15, iOS 13.0, *)
    class IPCryptViewModel: ObservableObject {
        @Published var inputIP = ""
        @Published var encryptedResult = ""
        @Published var errorMessage: String?

        private let key = IPCrypt.Key.random(for: .deterministic)

        func encrypt() {
            errorMessage = nil
            do {
                let encrypted = try IPCrypt.encrypt(inputIP, with: key)
                encryptedResult = encrypted.ipString ?? encrypted.hexString
            } catch {
                errorMessage = error.localizedDescription
                encryptedResult = ""
            }
        }

        func decrypt() {
            errorMessage = nil
            do {
                // Try to decrypt from hex first, then as IP
                let result: String
                if let data = Data(hexString: inputIP) {
                    result = try IPCrypt.decrypt(data: data, with: key)
                } else {
                    // Assume it's an encrypted IP in standard format
                    let encrypted = IPCrypt.EncryptedIP(
                        mode: .deterministic,
                        data: try IPAddress(inputIP).to16Bytes()
                    )
                    result = try IPCrypt.decrypt(encrypted, with: key)
                }
                encryptedResult = result
            } catch {
                errorMessage = error.localizedDescription
                encryptedResult = ""
            }
        }
    }

    // MARK: - Main Example Runner

    static func runAllExamples() throws {
        print("=== Basic Usage ===")
        try basicUsage()

        print("\n=== Different Modes ===")
        try differentModes()

        print("\n=== Error Handling ===")
        errorHandling()

        print("\n=== Batch Processing ===")
        try batchProcessing()

        print("\n=== Codable Integration ===")
        try codableIntegration()

        if #available(macOS 10.15, iOS 13.0, *) {
            print("\n=== Async Processing ===")
            Task {
                try await asyncProcessing()
            }
        }
    }
}

// Helper to make IPAddress available for the example
fileprivate extension IPAddress {
    init(_ string: String) throws {
        if let v4 = IPv4Address(string) {
            self = .v4(v4.rawValue)
        } else if let v6 = IPv6Address(string) {
            self = .v6(v6.rawValue)
        } else {
            throw IPCrypt.Error.invalidIPAddress(string)
        }
    }

    func to16Bytes() -> Data {
        switch self {
        case .v4(let data):
            var result = Data(repeating: 0, count: 10)
            result.append(contentsOf: [0xFF, 0xFF])
            result.append(data)
            return result
        case .v6(let data):
            return data
        }
    }
}

// Make IPAddress accessible
fileprivate enum IPAddress {
    case v4(Data)
    case v6(Data)
}