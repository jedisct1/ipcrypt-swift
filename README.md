# IPCrypt Swift Implementation

A pure Swift implementation of the [IPCrypt specification](https://ipcrypt-std.github.io) for IP address encryption and obfuscation. This library provides secure, format-preserving encryption for IPv4 and IPv6 addresses with both deterministic and non-deterministic modes.

## Features

- **Pure Swift** - No external dependencies or C libraries
- **Three encryption modes**:
  - `deterministic`: AES-128 deterministic encryption (format-preserving)
  - `nd`: KIASU-BC with 8-byte random tweak (non-deterministic)
  - `ndx`: AES-XTS with 16-byte random tweak (non-deterministic)
- **Type-safe API** with comprehensive error handling
- **Platform support**: macOS 10.15+, iOS 13+, tvOS 13+, watchOS 6+
- **Thread-safe** and optimized for performance
- **Fully tested** against official specification test vectors

## Installation

### Swift Package Manager

Add the following to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/jedisct1/swift-ipcrypt", from: "1.0.0")
],
targets: [
    .target(
        name: "YourTarget",
        dependencies: ["IPCrypt"]
    )
]
```

Or in Xcode:

1. File -> Add Package Dependencies
2. Enter the repository URL
3. Select the version you want to use

## Quick Start

```swift
import IPCrypt

// Encrypt an IP address with a random key
let key = IPCrypt.Key.random(for: .deterministic)
let encrypted = try IPCrypt.encrypt("192.0.2.1", with: key)
print("Encrypted: \(encrypted.ipString ?? encrypted.hexString)")

// Decrypt it back
let original = try IPCrypt.decrypt(encrypted, with: key)
print("Original: \(original)")
```

## Usage Guide

### Creating Keys

```swift
// From hex string (16 bytes for deterministic/nd, 32 bytes for ndx)
let key16 = try IPCrypt.Key(
    hexString: "0123456789abcdeffedcba9876543210",
    mode: .deterministic
)

let key32 = try IPCrypt.Key(
    hexString: "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301",
    mode: .ndx
)

// Generate random keys
let randomKey = IPCrypt.Key.random(for: .nd)

// From raw data
let keyData = Data(/* your key bytes */)
let key = try IPCrypt.Key(data: keyData, mode: .deterministic)
```

### Encryption Modes

#### Deterministic Mode

Always produces the same output for the same input. Useful when you need consistent encryption.

```swift
let key = IPCrypt.Key.random(for: .deterministic)

// Same input always produces same output
let encrypted1 = try IPCrypt.encrypt("10.0.0.1", with: key)
let encrypted2 = try IPCrypt.encrypt("10.0.0.1", with: key)
assert(encrypted1.data == encrypted2.data)

// Format-preserving: encrypted IPv4 remains valid IP
print(encrypted1.ipString!) // e.g., "a1b2:c3d4:e5f6:..."
```

#### Non-Deterministic Mode (ND)

Uses KIASU-BC with an 8-byte random tweak. Different output each time.

```swift
let key = IPCrypt.Key.random(for: .nd)

// Same input produces different outputs
let encrypted1 = try IPCrypt.encrypt("10.0.0.1", with: key)
let encrypted2 = try IPCrypt.encrypt("10.0.0.1", with: key)
assert(encrypted1.data != encrypted2.data)

// Output is 24 bytes: 8-byte tweak + 16-byte ciphertext
print(encrypted1.hexString) // e.g., "08e0c289bff23b7c..."

// Use specific tweak for reproducibility
let tweak = Data(hexString: "08e0c289bff23b7c")!
let encrypted = try IPCrypt.encrypt("10.0.0.1", with: key, tweak: tweak)
```

#### Non-Deterministic Extended Mode (NDX)

Uses AES-XTS with a 16-byte random tweak. Maximum security.

```swift
let key = IPCrypt.Key.random(for: .ndx)

// Output is 32 bytes: 16-byte tweak + 16-byte ciphertext
let encrypted = try IPCrypt.encrypt("10.0.0.1", with: key)
print("Size: \(encrypted.data.count) bytes")
print("Hex: \(encrypted.hexString)")
```

### Decryption

```swift
// Method 1: Decrypt using EncryptedIP object
let decrypted = try IPCrypt.decrypt(encrypted, with: key)

// Method 2: Decrypt from raw data
let encryptedData = Data(hexString: "08e0c289bff23b7c...")!
let decrypted = try IPCrypt.decrypt(data: encryptedData, with: key)
```

### Error Handling

```swift
do {
    let key = try IPCrypt.Key(hexString: keyString, mode: .deterministic)
    let result = try IPCrypt.encrypt(ipAddress, with: key)
    // Use result...
} catch IPCrypt.Error.invalidKeyLength(let expected, let actual) {
    print("Key length error: expected \(expected), got \(actual)")
} catch IPCrypt.Error.invalidTweakLength(let expected, let actual) {
    print("Tweak length error: expected \(expected), got \(actual)")
} catch IPCrypt.Error.invalidIPAddress(let address) {
    print("Invalid IP address: \(address)")
} catch IPCrypt.Error.invalidDataLength(let expected, let actual) {
    print("Data length error: expected \(expected), got \(actual)")
} catch {
    print("Unexpected error: \(error)")
}
```

### IPv6 Support

```swift
let key = IPCrypt.Key.random(for: .deterministic)

// Works with both IPv4 and IPv6
let ipv4Encrypted = try IPCrypt.encrypt("192.168.1.1", with: key)
let ipv6Encrypted = try IPCrypt.encrypt("2001:db8::1", with: key)

// IPv4 addresses are internally converted to IPv4-mapped IPv6
// This is transparent to the user
```

## Advanced Usage

### Integration with Codable

```swift
struct SecureLogEntry: Codable {
    let timestamp: Date
    let action: String
    let encryptedIP: String

    init(ip: String, action: String, key: IPCrypt.Key) throws {
        self.timestamp = Date()
        self.action = action
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

// Usage
let key = IPCrypt.Key.random(for: .nd)
let entry = try SecureLogEntry(ip: "192.0.2.1", action: "LOGIN", key: key)

// Serialize to JSON
let json = try JSONEncoder().encode(entry)

// Deserialize and decrypt
let decoded = try JSONDecoder().decode(SecureLogEntry.self, from: json)
let originalIP = try decoded.decryptIP(with: key)
```

### Batch Processing with Async/Await

```swift
@available(macOS 10.15, iOS 13.0, *)
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
```

### SwiftUI Integration

```swift
import SwiftUI
import IPCrypt

@available(iOS 13.0, macOS 10.15, *)
class IPEncryptionViewModel: ObservableObject {
    @Published var inputIP = ""
    @Published var outputText = ""
    @Published var errorMessage: String?

    private let key = IPCrypt.Key.random(for: .deterministic)

    func encrypt() {
        do {
            let encrypted = try IPCrypt.encrypt(inputIP, with: key)
            outputText = encrypted.ipString ?? encrypted.hexString
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
```

## Command Line Interface

The package includes a CLI tool for testing and scripting:

```bash
# Build the CLI
swift build

# Encrypt with deterministic mode
swift run IPCryptCLI deterministic encrypt 192.0.2.1 0123456789abcdeffedcba9876543210
# Output: Encrypted: 1dbd:c1b9:fff1:7586:7d0b:67b4:e76e:4777

# Encrypt with ND mode (random tweak)
swift run IPCryptCLI nd encrypt 192.0.2.1 0123456789abcdeffedcba9876543210
# Output: Encrypted: [24 bytes hex]

# Encrypt with ND mode (specific tweak)
swift run IPCryptCLI nd encrypt 0.0.0.0 0123456789abcdeffedcba9876543210 08e0c289bff23b7c
# Output: Encrypted: 08e0c289bff23b7cb349aadfe3bcef56221c384c7c217b16

# Decrypt
swift run IPCryptCLI deterministic decrypt 1dbd:c1b9:fff1:7586:7d0b:67b4:e76e:4777 2b7e151628aed2a6abf7158809cf4f3c
# Output: Decrypted: 192.0.2.1

swift run IPCryptCLI nd decrypt 08e0c289bff23b7cb349aadfe3bcef56221c384c7c217b16 0123456789abcdeffedcba9876543210
# Output: Decrypted: 0.0.0.0
```

## API Reference

### Types

#### `IPCrypt.Mode`

```swift
enum Mode {
    case deterministic  // 16-byte key, 16-byte output
    case nd            // 16-byte key, 24-byte output
    case ndx           // 32-byte key, 32-byte output
}
```

#### `IPCrypt.Key`

```swift
struct Key {
    let data: Data
    let mode: Mode

    init(data: Data, mode: Mode) throws
    init(hexString: String, mode: Mode) throws
    static func random(for mode: Mode) -> Key
}
```

#### `IPCrypt.EncryptedIP`

```swift
struct EncryptedIP: Equatable {
    let mode: Mode
    let data: Data           // Full encrypted data
    let tweak: Data?         // Tweak for non-deterministic modes
    let ciphertext: Data     // Ciphertext without tweak

    var hexString: String    // Hex representation
    var ipString: String?    // IP string (deterministic mode only)
}
```

#### `IPCrypt.Error`

```swift
enum Error: LocalizedError, Equatable {
    case invalidKeyLength(expected: Int, actual: Int)
    case invalidTweakLength(expected: Int, actual: Int)
    case invalidDataLength(expected: Int, actual: Int)
    case invalidIPAddress(String)
    case invalidHexString(String)
}
```

### Functions

```swift
// Encrypt an IP address
static func encrypt(_ ip: String, with key: Key, tweak: Data? = nil) throws -> EncryptedIP

// Decrypt an encrypted IP
static func decrypt(_ encrypted: EncryptedIP, with key: Key) throws -> String

// Decrypt from raw data
static func decrypt(data: Data, with key: Key) throws -> String
```

## Security Considerations

1. **Key Management**: Store keys securely using iOS Keychain or similar secure storage
2. **Deterministic Mode**: Same input produces same output - use only when necessary
3. **Non-Deterministic Modes**: Preferred for maximum security, prevents correlation attacks
4. **Thread Safety**: All operations are thread-safe and can be used concurrently
5. **No Authentication**: These methods provide confidentiality only, not authentication

## Testing

Run the test suite:

```bash
swift test
```

Run specific tests:

```bash
swift test --filter IPCryptModernAPITests
```
