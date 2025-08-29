import Foundation
import IPCrypt
import Network

func printUsage() {
    print("""
    IPCrypt Swift Implementation

    Usage: IPCryptCLI <mode> <operation> <ip> <key> [tweak]

    Modes:
        deterministic - AES-128 deterministic encryption
        nd           - KIASU-BC with 8-byte tweak
        ndx          - AES-XTS with 16-byte tweak

    Operations:
        encrypt      - Encrypt an IP address
        decrypt      - Decrypt an IP address

    Examples:
        IPCryptCLI deterministic encrypt 192.0.2.1 0123456789abcdeffedcba9876543210
        IPCryptCLI nd encrypt 192.0.2.1 0123456789abcdeffedcba9876543210 [optional_tweak_hex]
        IPCryptCLI ndx encrypt 192.0.2.1 0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301 [optional_tweak_hex]
    """)
}

guard CommandLine.arguments.count >= 5 else {
    printUsage()
    exit(1)
}

let modeName = CommandLine.arguments[1]
let operation = CommandLine.arguments[2]
let input = CommandLine.arguments[3]
let keyHex = CommandLine.arguments[4]

// Parse mode
let mode: IPCrypt.Mode
switch modeName {
case "deterministic":
    mode = .deterministic
case "nd":
    mode = .nd
case "ndx":
    mode = .ndx
default:
    print("Error: Invalid mode '\(modeName)'")
    printUsage()
    exit(1)
}

// Create key
let key: IPCrypt.Key
do {
    key = try IPCrypt.Key(hexString: keyHex, mode: mode)
} catch {
    print("Error creating key: \(error)")
    exit(1)
}

// Parse optional tweak
let tweak: Data?
if CommandLine.arguments.count > 5, mode != .deterministic {
    guard let tweakData = Data(hexString: CommandLine.arguments[5]) else {
        print("Error: Invalid tweak hex string")
        exit(1)
    }
    tweak = tweakData
} else {
    tweak = nil
}

// Perform operation
do {
    switch operation {
    case "encrypt":
        let encrypted = try IPCrypt.encrypt(input, with: key, tweak: tweak)

        // Output format depends on mode
        if mode == .deterministic, let ipString = encrypted.ipString {
            print("Encrypted: \(ipString)")
        } else {
            print("Encrypted: \(encrypted.hexString)")
        }

    case "decrypt":
        let result: String

        if mode == .deterministic {
            // For deterministic mode, input could be an IP address
            if input.contains(":") || input.contains(".") {
                // It's an IP address
                guard let ipAddress = try? IPAddress(input) else {
                    print("Error: Invalid IP address for decryption")
                    exit(1)
                }
                let encrypted = IPCrypt.EncryptedIP(mode: .deterministic, data: ipAddress.to16Bytes())
                result = try IPCrypt.decrypt(encrypted, with: key)
            } else {
                // It's hex data
                guard let data = Data(hexString: input) else {
                    print("Error: Invalid hex string for decryption")
                    exit(1)
                }
                result = try IPCrypt.decrypt(data: data, with: key)
            }
        } else {
            // For non-deterministic modes, input must be hex
            guard let data = Data(hexString: input) else {
                print("Error: For non-deterministic modes, provide encrypted data as hex")
                exit(1)
            }
            result = try IPCrypt.decrypt(data: data, with: key)
        }

        print("Decrypted: \(result)")

    default:
        print("Error: Invalid operation '\(operation)'")
        printUsage()
        exit(1)
    }
} catch {
    print("Error: \(error)")
    exit(1)
}

// MARK: - IPAddress

// Helper to access internal IPAddress type
private enum IPAddress {
    case v4(Data)
    case v6(Data)

    // MARK: Lifecycle

    init(_ string: String) throws {
        if let v4 = IPv4Address(string) {
            self = .v4(v4.rawValue)
        } else if let v6 = IPv6Address(string) {
            self = .v6(v6.rawValue)
        } else {
            throw IPCrypt.Error.invalidIPAddress(string)
        }
    }

    // MARK: Internal

    func to16Bytes() -> Data {
        switch self {
        case let .v4(data):
            var result = Data(repeating: 0, count: 10)
            result.append(contentsOf: [0xFF, 0xFF])
            result.append(data)
            return result
        case let .v6(data):
            return data
        }
    }
}
