import Foundation

/// IPCrypt provides methods for encrypting and obfuscating IP addresses
/// according to the IPCrypt specification.
///
/// This implementation supports three encryption modes:
/// - `deterministic`: Always produces the same output for the same input
/// - `nd`: Non-deterministic with 8-byte random tweak (KIASU-BC)
/// - `ndx`: Non-deterministic with 16-byte random tweak (AES-XTS)
///
/// ## Example Usage
/// ```swift
/// // Create a key for deterministic encryption
/// let key = IPCrypt.Key.random(for: .deterministic)
///
/// // Encrypt an IP address
/// let encrypted = try IPCrypt.encrypt("192.0.2.1", with: key)
///
/// // Decrypt back to original
/// let original = try IPCrypt.decrypt(encrypted, with: key)
/// ```
public enum IPCrypt {
    // MARK: - Error Types

    /// Errors that can occur during IPCrypt operations.
    ///
    /// These errors provide detailed information about what went wrong,
    /// including expected vs. actual values for validation failures.
    public enum Error: LocalizedError, Equatable {
        /// The provided key has an incorrect length for the specified mode
        case invalidKeyLength(expected: Int, actual: Int)
        /// The provided tweak has an incorrect length for the specified mode
        case invalidTweakLength(expected: Int, actual: Int)
        /// The encrypted data has an incorrect length for decryption
        case invalidDataLength(expected: Int, actual: Int)
        /// The provided string is not a valid IPv4 or IPv6 address
        case invalidIPAddress(String)
        /// The provided string is not valid hexadecimal
        case invalidHexString(String)

        public var errorDescription: String? {
            switch self {
            case let .invalidKeyLength(expected, actual):
                return "Invalid key length: expected \(expected) bytes, got \(actual)"
            case let .invalidTweakLength(expected, actual):
                return "Invalid tweak length: expected \(expected) bytes, got \(actual)"
            case let .invalidDataLength(expected, actual):
                return "Invalid data length: expected \(expected) bytes, got \(actual)"
            case .invalidIPAddress(let address):
                return "Invalid IP address: \(address)"
            case .invalidHexString(let hex):
                return "Invalid hexadecimal string: \(hex)"
            }
        }
    }

    // MARK: - Encryption Modes

    /// IPCrypt encryption mode.
    ///
    /// Each mode offers different security properties:
    /// - `deterministic`: Fast, format-preserving, but same input always produces same output
    /// - `nd`: Randomized output using KIASU-BC, moderate security
    /// - `ndx`: Randomized output using AES-XTS, highest security
    public enum Mode {
        /// Deterministic AES-128 encryption (16-byte output)
        case deterministic
        /// Non-deterministic KIASU-BC with 8-byte tweak (24-byte output)
        case nd
        /// Non-deterministic AES-XTS with 16-byte tweak (32-byte output)
        case ndx

        /// Required key length for this mode in bytes
        public var keyLength: Int {
            switch self {
            case .deterministic, .nd: return 16
            case .ndx: return 32
            }
        }

        /// Tweak length for non-deterministic modes in bytes
        public var tweakLength: Int? {
            switch self {
            case .deterministic: return nil
            case .nd: return 8
            case .ndx: return 16
            }
        }

        /// Total output length including tweak for non-deterministic modes
        public var outputLength: Int {
            switch self {
            case .deterministic: return 16
            case .nd: return 24
            case .ndx: return 32
            }
        }
    }

    // MARK: - Key Management

    /// A cryptographic key for IPCrypt operations.
    ///
    /// Keys are bound to a specific encryption mode and validated
    /// to ensure they have the correct length:
    /// - Deterministic/ND modes: 16 bytes (128 bits)
    /// - NDX mode: 32 bytes (256 bits)
    public struct Key {
        public let data: Data
        public let mode: Mode

        /// Initialize a key with raw bytes
        /// - Parameters:
        ///   - data: The key material
        ///   - mode: The encryption mode this key will be used for
        /// - Throws: `IPCrypt.Error.invalidKeyLength` if the key length doesn't match the mode requirements
        public init(data: Data, mode: Mode) throws {
            guard data.count == mode.keyLength else {
                throw Error.invalidKeyLength(expected: mode.keyLength, actual: data.count)
            }
            self.data = data
            self.mode = mode
        }

        /// Initialize a key from a hexadecimal string
        /// - Parameters:
        ///   - hexString: The key as a hex string
        ///   - mode: The encryption mode this key will be used for
        /// - Throws: `IPCrypt.Error.invalidHexString` or `IPCrypt.Error.invalidKeyLength`
        public init(hexString: String, mode: Mode) throws {
            guard let data = Data(hexString: hexString) else {
                throw Error.invalidHexString(hexString)
            }
            try self.init(data: data, mode: mode)
        }

        /// Generate a random key for the specified mode.
        ///
        /// Uses the system's secure random number generator to create
        /// cryptographically strong keys.
        ///
        /// - Parameter mode: The encryption mode
        /// - Returns: A new random key suitable for the mode
        ///
        /// ## Example
        /// ```swift
        /// let key = IPCrypt.Key.random(for: .deterministic)
        /// ```
        public static func random(for mode: Mode) -> Key {
            var bytes = Data(count: mode.keyLength)
            _ = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, mode.keyLength, $0.baseAddress!) }
            return try! Key(data: bytes, mode: mode)
        }
    }

    // MARK: - Encrypted IP Result

    /// Result of encrypting an IP address.
    ///
    /// Contains the encrypted data along with metadata about the encryption:
    /// - For deterministic mode: Just the 16-byte ciphertext
    /// - For ND mode: 8-byte tweak + 16-byte ciphertext (24 bytes total)
    /// - For NDX mode: 16-byte tweak + 16-byte ciphertext (32 bytes total)
    public struct EncryptedIP: Equatable {
        /// The encryption mode used
        public let mode: Mode
        /// The encrypted data (including tweak for non-deterministic modes)
        public let data: Data
        /// The tweak used (nil for deterministic mode)
        public let tweak: Data?
        /// The ciphertext (without tweak)
        public let ciphertext: Data

        /// Get the encrypted IP as a hexadecimal string.
        ///
        /// Returns the full encrypted data (including tweak for non-deterministic modes)
        /// as a lowercase hexadecimal string.
        public var hexString: String {
            data.toHexString()
        }

        /// For deterministic mode, returns the encrypted IP address string.
        ///
        /// Only available for deterministic mode where the output is a valid IP address.
        /// Returns nil for non-deterministic modes.
        ///
        /// ## Example
        /// ```swift
        /// let encrypted = try IPCrypt.encrypt("192.0.2.1", with: key)
        /// if let ipString = encrypted.ipString {
        ///     print("Encrypted to IP: \(ipString)")
        /// }
        /// ```
        public var ipString: String? {
            guard mode == .deterministic else { return nil }
            return (try? IPAddress(from: ciphertext))?.stringValue
        }

        public init(mode: Mode, data: Data, tweak: Data? = nil) {
            self.mode = mode
            self.data = data
            self.tweak = tweak

            switch mode {
            case .deterministic:
                self.ciphertext = data
            case .nd:
                self.ciphertext = Data(data[8...])
            case .ndx:
                self.ciphertext = Data(data[16...])
            }
        }
    }

    // MARK: - Main API

    /// Encrypt an IP address.
    ///
    /// Supports both IPv4 and IPv6 addresses. IPv4 addresses are automatically
    /// converted to IPv4-mapped IPv6 format for encryption.
    ///
    /// - Parameters:
    ///   - ip: The IP address string (IPv4 or IPv6)
    ///   - key: The encryption key (must match the mode)
    ///   - tweak: Optional tweak for non-deterministic modes (random if nil)
    /// - Returns: The encrypted IP result containing ciphertext and metadata
    /// - Throws: `IPCrypt.Error` if parameters are invalid
    ///
    /// ## Example
    /// ```swift
    /// let key = IPCrypt.Key.random(for: .nd)
    /// let encrypted = try IPCrypt.encrypt("192.0.2.1", with: key)
    /// print("Encrypted: \(encrypted.hexString)")
    /// ```
    public static func encrypt(_ ip: String, with key: Key, tweak: Data? = nil) throws -> EncryptedIP {
        switch key.mode {
        case .deterministic:
            return try encryptDeterministic(ip, key: key.data)
        case .nd:
            return try encryptND(ip, key: key.data, tweak: tweak)
        case .ndx:
            return try encryptNDX(ip, key: key.data, tweak: tweak)
        }
    }

    /// Decrypt an encrypted IP address.
    ///
    /// The key must be the same one used for encryption and must match
    /// the mode of the encrypted data.
    ///
    /// - Parameters:
    ///   - encrypted: The encrypted IP data from `encrypt()`
    ///   - key: The decryption key (must be same as encryption key)
    /// - Returns: The original IP address string
    /// - Throws: `IPCrypt.Error` if parameters are invalid or decryption fails
    ///
    /// ## Example
    /// ```swift
    /// let decrypted = try IPCrypt.decrypt(encrypted, with: key)
    /// print("Original IP: \(decrypted)")
    /// ```
    public static func decrypt(_ encrypted: EncryptedIP, with key: Key) throws -> String {
        guard encrypted.mode == key.mode else {
            throw Error.invalidDataLength(expected: key.mode.outputLength, actual: encrypted.data.count)
        }

        switch key.mode {
        case .deterministic:
            return try decryptDeterministic(encrypted.data, key: key.data)
        case .nd:
            return try decryptND(encrypted.data, key: key.data)
        case .ndx:
            return try decryptNDX(encrypted.data, key: key.data)
        }
    }

    /// Decrypt encrypted IP data from raw bytes.
    ///
    /// Convenience method for decrypting from raw data instead of an `EncryptedIP` object.
    /// The data length must match the expected output length for the key's mode.
    ///
    /// - Parameters:
    ///   - data: The encrypted data (including tweak for non-deterministic modes)
    ///   - key: The decryption key
    /// - Returns: The original IP address string
    /// - Throws: `IPCrypt.Error` if parameters are invalid or data length is incorrect
    ///
    /// ## Example
    /// ```swift
    /// let encryptedData = Data(hexString: "08e0c289bff23b7c...")!
    /// let decrypted = try IPCrypt.decrypt(data: encryptedData, with: key)
    /// ```
    public static func decrypt(data: Data, with key: Key) throws -> String {
        guard data.count == key.mode.outputLength else {
            throw Error.invalidDataLength(expected: key.mode.outputLength, actual: data.count)
        }

        let encrypted = EncryptedIP(mode: key.mode, data: data)
        return try decrypt(encrypted, with: key)
    }

    // MARK: - Private Implementation

    private static func encryptDeterministic(_ ip: String, key: Data) throws -> EncryptedIP {
        guard let ipAddress = try? IPAddress(ip) else {
            throw Error.invalidIPAddress(ip)
        }

        let plaintext = ipAddress.to16Bytes()
        let ciphertext = AESCore.encryptBlock(plaintext, key: key)

        return EncryptedIP(mode: .deterministic, data: ciphertext)
    }

    private static func decryptDeterministic(_ data: Data, key: Data) throws -> String {
        guard data.count == 16 else {
            throw Error.invalidDataLength(expected: 16, actual: data.count)
        }

        let plaintext = AESCore.decryptBlock(data, key: key)
        guard let ipAddress = try? IPAddress(from: plaintext) else {
            throw Error.invalidIPAddress("(decrypted data)")
        }

        return ipAddress.stringValue
    }

    private static func encryptND(_ ip: String, key: Data, tweak: Data?) throws -> EncryptedIP {
        guard let ipAddress = try? IPAddress(ip) else {
            throw Error.invalidIPAddress(ip)
        }

        let actualTweak: Data
        if let providedTweak = tweak {
            guard providedTweak.count == 8 else {
                throw Error.invalidTweakLength(expected: 8, actual: providedTweak.count)
            }
            actualTweak = providedTweak
        } else {
            actualTweak = Data.random(count: 8)
        }

        let ipBytes = ipAddress.to16Bytes()
        let ciphertext = KIASUBC.encrypt(key: key, tweak: actualTweak, plaintext: ipBytes)

        var result = Data()
        result.append(actualTweak)
        result.append(ciphertext)

        return EncryptedIP(mode: .nd, data: result, tweak: actualTweak)
    }

    private static func decryptND(_ data: Data, key: Data) throws -> String {
        guard data.count == 24 else {
            throw Error.invalidDataLength(expected: 24, actual: data.count)
        }

        let tweak = data[0..<8]
        let ciphertext = data[8..<24]

        let ipBytes = KIASUBC.decrypt(key: key, tweak: Data(tweak), ciphertext: Data(ciphertext))
        guard let ipAddress = try? IPAddress(from: ipBytes) else {
            throw Error.invalidIPAddress("(decrypted data)")
        }

        return ipAddress.stringValue
    }

    private static func encryptNDX(_ ip: String, key: Data, tweak: Data?) throws -> EncryptedIP {
        guard let ipAddress = try? IPAddress(ip) else {
            throw Error.invalidIPAddress(ip)
        }

        let actualTweak: Data
        if let providedTweak = tweak {
            guard providedTweak.count == 16 else {
                throw Error.invalidTweakLength(expected: 16, actual: providedTweak.count)
            }
            actualTweak = providedTweak
        } else {
            actualTweak = Data.random(count: 16)
        }

        let ipBytes = ipAddress.to16Bytes()
        let ciphertext = AESXTS.encrypt(key: key, tweak: actualTweak, plaintext: ipBytes)

        var result = Data()
        result.append(actualTweak)
        result.append(ciphertext)

        return EncryptedIP(mode: .ndx, data: result, tweak: actualTweak)
    }

    private static func decryptNDX(_ data: Data, key: Data) throws -> String {
        guard data.count == 32 else {
            throw Error.invalidDataLength(expected: 32, actual: data.count)
        }

        let tweak = data[0..<16]
        let ciphertext = data[16..<32]

        let ipBytes = AESXTS.decrypt(key: key, tweak: Data(tweak), ciphertext: Data(ciphertext))
        guard let ipAddress = try? IPAddress(from: ipBytes) else {
            throw Error.invalidIPAddress("(decrypted data)")
        }

        return ipAddress.stringValue
    }
}

// MARK: - Data Extensions

extension Data {
    /// Generate random data of specified length
    static func random(count: Int) -> Data {
        var bytes = Data(count: count)
        _ = bytes.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        return bytes
    }
}
