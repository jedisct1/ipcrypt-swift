import Foundation
import Network

/// Internal representation of an IP address for cryptographic operations
internal enum IPAddress: Equatable {
    case v4(Data)
    case v6(Data)

    init(_ string: String) throws {
        if let v4 = IPv4Address(string) {
            self = .v4(v4.rawValue)
        } else if let v6 = IPv6Address(string) {
            self = .v6(v6.rawValue)
        } else {
            throw IPCrypt.Error.invalidIPAddress(string)
        }
    }

    init(from bytes16: Data) throws {
        guard bytes16.count == 16 else {
            throw IPCrypt.Error.invalidDataLength(expected: 16, actual: bytes16.count)
        }

        let prefix = bytes16[0..<10]
        let mappingBytes = bytes16[10..<12]

        if prefix == Data(repeating: 0, count: 10) && mappingBytes == Data([0xFF, 0xFF]) {
            self = .v4(bytes16[12..<16])
        } else {
            self = .v6(bytes16)
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

    var stringValue: String {
        switch self {
        case .v4(let data):
            guard data.count == 4 else { return "" }
            guard let v4 = IPv4Address(data) else { return "" }
            return "\(v4)"
        case .v6(let data):
            guard data.count == 16 else { return "" }
            guard let v6 = IPv6Address(data) else { return "" }
            return "\(v6)"
        }
    }

    var description: String {
        stringValue
    }
}

// MARK: - Data Hex Extensions

public extension Data {
    /// Convert data bytes to a lowercase hexadecimal string.
    ///
    /// - Returns: A lowercase hexadecimal string representation of the data
    ///
    /// ## Example
    /// ```swift
    /// let data = Data([0x01, 0x23, 0xAB])
    /// print(data.toHexString()) // "0123ab"
    /// ```
    func toHexString() -> String {
        map { String(format: "%02x", $0) }.joined()
    }

    /// Computed property alias for toHexString()
    var hexString: String {
        toHexString()
    }

    /// Initialize data from a hexadecimal string.
    ///
    /// The string must contain an even number of hexadecimal characters.
    /// Both uppercase and lowercase hex digits are accepted.
    ///
    /// - Parameter hexString: A hexadecimal string (e.g., "0123abcd")
    /// - Returns: Data if the string is valid hex, nil otherwise
    ///
    /// ## Example
    /// ```swift
    /// if let data = Data(hexString: "0123abcd") {
    ///     print(data.count) // 4
    /// }
    /// ```
    init?(hexString: String) {
        let len = hexString.count / 2
        var data = Data(capacity: len)
        var index = hexString.startIndex

        for _ in 0..<len {
            let nextIndex = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index..<nextIndex], radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }

        self = data
    }
}
