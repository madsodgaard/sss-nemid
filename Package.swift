// swift-tools-version:5.2
import PackageDescription

let package = Package(
    name: "sss-nemid",
    platforms: [
        .macOS(.v10_15),
    ],
    products: [
        .library(
            name: "NemID",
            targets: ["NemID"]),
        /* This target is used only for symbol mangling. It's added and removed automatically because it emits build warnings. MANGLE_START
         .library(name: "CNemIDBoringSSL", type: .static, targets: ["CNemIDBoringSSL"]),
         MANGLE_END */
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "1.1.3"),
        .package(url: "https://github.com/yahoojapan/SwiftyXMLParser.git", from: "5.3.0")
    ],
    targets: [
        .target(name: "CNemIDBoringSSL"),
        .target(
            name: "NemID",
            dependencies: [
                .target(name: "CNemIDBoringSSL"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "SwiftyXMLParser", package: "SwiftyXMLParser")
            ]),
        .testTarget(
            name: "NemIDTests",
            dependencies: ["NemID"]),
    ],
    cxxLanguageStandard: .cxx11
)
