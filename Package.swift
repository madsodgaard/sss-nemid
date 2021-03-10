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
        .package(url: "https://github.com/swift-server/async-http-client.git", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "NemID",
            dependencies: [
                "Clibxml2",
                "CNemIDBoringSSL",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "AsyncHTTPClient", package: "async-http-client"),
            ]
        ),
        .target(name: "CNemIDBoringSSL"),
        .systemLibrary(
            name: "Clibxml2",
            pkgConfig: "libxml-2.0",
            providers: [
                .apt(["libxml2"]),
                .brew(["libxml2"]),
            ]
        ),
        .testTarget(
            name: "NemIDTests",
            dependencies: ["NemID"]),
    ],
    cxxLanguageStandard: .cxx11
)
