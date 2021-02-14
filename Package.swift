// swift-tools-version:5.3
import PackageDescription

let package = Package(
    name: "sss-nemid",
    platforms: [
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "NemID'",
            targets: ["NemID"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "1.1.3")
    ],
    targets: [
        .target(
            name: "NemID",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto")
            ]),
        .testTarget(
            name: "NemIDTests",
            dependencies: ["NemID"]),
    ]
)
