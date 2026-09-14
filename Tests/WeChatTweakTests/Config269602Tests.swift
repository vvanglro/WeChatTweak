import XCTest
@testable import WeChatTweak

final class Config269602Tests: XCTestCase {
    private func repoRoot() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    func test269602HasVerifiedDylibPatchPoints() throws {
        let url = repoRoot().appendingPathComponent("config.json")
        let configs = try JSONDecoder().decode([Config].self, from: Data(contentsOf: url))
        let config = try XCTUnwrap(configs.first { $0.version == "269602" })
        XCTAssertEqual(config.targets.map(\.identifier), ["revoke", "revoke-keeptip", "multiInstance"])
        XCTAssertTrue(config.targets.allSatisfy { $0.binary == "Contents/Resources/wechat.dylib" })

        let silent = try XCTUnwrap(config.targets.first { $0.identifier == "revoke" }?.entries.first)
        XCTAssertEqual(silent.addr, 0x44de938)
        XCTAssertEqual(silent.expected.map(\.hexString), ["F44FBEA9FD7B01A9"])
        XCTAssertEqual(silent.asm.hexString, "00008052C0035FD6")

        let keeptip = try XCTUnwrap(config.targets.first { $0.identifier == "revoke-keeptip" })
        XCTAssertEqual(keeptip.entries.count, 3)
        XCTAssertEqual(keeptip.entries[0].addr, 0x44de938)
        XCTAssertEqual(keeptip.entries[0].expected.map(\.hexString), ["F44FBEA9FD7B01A9", "00008052C0035FD6"])
        XCTAssertEqual(keeptip.entries[0].asm.hexString, "F44FBEA9FD7B01A9")
        XCTAssertEqual(keeptip.entries[1].addr, 0x4941e44)
        XCTAssertEqual(keeptip.entries[1].expected.map(\.hexString), ["40100034", "82000014"])
        XCTAssertEqual(keeptip.entries[1].asm.hexString, "40100034")
        XCTAssertEqual(keeptip.entries[2].addr, 0x49425e4)
        XCTAssertEqual(keeptip.entries[2].expected.map(\.hexString), ["60E600F9"])
        XCTAssertEqual(keeptip.entries[2].asm.hexString, "7FE600F9")

        let multiInstance = try XCTUnwrap(config.targets.first { $0.identifier == "multiInstance" }?.entries.first)
        XCTAssertEqual(multiInstance.addr, 0x27370c)
        XCTAssertEqual(multiInstance.expected.map(\.hexString), ["FF0306D1FC6F14A9"])
        XCTAssertEqual(multiInstance.asm.hexString, "20008052C0035FD6")
    }
}
