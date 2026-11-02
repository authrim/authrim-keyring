import Foundation
import Testing
@testable import AuthrimKeyring

/// Exports shaped like the apps' own, with made-up accounts and keys.
struct AppExportReaderTests {
    private func read(_ json: String) throws -> ImportedAccounts {
        try AppExportReader.read(Data(json.utf8))
    }

    @Test func aegis() throws {
        let result = try read("""
        {"version":1,"header":{"slots":null,"params":null},"db":{"version":3,"entries":[
          {"type":"totp","name":"alex@example.com","issuer":"Northwind","info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA1","digits":6,"period":30}},
          {"type":"hotp","name":"alex","issuer":"Harbor Bank","info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA1","digits":6,"counter":12}},
          {"type":"steam","name":"player","issuer":"Steam","info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA1","digits":5,"period":30}},
          {"type":"yandex","name":"alex","issuer":"Yandex","info":{"secret":"JBSWY3DPEHPK3PXP"}}
        ]}}
        """)
        #expect(result.accounts.map(\.kind) == [.totp, .hotp(counter: 12), .steam])
        #expect(result.skipped.map(\.name) == ["Yandex – alex"])
    }

    @Test(arguments: ["-1", "1.5", "\"42\""])
    func invalidCountersAreSkipped(counter: String) throws {
        let result = try read("""
        {"db":{"entries":[{"type":"hotp","name":"alex","issuer":"Harbor","info":{"secret":"JBSWY3DPEHPK3PXP","counter":\(counter)}}]}}
        """)
        #expect(result.accounts.isEmpty)
        #expect(result.skipped.count == 1)
    }

    @Test func encryptedAegis() {
        #expect(throws: ImportError.encrypted(app: "Aegis")) {
            try read(#"{"version":1,"header":{},"db":"c2VjcmV0"}"#)
        }
    }

    @Test func twoFAS() throws {
        let result = try read("""
        {"services":[
          {"name":"Cedar Games","secret":"JBSWY3DPEHPK3PXP","otp":{"account":"alex","tokenType":"TOTP","digits":6,"period":30,"algorithm":"SHA1"}},
          {"name":"Harbor Bank","secret":"JBSWY3DPEHPK3PXP","otp":{"account":"alex","tokenType":"HOTP","digits":6,"counter":3,"algorithm":"SHA1"}},
          {"name":"Steam","secret":"JBSWY3DPEHPK3PXP","otp":{"account":"player","tokenType":"STEAM"}}
        ],"schemaVersion":4}
        """)
        #expect(result.accounts.map(\.kind) == [.totp, .hotp(counter: 3), .steam])
    }

    @Test func bitwarden() throws {
        let result = try read("""
        {"encrypted":false,"folders":[],"items":[
          {"type":1,"name":"Orbit Chat","login":{"username":"alex","totp":"otpauth://totp/Orbit:alex?secret=JBSWY3DPEHPK3PXP&issuer=Orbit",
            "uris":[{"match":null,"uri":"https://www.orbit.example/login"},{"uri":"androidapp://example.orbit"}]}},
          {"type":1,"name":"Willow Docs","login":{"username":"alex@example.com","totp":"JBSW Y3DP EHPK 3PXP","uris":[]}},
          {"type":1,"name":"Steam","login":{"username":"player","totp":"steam://JBSWY3DPEHPK3PXP"}},
          {"type":1,"name":"Password only","login":{"username":"alex","password":"not-read"}},
          {"type":2,"name":"A note","notes":"text"}
        ]}
        """)
        #expect(result.accounts.map(\.issuer) == ["Orbit Chat", "Willow Docs", "Steam"])
        #expect(result.accounts.map(\.kind) == [.totp, .totp, .steam])
        #expect(result.skipped.isEmpty)
        let orbit = try #require(result.accounts.first)
        #expect(result.details == [AccountDetails(id: orbit.id, websites: ["orbit.example"])])
    }

    @Test func encryptedBitwarden() {
        #expect(throws: ImportError.encrypted(app: "Bitwarden")) {
            try read(#"{"encrypted":true,"passwordProtected":true,"data":"x"}"#)
        }
    }

    @Test func keyURIsIncludingSteamAndCounterBased() throws {
        let result = try AppExportReader.readKeyURIs("""
        otpauth://totp/Fern:alex?secret=JBSWY3DPEHPK3PXP
        otpauth://hotp/Harbor:alex?secret=JBSWY3DPEHPK3PXP&counter=5
        otpauth://steam/Steam:player?secret=JBSWY3DPEHPK3PXP
        """)
        #expect(result.accounts.map(\.kind) == [.totp, .hotp(counter: 5), .steam])
    }
}
