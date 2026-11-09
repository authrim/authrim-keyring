import Foundation
import Testing
@testable import AuthrimKeyring

nonisolated private final class ResolutionTrace: @unchecked Sendable {
    private let lock = NSLock()
    private var hosts: [String] = []

    func append(_ host: String) { lock.lock(); hosts.append(host); lock.unlock() }
    var values: [String] { lock.lock(); defer { lock.unlock() }; return hosts }
}

@Suite(.serialized)
struct WalletPublicProxyTests {
    @Test func refusesEveryPrivateOrUnparseableDNSAnswer() throws {
        for answers in [
            ["10.0.0.8"], ["8.8.8.8", "192.168.1.5"], ["127.0.0.1"],
            ["fd00::1"], ["fec0::1"], ["64:ff9b:1::a00:1"],
            ["2002:a00:8::1"], ["2001::1"], ["2001:2::1"],
            ["2001:0002::1"], ["8.8.8.8", "2001:2::1"],
            ["2001:5::1"], ["2001:10::1"], ["2001:1::4"],
            ["2001:4:113::1"], ["2001:db8::1"],
            ["192.0.2.1"], ["198.51.100.1"], ["203.0.113.1"],
            ["::ffff:10.0.0.8"], ["not-an-address"], []
        ] {
            #expect(throws: WalletError.self) {
                try WalletPublicProxy.publicAddress(from: answers)
            }
        }
    }

    @Test func acceptsPublicDNSAnswersForThePinnedConnection() throws {
        #expect(try WalletPublicProxy.publicAddress(from: ["8.8.8.8", "2606:4700::1111"]) == "8.8.8.8")
        #expect(try WalletPublicProxy.publicAddress(from: ["64:ff9b::808:808"]) == "64:ff9b::808:808")
        for address in [
            "2001:1::1", "2001:1::2", "2001:1::3", "2001:3::1",
            "2001:4:112::1", "2001:20::1", "2001:30::1", "2001:4860::8888",
        ] {
            #expect(try WalletPublicProxy.publicAddress(from: [address]) == address)
        }
    }

    @Test func refusesBenchmarkingIPv6HostLiteral() {
        let url = URL(string: "https://[2001:2::1]/offer")!
        #expect(throws: WalletError.self) { try WalletHTTP.requireHTTPS(url, "The offer URL") }
    }

    @Test func publicLookingOfferHostResolvingPrivatelyNeverGetsFetched() async {
        let trace = ResolutionTrace()
        let http = WalletHTTP(publicAddressResolver: { host in
            trace.append(host)
            return ["10.0.0.8"]
        })
        let url = URL(string: "https://offer.example/credential-offer")!
        await #expect(throws: WalletError.self) { try await http.send(url) }
        // This proves the production URLSession used CONNECT; a direct fallback would skip the
        // resolver and cause this assertion to fail even if the fake host were unreachable.
        #expect(trace.values == ["offer.example"])
    }

    @Test func publicIPv6LiteralReachesThePinnedResolver() async {
        let trace = ResolutionTrace()
        let http = WalletHTTP(publicAddressResolver: { host in
            trace.append(host)
            return ["10.0.0.8"]
        })
        let url = URL(string: "https://[2606:4700::1111]/offer")!
        await #expect(throws: WalletError.self) { try await http.send(url) }
        #expect(trace.values == ["2606:4700::1111"])
    }
}
