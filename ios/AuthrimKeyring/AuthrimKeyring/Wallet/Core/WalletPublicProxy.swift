import Foundation
import Network

/// A loopback CONNECT proxy used only by WalletHTTP's production URLSession. It lets URLSession
/// keep its HTTP and TLS handling while preventing a QR-controlled hostname from reaching a
/// private address after DNS resolution. No CONNECT response or application bytes are sent until
/// the destination has been resolved, pinned to a public numeric IP, and checked after connect.
nonisolated final class WalletPublicProxy: @unchecked Sendable {
    typealias Resolver = @Sendable (String) throws -> [String]

    private struct Authority: Hashable {
        let host: String
        let port: UInt16

        init?(_ url: URL) {
            guard let host = url.host, let port = UInt16(exactly: url.port ?? 443) else { return nil }
            self.host = host.lowercased()
            self.port = port
        }

        init(host: String, port: UInt16) {
            self.host = host
            self.port = port
        }
    }

    private let queue = DispatchQueue(label: "com.authrim.keyring.wallet-public-proxy")
    private let resolve: Resolver
    private var listener: NWListener?
    private var listeningPort: NWEndpoint.Port?
    private var startTimer: DispatchSourceTimer?
    private var waiters: [CheckedContinuation<NWEndpoint.Port, Error>] = []
    private var allowed: [Authority: Int] = [:]
    private var tunnels: [UUID: Tunnel] = [:]
    private var stopped = false

    init(resolve: @escaping Resolver = { try WalletPublicProxy.systemAddresses($0) }) {
        self.resolve = resolve
    }

    /// Registers this exact HTTPS authority for the lifetime of one WalletHTTP request.
    func begin(_ url: URL) async throws -> NWEndpoint.Port {
        guard let authority = Authority(url) else { throw WalletError.network("The request URL has no valid port.") }
        let port = try await start()
        queue.sync { allowed[authority, default: 0] += 1 }
        return port
    }

    func end(_ url: URL) {
        guard let authority = Authority(url) else { return }
        queue.sync {
            let count = allowed[authority, default: 0]
            if count <= 1 { allowed.removeValue(forKey: authority) }
            else { allowed[authority] = count - 1 }
        }
    }

    func stop() {
        queue.async {
            self.stopped = true
            self.listener?.cancel()
            self.listener = nil
            self.listeningPort = nil
            self.startTimer?.cancel()
            self.startTimer = nil
            self.failWaiters(WalletError.network("The wallet network proxy stopped."))
            let active = Array(self.tunnels.values)
            self.tunnels.removeAll()
            for tunnel in active { tunnel.close() }
        }
    }

    private func start() async throws -> NWEndpoint.Port {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { [self] in
                if self.stopped {
                    continuation.resume(throwing: WalletError.network("The wallet network proxy stopped."))
                    return
                }
                if let port = self.listeningPort {
                    continuation.resume(returning: port)
                    return
                }
                self.waiters.append(continuation)
                guard self.listener == nil else { return }
                do {
                    let parameters = NWParameters.tcp
                    parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
                    let listener = try NWListener(using: parameters)
                    listener.newConnectionLimit = 16
                    listener.newConnectionHandler = { [weak self, weak listener] connection in
                        guard let self, self.listener === listener else { connection.cancel(); return }
                        self.accept(connection)
                    }
                    listener.stateUpdateHandler = { [weak self, weak listener] state in
                        guard let listener else { return }
                        self?.listenerChanged(state, from: listener)
                    }
                    self.listener = listener
                    let timer = DispatchSource.makeTimerSource(queue: self.queue)
                    timer.schedule(deadline: .now() + 5)
                    timer.setEventHandler { [weak self] in
                        guard let self, self.listeningPort == nil else { return }
                        self.listener?.cancel()
                        self.listener = nil
                        self.startTimer?.cancel()
                        self.startTimer = nil
                        self.failWaiters(WalletError.network("The wallet network proxy timed out."))
                    }
                    self.startTimer = timer
                    timer.resume()
                    listener.start(queue: self.queue)
                } catch {
                    self.failWaiters(WalletError.network("The wallet network proxy could not start."))
                }
            }
        }
    }

    private func listenerChanged(_ state: NWListener.State, from source: NWListener) {
        guard listener === source else { return }
        switch state {
        case .ready:
            guard let port = listener?.port else {
                failWaiters(WalletError.network("The wallet network proxy has no port."))
                return
            }
            listeningPort = port
            startTimer?.cancel()
            startTimer = nil
            let pending = waiters
            waiters.removeAll()
            for waiter in pending { waiter.resume(returning: port) }
        case .failed:
            startTimer?.cancel()
            startTimer = nil
            listener?.cancel()
            listener = nil
            listeningPort = nil
            failWaiters(WalletError.network("The wallet network proxy failed."))
        case .cancelled:
            startTimer?.cancel()
            startTimer = nil
            listener = nil
            listeningPort = nil
            failWaiters(WalletError.network("The wallet network proxy was cancelled."))
        default: break
        }
    }

    private func failWaiters(_ error: Error) {
        let pending = waiters
        waiters.removeAll()
        for waiter in pending { waiter.resume(throwing: error) }
    }

    private func accept(_ connection: NWConnection) {
        guard !stopped, tunnels.count < 16 else { connection.cancel(); return }
        let tunnel = Tunnel(
            client: connection, queue: queue, resolve: resolve,
            isAllowed: { [weak self] host, port in
                (self?.allowed[Authority(host: host.lowercased(), port: port), default: 0] ?? 0) > 0
            },
            onClose: { [weak self] id in self?.tunnels.removeValue(forKey: id) })
        tunnels[tunnel.id] = tunnel
        tunnel.start()
    }

    /// Fail closed if *any* answer is private, not just the one selected first. The selected
    /// numeric address is used for the actual NWConnection, avoiding a second DNS lookup.
    static func publicAddress(from addresses: [String]) throws -> String {
        guard let first = addresses.first, !addresses.isEmpty,
              addresses.allSatisfy({ address in
                  let host = NWEndpoint.Host(address)
                  switch host {
                  case .ipv4, .ipv6: return WalletHTTP.isPublicHost(address)
                  case .name: return false
                  @unknown default: return false
                  }
              }) else {
            throw WalletError.network("The host resolves to a non-public address.")
        }
        return first
    }

    static func systemAddresses(_ host: String) throws -> [String] {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        hints.ai_protocol = IPPROTO_TCP
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &result) == 0, let first = result else {
            throw WalletError.network("The host could not be resolved.")
        }
        defer { freeaddrinfo(first) }
        var addresses: [String] = []
        var current: UnsafeMutablePointer<addrinfo>? = first
        while let item = current {
            var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let status = buffer.withUnsafeMutableBufferPointer { chars in
                getnameinfo(item.pointee.ai_addr, item.pointee.ai_addrlen,
                            chars.baseAddress, socklen_t(chars.count), nil, 0, NI_NUMERICHOST)
            }
            guard status == 0 else { throw WalletError.network("A resolved address is invalid.") }
            let address = String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
            if !addresses.contains(address) { addresses.append(address) }
            current = item.pointee.ai_next
        }
        return addresses
    }

    private final class Tunnel: @unchecked Sendable {
        let id = UUID()
        private let client: NWConnection
        private let queue: DispatchQueue
        private let resolve: Resolver
        private let isAllowed: (String, UInt16) -> Bool
        private let onClose: (UUID) -> Void
        private var server: NWConnection?
        private var expectedEndpoint: NWEndpoint?
        private var header = Data()
        private var bufferedTLS = Data()
        private var timer: DispatchSourceTimer?
        private var opened = false
        private var closed = false
        private var clientEOF = false
        private var serverEOF = false

        init(
            client: NWConnection, queue: DispatchQueue, resolve: @escaping Resolver,
            isAllowed: @escaping (String, UInt16) -> Bool, onClose: @escaping (UUID) -> Void
        ) {
            self.client = client
            self.queue = queue
            self.resolve = resolve
            self.isAllowed = isAllowed
            self.onClose = onClose
        }

        func start() {
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.schedule(deadline: .now() + 20)
            timer.setEventHandler { [weak self] in self?.close() }
            self.timer = timer
            timer.resume()
            client.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .ready: self.readConnect()
                case .failed, .cancelled: self.close()
                default: break
                }
            }
            client.start(queue: queue)
        }

        private func readConnect() {
            guard !closed else { return }
            client.receive(minimumIncompleteLength: 1, maximumLength: max(1, 8192 - header.count)) {
                [weak self] data, _, complete, error in
                guard let self, !self.closed else { return }
                if error != nil { self.close(); return }
                if let data { self.header.append(data) }
                if let end = self.header.range(of: Data("\r\n\r\n".utf8)) {
                    self.bufferedTLS = Data(self.header[end.upperBound...])
                    let request = Data(self.header[..<end.lowerBound])
                    self.header.removeAll()
                    self.connect(request)
                } else if complete || self.header.count >= 8192 {
                    self.close()
                } else {
                    self.readConnect()
                }
            }
        }

        private func connect(_ request: Data) {
            guard let (host, port) = Self.connectAuthority(request),
                  isAllowed(host, port), WalletHTTP.isPublicHost(host) else {
                close(); return
            }
            DispatchQueue.global(qos: .utility).async { [weak self] in
                guard let self else { return }
                let result = Result { try WalletPublicProxy.publicAddress(from: self.resolve(host)) }
                self.queue.async {
                    guard !self.closed else { return }
                    switch result {
                    case .success(let address): self.connect(to: address, port: port)
                    case .failure: self.close()
                    }
                }
            }
        }

        private static func connectAuthority(_ request: Data) -> (String, UInt16)? {
            guard request.allSatisfy({ $0 < 128 }),
                  let text = String(data: request, encoding: .ascii),
                  let first = text.components(separatedBy: "\r\n").first else { return nil }
            let parts = first.split(separator: " ", omittingEmptySubsequences: false)
            guard parts.count == 3, parts[0] == "CONNECT", parts[2] == "HTTP/1.1" else { return nil }
            let authority = parts[1]
            // URLSession can send an IPv6 CONNECT target without URI brackets. Split off
            // the final decimal port only after validating the remaining host as IPv6.
            if !authority.hasPrefix("["), let separator = authority.lastIndex(of: ":"),
               authority[..<separator].contains(":") {
                let host = String(authority[..<separator])
                let portText = authority[authority.index(after: separator)...]
                var address = in6_addr()
                guard inet_pton(AF_INET6, host, &address) == 1,
                      !portText.isEmpty, portText.utf8.allSatisfy({ (0x30...0x39).contains($0) }),
                      let port = UInt16(portText), port > 0 else { return nil }
                return (host, port)
            }
            guard let components = URLComponents(string: "https://\(authority)/"),
                  let host = components.host, let port = components.port,
                  let number = UInt16(exactly: port), number > 0,
                  components.user == nil, components.password == nil,
                  components.percentEncodedPath == "/", components.query == nil,
                  components.fragment == nil else { return nil }
            // URLComponents includes brackets in IPv6 literal hosts, while URL.host (used
            // to register the allowed authority) does not. Compare and resolve the same
            // unbracketed numeric host without accepting bracketed DNS names.
            if host.hasPrefix("[") && host.hasSuffix("]") {
                let literal = String(host.dropFirst().dropLast())
                var address = in6_addr()
                guard inet_pton(AF_INET6, literal, &address) == 1 else { return nil }
                return (literal, number)
            }
            return (host, number)
        }

        private func connect(to address: String, port: UInt16) {
            guard !closed, let nwPort = NWEndpoint.Port(rawValue: port) else { close(); return }
            let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(address), port: nwPort)
            expectedEndpoint = endpoint
            let parameters = NWParameters.tcp
            parameters.allowFastOpen = false
            parameters.preferNoProxies = true
            let server = NWConnection(to: endpoint, using: parameters)
            self.server = server
            server.pathUpdateHandler = { [weak self] path in
                guard let self, self.opened else { return }
                if path.remoteEndpoint != self.expectedEndpoint { self.close() }
            }
            server.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .ready:
                    guard !self.opened, self.server?.currentPath?.remoteEndpoint == endpoint else {
                        self.close(); return
                    }
                    server.requestEstablishmentReport(queue: self.queue) { [weak self] report in
                        guard let self, !self.closed, report?.usedProxy == false,
                              self.server?.currentPath?.remoteEndpoint == endpoint else {
                            self?.close(); return
                        }
                        self.opened = true
                        self.client.send(content: Data("HTTP/1.1 200 Connection Established\r\n\r\n".utf8),
                                         completion: .contentProcessed { [weak self] error in
                            guard let self else { return }
                            if error != nil { self.close(); return }
                            if self.bufferedTLS.isEmpty {
                                self.pipe(from: self.client, to: server, fromClient: true)
                            } else {
                                server.send(content: self.bufferedTLS, completion: .contentProcessed { [weak self] error in
                                    guard let self else { return }
                                    self.bufferedTLS.removeAll()
                                    if error != nil { self.close() }
                                    else { self.pipe(from: self.client, to: server, fromClient: true) }
                                })
                            }
                            self.pipe(from: server, to: self.client, fromClient: false)
                        })
                    }
                case .waiting, .failed, .cancelled: self.close()
                default: break
                }
            }
            server.start(queue: queue)
        }

        /// One receive is followed by one completed send, keeping at most 16 KiB queued in
        /// either direction. EOF is forwarded as a half-close so a response can still arrive.
        private func pipe(from source: NWConnection, to destination: NWConnection, fromClient: Bool) {
            guard !closed else { return }
            source.receive(minimumIncompleteLength: 1, maximumLength: 16 * 1024) {
                [weak self] data, _, complete, error in
                guard let self, !self.closed else { return }
                if error != nil { self.close(); return }
                if let data, !data.isEmpty {
                    destination.send(content: data, completion: .contentProcessed { [weak self] sendError in
                        guard let self else { return }
                        if sendError != nil { self.close(); return }
                        if complete { self.finishDirection(destination, fromClient: fromClient) }
                        else { self.pipe(from: source, to: destination, fromClient: fromClient) }
                    })
                } else if complete {
                    self.finishDirection(destination, fromClient: fromClient)
                } else {
                    self.pipe(from: source, to: destination, fromClient: fromClient)
                }
            }
        }

        private func finishDirection(_ destination: NWConnection, fromClient: Bool) {
            destination.send(content: nil, contentContext: .finalMessage, isComplete: true,
                             completion: .contentProcessed { _ in })
            if fromClient { clientEOF = true } else { serverEOF = true }
            if clientEOF && serverEOF { close() }
        }

        func close() {
            guard !closed else { return }
            closed = true
            timer?.cancel()
            timer = nil
            server?.cancel()
            client.cancel()
            onClose(id)
        }
    }
}
