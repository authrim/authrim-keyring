import AuthenticationServices
import SwiftUI

/// Entry point the system loads for AutoFill of one-time codes and passkeys.
final class CredentialProviderViewController: ASCredentialProviderViewController {
    lazy var store = AccountStore()
    private var appLock = AppLock()
    /// Set once the request is completed or cancelled; the system takes only one answer.
    private var isFinished = false
    /// Work started for the current request, cancelled when the next one begins so
    /// a late result from an earlier request cannot answer this one.
    private var tasks: [Task<Void, Never>] = []
    /// Set when the device owner was confirmed earlier in the current request.
    var isUserVerified = false

    /// Starts answering a new request; the system may reuse this controller.
    func resetFinished() {
        isFinished = false
        isUserVerified = false
        // A reused controller must not carry an unlock, the lock setting as it was,
        // or work waiting for a sheet over to the next request.
        appLock = AppLock()
        onAppear = []
        tasks.forEach { $0.cancel() }
        tasks = []
    }

    /// Starts work for the current request.
    func startTask(_ work: @escaping () async -> Void) {
        tasks.append(Task { await work() })
    }

    /// Claims the one answer to the current request. False if it has already ended,
    /// for example cancelled while Face ID or a save was still in progress.
    func beginFinishing() -> Bool {
        // Work of an earlier request is cancelled and may not answer this one.
        guard !isFinished, !Task.isCancelled else { return false }
        isFinished = true
        return true
    }

    /// Work that asks for Face ID, which only succeeds once the sheet is on screen.
    private var onAppear: [() -> Void] = []
    private var hasAppeared = false

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        hasAppeared = false
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        hasAppeared = true
        let work = onAppear
        onAppear = []
        work.forEach { $0() }
    }

    /// Runs `work` once the interface is visible.
    func whenVisible(_ work: @escaping () async -> Void) {
        let start = { self.startTask(work) }
        if hasAppeared {
            _ = start()
        } else {
            onAppear.append { _ = start() }
        }
    }

    // MARK: One-time codes

    /// The user chose Keyring from the list of code providers.
    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        resetFinished()
        let host = serviceIdentifiers.lazy.compactMap(Self.host).first
        whenVisible { [self] in
            guard await unlockIfNeeded() else { return cancel(.userCanceled) }
            store.load()
            show(OneTimeCodePickerView(
                accounts: store.accounts,
                details: store.details,
                host: host,
                onPick: { [weak self] account, rememberSite in
                    self?.pick(account, rememberingSite: rememberSite ? host : nil)
                },
                onCancel: { [weak self] in self?.cancel(.userCanceled) }
            ))
        }
    }

    /// A suggestion above the keyboard was tapped.
    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        resetFinished()
        // A passkey always asks for Face ID or the passcode, which needs the interface.
        if credentialRequest is ASPasskeyCredentialRequest {
            return cancel(.userInteractionRequired)
        }
        guard #available(iOS 18, *), credentialRequest is ASOneTimeCodeCredentialRequest else {
            return cancel(.failed)
        }
        // With the app lock on, a code needs Face ID, which only the interface can ask for.
        guard !isLockRequired else { return cancel(.userInteractionRequired) }
        completeOneTimeCode(for: credentialRequest)
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        resetFinished()
        if let request = credentialRequest as? ASPasskeyCredentialRequest {
            return preparePasskeyAssertion(request)
        }
        whenVisible { [self] in
            guard await unlockIfNeeded() else { return cancel(.userCanceled) }
            completeOneTimeCode(for: credentialRequest)
        }
    }

    private func completeOneTimeCode(for request: any ASCredentialRequest) {
        guard #available(iOS 18, *),
              let identity = request.credentialIdentity as? ASOneTimeCodeCredentialIdentity,
              let id = identity.recordIdentifier.flatMap(UUID.init(uuidString:))
        else { return cancel(.failed) }
        store.load()
        // The card, or this site on it, may have been removed since the suggestion
        // was registered; an outdated suggestion must not fill in a code. Nor may one
        // that an older version registered for a shared suffix such as `pages.dev`.
        let site = Self.host(of: identity.serviceIdentifier)
        guard let account = store.accounts.first(where: { $0.id == id }),
              let site, Website.canSuggestAboveKeyboard(site),
              store.details(for: id).websites.contains(where: { Website.matches(host: site, site: $0) })
        else { return cancel(.credentialIdentityNotFound) }
        finish(with: account)
    }

    private func pick(_ account: OTPAccount, rememberingSite host: String?) {
        if let host, let site = Website.normalized(host) {
            // Read again just before writing, so codes changed in the app meanwhile are kept.
            store.load()
            var details = store.details(for: account.id)
            if !details.websites.contains(site), details.websites.count < Website.maximumPerAccount {
                details.websites.append(site)
                store.setDetails(details)
            }
        }
        finish(with: account)
    }

    private func finish(with account: OTPAccount) {
        guard #available(iOS 18, *) else { return cancel(.failed) }
        startTask { [self] in
            // Before completing: the extension may be stopped right after. This keeps
            // suggestions current with a site added here or a card changed in the app.
            if let identities = store.autoFillIdentities {
                await CredentialIdentitySync.replace(with: identities)
            }
            guard beginFinishing() else { return }
            // Only now, as a counter-based code is used up by making it.
            guard let code = TOTPGenerator.code(for: account)?.value ?? store.nextCode(for: account.id) else {
                let error = NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.Code.failed.rawValue)
                return extensionContext.cancelRequest(withError: error)
            }
            _ = await extensionContext.completeOneTimeCodeRequest(using: ASOneTimeCodeCredential(code: code))
        }
    }

    // MARK: Shared

    /// Whether codes need Face ID or the passcode first. Also before the app has
    /// run since updating from 1.0, when the lock setting has not reached the App Group.
    var isLockRequired: Bool {
        appLock.isLocked || !SharedDefaults.hasMigrated
    }

    func unlockIfNeeded() async -> Bool {
        // The lock of this request, even if another request replaces it meanwhile.
        let lock = appLock
        if lock.isLocked {
            await lock.unlock()
            return !lock.isLocked
        }
        if !SharedDefaults.hasMigrated {
            return await lock.confirmDeviceOwner(reason: String(localized: "Unlock Authrim Keyring to view your codes."))
        }
        return true
    }

    func cancel(_ code: ASExtensionError.Code) {
        guard beginFinishing() else { return }
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: code.rawValue))
    }

    func show(_ view: some View) {
        // A screen for an earlier request must not replace the current one.
        guard !Task.isCancelled else { return }
        children.forEach {
            $0.willMove(toParent: nil)
            $0.view.removeFromSuperview()
            $0.removeFromParent()
        }
        let host = UIHostingController(rootView: view)
        addChild(host)
        host.view.frame = self.view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        self.view.addSubview(host.view)
        host.didMove(toParent: self)
    }

    /// The domain of a page or app asking for a credential.
    nonisolated static func host(of identifier: ASCredentialServiceIdentifier) -> String? {
        switch identifier.type {
        case .domain:
            identifier.identifier.lowercased()
        case .URL:
            URLComponents(string: identifier.identifier)?.host?.lowercased()
        default:
            nil
        }
    }
}
