import AuthenticationServices
import LocalAuthentication

/// Creating passkeys and signing in with them, for the AutoFill extension.
extension CredentialProviderViewController {
    // MARK: Registration

    override func prepareInterface(forPasskeyRegistration registrationRequest: any ASCredentialRequest) {
        resetFinished()
        guard let request = registrationRequest as? ASPasskeyCredentialRequest,
              let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity
        else { return cancel(.failed) }
        guard request.supportedAlgorithms.contains(.ES256) else { return cancel(.failed) }
        store.load()
        // Unreadable passkeys must not pass for none, or an excluded one could be created twice.
        guard !store.arePasskeysUnavailable else { return cancel(.failed) }
        let relyingParty = identity.relyingPartyIdentifier
        if #available(iOS 18, *), let excluded = request.excludedCredentials, !excluded.isEmpty {
            let excludedIDs = Set(excluded.map(\.credentialID))
            if store.passkeys.contains(where: { $0.relyingParty == relyingParty && excludedIDs.contains($0.credentialID) }) {
                return cancel(.matchedExcludedCredential)
            }
        }
        show(PasskeyRegistrationView(
            relyingParty: relyingParty,
            userName: identity.userName,
            isDeviceOnlyByRule: PasskeySyncRules.isDeviceOnly(relyingParty),
            isSyncEnabled: store.isSyncEnabled,
            onCreate: { [weak self] deviceOnly, remember in
                self?.startTask { [weak self] in
                    await self?.register(request, identity: identity, deviceOnly: deviceOnly, rememberRule: remember)
                }
            },
            onCancel: { [weak self] in self?.cancel(.userCanceled) }
        ))
    }

    private func register(
        _ request: ASPasskeyCredentialRequest,
        identity: ASPasskeyCredentialIdentity,
        deviceOnly: Bool,
        rememberRule: Bool
    ) async {
        guard let verified = await verifyUser(
            reason: String(localized: "Create a passkey for \(identity.relyingPartyIdentifier)."),
            preference: request.userVerificationPreference
        ) else { return cancel(.userCanceled) }
        if rememberRule {
            PasskeySyncRules.setDeviceOnly(deviceOnly, for: identity.relyingPartyIdentifier)
        }
        do {
            let (passkey, publicKey) = try Passkey.make(
                relyingParty: identity.relyingPartyIdentifier,
                userName: identity.userName,
                userHandle: identity.userHandle,
                deviceOnly: deviceOnly
            )
            let authenticatorData = WebAuthn.authenticatorData(
                relyingParty: passkey.relyingParty,
                flags: WebAuthn.flags(isUserVerified: verified, attested: true),
                credential: (passkey.credentialID, publicKey)
            )
            try store.addPasskey(passkey)
            let credential = ASPasskeyRegistrationCredential(
                relyingParty: passkey.relyingParty,
                clientDataHash: request.clientDataHash,
                credentialID: passkey.credentialID,
                attestationObject: WebAuthn.attestationObject(authenticatorData: authenticatorData)
            )
            // Before completing, since the extension may be stopped right after.
            if let identities = store.autoFillIdentities {
                await CredentialIdentitySync.replace(with: identities)
            }
            guard beginFinishing() else {
                // Cancelled meanwhile: the site never learns of this passkey.
                store.deletePasskey(passkey.id)
                if let identities = store.autoFillIdentities {
                    await CredentialIdentitySync.replace(with: identities)
                }
                return
            }
            _ = await extensionContext.completeRegistrationRequest(using: credential)
        } catch {
            cancel(.failed)
        }
    }

    // MARK: Sign-in

    /// The user chose Keyring for a site's passkey sign-in.
    override func prepareCredentialList(
        for serviceIdentifiers: [ASCredentialServiceIdentifier],
        requestParameters: ASPasskeyCredentialRequestParameters
    ) {
        resetFinished()
        store.load()
        let allowed = Set(requestParameters.allowedCredentials)
        let candidates = store.passkeys.filter {
            $0.relyingParty == requestParameters.relyingPartyIdentifier
                && (allowed.isEmpty || allowed.contains($0.credentialID))
        }
        // The list shows account names, so the app lock comes first. Face ID passed
        // here also verifies the user for the sign-in, so it is not asked twice.
        whenVisible { [self] in
            if isLockRequired {
                guard await unlockIfNeeded() else { return cancel(.userCanceled) }
                isUserVerified = LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
            }
            showPasskeyList(candidates, requestParameters: requestParameters)
        }
    }

    private func showPasskeyList(_ candidates: [Passkey], requestParameters: ASPasskeyCredentialRequestParameters) {
        show(PasskeyPickerView(
            relyingParty: requestParameters.relyingPartyIdentifier,
            passkeys: candidates,
            onPick: { [weak self] passkey in
                self?.startTask { [weak self] in
                    await self?.assert(
                        with: passkey,
                        clientDataHash: requestParameters.clientDataHash,
                        preference: requestParameters.userVerificationPreference
                    )
                }
            },
            onCancel: { [weak self] in self?.cancel(.userCanceled) }
        ))
    }

    /// A passkey suggested above the keyboard was chosen.
    func preparePasskeyAssertion(_ request: ASPasskeyCredentialRequest) {
        guard let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity else { return cancel(.failed) }
        store.load()
        guard let passkey = store.passkeys.first(where: {
            $0.credentialID == identity.credentialID && $0.relyingParty == identity.relyingPartyIdentifier
        }) else { return cancel(.credentialIdentityNotFound) }
        // Face ID only works once the sheet is on screen.
        whenVisible { [self] in
            await assert(with: passkey, clientDataHash: request.clientDataHash, preference: request.userVerificationPreference)
        }
    }

    private func assert(
        with passkey: Passkey,
        clientDataHash: Data,
        preference: ASAuthorizationPublicKeyCredentialUserVerificationPreference
    ) async {
        let verified: Bool
        if isUserVerified {
            verified = true
        } else {
            guard let result = await verifyUser(
                reason: String(localized: "Sign in to \(passkey.relyingParty)."),
                preference: preference
            ) else { return cancel(.userCanceled) }
            verified = result
        }
        do {
            let authenticatorData = WebAuthn.authenticatorData(
                relyingParty: passkey.relyingParty,
                flags: WebAuthn.flags(isUserVerified: verified, attested: false)
            )
            let signature = try passkey.sign(authenticatorData + clientDataHash)
            guard beginFinishing() else { return }
            store.recordUse(of: passkey.id)
            let credential = ASPasskeyAssertionCredential(
                userHandle: passkey.userHandle,
                relyingParty: passkey.relyingParty,
                signature: signature,
                clientDataHash: clientDataHash,
                authenticatorData: authenticatorData,
                credentialID: passkey.credentialID
            )
            _ = await extensionContext.completeAssertionRequest(using: credential)
        } catch {
            cancel(.failed)
        }
    }

    // MARK: User verification

    /// Asks for Face ID, Touch ID or the passcode. Returns whether the user was
    /// verified, or nil when the request cannot go ahead: the user cancelled, or the
    /// site requires verification on a device without a passcode.
    private func verifyUser(
        reason: String,
        preference: ASAuthorizationPublicKeyCredentialUserVerificationPreference
    ) async -> Bool? {
        let context = LAContext()
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil) else {
            return preference == .required ? nil : false
        }
        do {
            return try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) ? true : nil
        } catch {
            return nil
        }
    }
}
