extension AccountStore {
    /// What AutoFill should know about right now, or nil while something could not
    /// be read: registering then would remove suggestions that are still valid.
    var autoFillIdentities: CredentialIdentitySync.Identities? {
        guard !isContentUnavailable, !areDetailsUnavailable else { return nil }
        return CredentialIdentitySync.identities(accounts: accounts, details: details, passkeys: passkeys)
    }
}
