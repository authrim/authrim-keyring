extension AccountStore {
    /// What AutoFill should know about right now.
    var autoFillIdentities: CredentialIdentitySync.Identities {
        CredentialIdentitySync.identities(accounts: accounts, details: details, passkeys: passkeys)
    }
}
