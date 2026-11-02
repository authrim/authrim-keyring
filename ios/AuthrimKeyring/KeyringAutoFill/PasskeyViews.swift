import SwiftUI

/// Confirms a new passkey and where it is kept.
struct PasskeyRegistrationView: View {
    let relyingParty: String
    let userName: String
    let isDeviceOnlyByRule: Bool
    let isSyncEnabled: Bool
    let onCreate: (_ deviceOnly: Bool, _ rememberForSite: Bool) -> Void
    let onCancel: () -> Void

    @State private var deviceOnly: Bool
    @State private var rememberForSite = false
    @State private var isCreating = false

    init(
        relyingParty: String,
        userName: String,
        isDeviceOnlyByRule: Bool,
        isSyncEnabled: Bool,
        onCreate: @escaping (Bool, Bool) -> Void,
        onCancel: @escaping () -> Void
    ) {
        self.relyingParty = relyingParty
        self.userName = userName
        self.isDeviceOnlyByRule = isDeviceOnlyByRule
        self.isSyncEnabled = isSyncEnabled
        self.onCreate = onCreate
        self.onCancel = onCancel
        _deviceOnly = State(initialValue: isDeviceOnlyByRule)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    LabeledContent("Website", value: relyingParty)
                    LabeledContent("Account", value: userName)
                }
                Section {
                    Toggle("Keep on This iPhone Only", isOn: $deviceOnly)
                    if deviceOnly != isDeviceOnlyByRule {
                        Toggle("Always for This Website", isOn: $rememberForSite)
                    }
                } footer: {
                    Text(footer)
                }
            }
            .navigationTitle("Save Passkey")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: onCancel)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        isCreating = true
                        onCreate(deviceOnly, rememberForSite)
                    }
                    .disabled(isCreating)
                }
            }
        }
    }

    private var footer: String {
        if deviceOnly {
            String(localized: "Keyring keeps the passkey on this iPhone only. It is not synced or included in backups, and cannot be moved later. If you lose this iPhone, sign in another way.")
        } else if isSyncEnabled {
            String(localized: "The passkey is synced to your other devices through iCloud Keychain, end-to-end encrypted.")
        } else {
            String(localized: "The passkey is kept on this iPhone for now and moves to iCloud Keychain if you turn on iCloud sync.")
        }
    }
}

/// Chooses which saved passkey to sign in with.
struct PasskeyPickerView: View {
    let relyingParty: String
    let passkeys: [Passkey]
    let onPick: (Passkey) -> Void
    let onCancel: () -> Void

    /// Only the first choice counts; a second tap would start another sign-in.
    @State private var hasPicked = false

    var body: some View {
        NavigationStack {
            List(passkeys) { passkey in
                Button {
                    guard !hasPicked else { return }
                    hasPicked = true
                    onPick(passkey)
                } label: {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(passkey.userName.isEmpty ? passkey.displayTitle : passkey.userName)
                            .foregroundStyle(.primary)
                        Text(passkey.isBackupEligible ? String(localized: "Synced passkey") : String(localized: "On this iPhone only"))
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    // The whole row, not just the text, can be tapped.
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .contentShape(.rect)
                }
                .buttonStyle(.plain)
            }
            .overlay {
                if passkeys.isEmpty {
                    ContentUnavailableView(
                        "No Passkeys",
                        systemImage: "person.badge.key",
                        description: Text("Keyring has no passkey for \(relyingParty).")
                    )
                }
            }
            .navigationTitle(relyingParty)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: onCancel)
                }
            }
        }
    }
}
