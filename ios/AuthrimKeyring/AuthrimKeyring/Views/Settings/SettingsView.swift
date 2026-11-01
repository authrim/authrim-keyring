import SwiftUI

struct SettingsView: View {
    @Environment(AccountStore.self) private var store
    @Environment(AppLock.self) private var appLock
    @Environment(\.dismiss) private var dismiss

    @State private var isConfirmingDeleteAll = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Toggle(isOn: lockBinding) {
                        Label("Require \(appLock.biometryName)", systemImage: "lock")
                    }
                    .disabled(!appLock.canUseDeviceAuthentication || appLock.isAuthenticating)
                } header: {
                    Text("Security")
                } footer: {
                    if appLock.canUseDeviceAuthentication {
                        Text("Ask for \(appLock.biometryName) or your passcode each time the app is opened.")
                    } else {
                        Text("Set a device passcode to use the app lock.")
                    }
                }

                Section {
                    Button("Delete All Accounts", role: .destructive) {
                        isConfirmingDeleteAll = true
                    }
                    .disabled(store.accounts.isEmpty)
                } header: {
                    Text("Data")
                } footer: {
                    Text("Secret keys are stored only in this device’s Keychain. They are never sent to a server or synced with iCloud, and they do not move to a new device. If you change or lose this device, you will need to set up two-factor authentication again for each service, so keep the backup codes each service provides.")
                }

                Section("Supported Codes") {
                    LabeledContent("Type", value: "TOTP (RFC 6238)")
                    LabeledContent("Algorithm", value: "SHA1, SHA256, SHA512")
                    LabeledContent("Digits", value: "6, 7, 8")
                    LabeledContent("Period") {
                        Text("30, 60 seconds")
                    }
                }

                Section("About") {
                    LabeledContent("Version", value: Self.appVersion)
                    Link(destination: AppLinks.privacyPolicy) {
                        Label("Privacy Policy", systemImage: "hand.raised")
                    }
                    Link(destination: AppLinks.support) {
                        Label("Support", systemImage: "questionmark.circle")
                    }
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .confirmationDialog(
                "Delete all accounts?",
                isPresented: $isConfirmingDeleteAll,
                titleVisibility: .visible
            ) {
                Button("Delete All Accounts", role: .destructive) { store.deleteAll() }
            } message: {
                Text("You will no longer be able to generate codes for these services. Make sure you have another way to sign in. This cannot be undone.")
            }
        }
    }

    private var lockBinding: Binding<Bool> {
        Binding(
            get: { appLock.isEnabled },
            set: { newValue in Task { await appLock.setEnabled(newValue) } }
        )
    }

    private static var appVersion: String {
        let info = Bundle.main.infoDictionary
        let version = info?["CFBundleShortVersionString"] as? String ?? "-"
        let build = info?["CFBundleVersion"] as? String ?? "-"
        return "\(version) (\(build))"
    }
}

enum AppLinks {
    static let privacyPolicy = URL(string: "https://authrim.com/keyring/privacy")!
    static let support = URL(string: "https://authrim.com/keyring/support")!
}
