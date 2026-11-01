import SwiftUI
import UniformTypeIdentifiers

struct SettingsView: View {
    @Environment(AccountStore.self) private var store
    @Environment(AppLock.self) private var appLock
    @Environment(\.dismiss) private var dismiss

    @AppStorage("hasSeenTutorial") private var hasSeenTutorial = false
    @State private var isConfirmingDeleteAll = false
    @State private var isConfirmingSyncOff = false
    @State private var isExporting = false
    @State private var isPickingBackup = false
    @State private var pickedBackup: PickedFile?
    @State private var pickerError: String?

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
                    Toggle(isOn: syncBinding) {
                        Label("iCloud Keychain Sync", systemImage: "icloud")
                    }
                } header: {
                    Text("Sync")
                } footer: {
                    Text("When on, secret keys are kept in iCloud Keychain, which is end-to-end encrypted, and appear on your other devices where Keyring sync is on. iCloud Keychain must be turned on in the Settings app. Card order is not synced.")
                }

                Section {
                    Button("Export Encrypted Backup", systemImage: "square.and.arrow.up") {
                        isExporting = true
                    }
                    .disabled(store.accounts.isEmpty)
                    Button("Import Backup", systemImage: "square.and.arrow.down") {
                        isPickingBackup = true
                    }
                } header: {
                    Text("Backup")
                } footer: {
                    Text("A backup file is protected by a password you choose and can be restored on any device, even without iCloud.")
                }

                Section {
                    Button("Delete All Accounts", role: .destructive) {
                        isConfirmingDeleteAll = true
                    }
                    .disabled(store.accounts.isEmpty)
                } header: {
                    Text("Data")
                } footer: {
                    if store.isSyncEnabled {
                        Text("Secret keys are stored in iCloud Keychain and are never sent to any other server. Also keep the backup codes each service provides.")
                    } else {
                        Text("Secret keys are stored only in this device’s Keychain and are never sent to a server. They do not move to a new device on their own, so turn on iCloud sync or keep an encrypted backup. Also keep the backup codes each service provides.")
                    }
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
                    Button("Show Tutorial", systemImage: "questionmark.bubble") {
                        // The home screen starts it once this sheet is gone.
                        hasSeenTutorial = false
                        dismiss()
                    }
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
                if store.isSyncEnabled {
                    Text("They are also removed from iCloud Keychain and from your other devices that use sync. You will no longer be able to generate codes for these services. Make sure you have another way to sign in. This cannot be undone.")
                } else {
                    Text("You will no longer be able to generate codes for these services. Make sure you have another way to sign in. This cannot be undone.")
                }
            }
            .confirmationDialog(
                "Turn off iCloud sync?",
                isPresented: $isConfirmingSyncOff,
                titleVisibility: .visible
            ) {
                Button("Keep Copies in iCloud") {
                    store.setSyncEnabled(false)
                }
                Button("Remove from iCloud", role: .destructive) {
                    store.setSyncEnabled(false, removeFromICloud: true)
                }
            } message: {
                Text("Your accounts stay on this device. Removing them from iCloud also removes them from your other devices that use sync.")
            }
            .sheet(isPresented: $isExporting) { ExportBackupView() }
            .sheet(item: $pickedBackup) { ImportBackupView(fileURL: $0.url) }
            .fileImporter(isPresented: $isPickingBackup, allowedContentTypes: [.json]) { result in
                switch result {
                case .success(let url):
                    pickedBackup = PickedFile(url: url)
                case .failure(let error):
                    if (error as? CocoaError)?.code != .userCancelled {
                        pickerError = error.localizedDescription
                    }
                }
            }
            // The home screen's alert cannot appear while this sheet is up.
            .alert("Something went wrong", isPresented: hasStoreError) {
                Button("OK") { store.lastError = nil }
            } message: {
                Text(store.lastError ?? "")
            }
            .alert("Cannot Import Backup", isPresented: hasPickerError) {
                Button("OK") { pickerError = nil }
            } message: {
                Text(pickerError ?? "")
            }
        }
    }

    private var syncBinding: Binding<Bool> {
        Binding(
            get: { store.isSyncEnabled },
            set: { newValue in
                if newValue {
                    store.setSyncEnabled(true)
                } else {
                    isConfirmingSyncOff = true
                }
            }
        )
    }

    private var hasStoreError: Binding<Bool> {
        Binding(get: { store.lastError != nil }, set: { if !$0 { store.lastError = nil } })
    }

    private var hasPickerError: Binding<Bool> {
        Binding(get: { pickerError != nil }, set: { if !$0 { pickerError = nil } })
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

private struct PickedFile: Identifiable {
    let id = UUID()
    let url: URL
}

enum AppLinks {
    static let privacyPolicy = URL(string: "https://authrim.com/keyring/privacy")!
    static let support = URL(string: "https://authrim.com/keyring/support")!
}
