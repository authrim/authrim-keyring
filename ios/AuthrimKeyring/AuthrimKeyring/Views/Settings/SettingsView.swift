import SwiftUI
import UniformTypeIdentifiers

struct SettingsView: View {
    @Environment(AccountStore.self) private var store
    @Environment(AppLock.self) private var appLock
    @Environment(\.dismiss) private var dismiss

    @Environment(WallpaperStore.self) private var wallpaper
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

                Section("Appearance") {
                    NavigationLink {
                        WallpaperSettingsView()
                    } label: {
                        LabeledContent {
                            Text(wallpaperName)
                        } label: {
                            Label("Wallpaper", systemImage: "photo.on.rectangle")
                        }
                    }
                }

                Section {
                    Toggle(isOn: syncBinding) {
                        Label("iCloud Keychain Sync", systemImage: "icloud")
                    }
                } header: {
                    Text("Sync")
                } footer: {
                    Text("Shares your accounts, end-to-end encrypted, among your devices with sync on. Requires iCloud Keychain.")
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

                Section {
                    Button("Delete All Accounts", role: .destructive) {
                        isConfirmingDeleteAll = true
                    }
                    .disabled(store.accounts.isEmpty && !hasKeptICloudCopies)
                } header: {
                    Text("Data")
                } footer: {
                    if store.isSyncEnabled {
                        Text("Secret keys are stored in iCloud Keychain and are never sent to any other server. Also keep the backup codes each service provides.")
                    } else {
                        Text("Secret keys are stored only in this device’s Keychain and are never sent to a server. They do not move to a new device on their own, so turn on iCloud sync or keep an encrypted backup. Also keep the backup codes each service provides.")
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
                Button("Delete All Accounts", role: .destructive) {
                    Task { await store.deleteAll(confirmingWith: appLock) }
                }
                if hasKeptICloudCopies {
                    Button("Also Delete from iCloud", role: .destructive) {
                        Task { await store.deleteAll(includingICloud: true, confirmingWith: appLock) }
                    }
                }
            } message: {
                if hasKeptICloudCopies {
                    Text("Copies kept in iCloud Keychain are not deleted unless you also delete them from iCloud, which removes them from your other devices that use sync. You will no longer be able to generate codes for these services. Make sure you have another way to sign in. This cannot be undone.")
                } else if store.isSyncEnabled {
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
                    Task { await store.disableSyncRemovingICloudCopies(confirmingWith: appLock) }
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
                    Task { await store.enableSync(confirmingWith: appLock) }
                } else {
                    isConfirmingSyncOff = true
                }
            }
        )
    }

    private var hasStoreError: Binding<Bool> {
        Binding(get: { store.lastError != nil }, set: { if !$0 { store.lastError = nil } })
    }

    private var wallpaperName: LocalizedStringResource {
        switch wallpaper.settings.kind {
        case .system: "Default"
        case .preset(let id): WallpaperPreset.named(id)?.name ?? "Default"
        case .photo: "Photo"
        }
    }

    /// Copies left in iCloud Keychain when sync was turned off on this device.
    private var hasKeptICloudCopies: Bool {
        !store.isSyncEnabled && store.iCloudAccountCount > 0
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

extension AccountStore {
    /// Turns sync on after the device owner confirms, since it copies every
    /// secret to iCloud Keychain and the user's other devices.
    func enableSync(confirmingWith appLock: AppLock) async {
        guard await appLock.confirmDeviceOwner(reason: String(localized: "Turn on iCloud Keychain sync.")) else {
            return
        }
        setSyncEnabled(true)
    }

    /// Deletes every account after the device owner confirms. It cannot be undone,
    /// and with sync it also reaches the user's other devices.
    func deleteAll(includingICloud: Bool = false, confirmingWith appLock: AppLock) async {
        guard await appLock.confirmDeviceOwner(reason: String(localized: "Delete all accounts.")) else {
            return
        }
        deleteAll(includingICloud: includingICloud)
    }

    /// Turns sync off and deletes the iCloud copies after the device owner confirms,
    /// since that also removes them from the user's other devices.
    func disableSyncRemovingICloudCopies(confirmingWith appLock: AppLock) async {
        guard await appLock.confirmDeviceOwner(reason: String(localized: "Remove your accounts from iCloud Keychain.")) else {
            return
        }
        setSyncEnabled(false, removeFromICloud: true)
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
