import SwiftUI
import UniformTypeIdentifiers

/// Encrypts every account with a password and hands the file to the system exporter.
struct ExportBackupView: View {
    @Environment(AccountStore.self) private var store
    @Environment(AppLock.self) private var appLock
    @Environment(\.dismiss) private var dismiss

    @State private var password = ""
    @State private var confirmation = ""
    @State private var isWorking = false
    @State private var document: BackupDocument?
    @State private var errorMessage: String?

    private var isPasswordLongEnough: Bool {
        password.count >= EncryptedBackup.minimumPasswordLength
    }

    private var canExport: Bool {
        isPasswordLongEnough && password == confirmation && !isWorking && !store.accounts.isEmpty
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("The backup file contains the secret keys and recovery codes of all your accounts, encrypted with the password you set here. Keep the file and the password in separate places.")
                }

                Section {
                    SecureField("Password", text: $password)
                    SecureField("Confirm Password", text: $confirmation)
                } footer: {
                    if !confirmation.isEmpty, password != confirmation {
                        Text("The passwords do not match.")
                            .foregroundStyle(.red)
                    } else {
                        Text("Use at least \(EncryptedBackup.minimumPasswordLength) characters. The password cannot be recovered, and the backup cannot be restored without it.")
                    }
                }
            }
            .disabled(isWorking)
            .navigationTitle("Export Backup")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    if isWorking {
                        ProgressView()
                    } else {
                        Button("Export") { Task { await export() } }
                            .disabled(!canExport)
                    }
                }
            }
            .fileExporter(
                isPresented: isExporting,
                document: document,
                contentType: .json,
                defaultFilename: Self.defaultFilename
            ) { result in
                document = nil
                switch result {
                case .success:
                    dismiss()
                case .failure(let error):
                    if (error as? CocoaError)?.code != .userCancelled {
                        errorMessage = error.localizedDescription
                    }
                }
            }
            .alert("Cannot Export Backup", isPresented: hasError) {
                Button("OK") { errorMessage = nil }
            } message: {
                Text(errorMessage ?? "")
            }
        }
        .interactiveDismissDisabled(isWorking)
    }

    private var isExporting: Binding<Bool> {
        Binding(get: { document != nil }, set: { if !$0 { document = nil } })
    }

    private var hasError: Binding<Bool> {
        Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })
    }

    private static var defaultFilename: String {
        // The local date, so a backup made in the morning is not named after yesterday.
        let date = Date.now.formatted(Date.ISO8601FormatStyle(timeZone: .current).year().month().day())
        return "Keyring-Backup-\(date)"
    }

    private func export() async {
        isWorking = true
        defer { isWorking = false }
        // The file holds every secret, so an unattended unlocked phone must not be enough.
        guard await appLock.confirmDeviceOwner(reason: String(localized: "Export a backup of your accounts.")) else {
            return
        }
        // Without the details the file would silently lack the recovery codes.
        guard !store.areDetailsUnavailable else {
            errorMessage = AccountStore.StoreError.detailsUnavailable.localizedDescription
            return
        }
        let contents = EncryptedBackup.Contents(accounts: store.accounts, details: Array(store.details.values))
        let password = password
        do {
            let data = try await Task.detached(priority: .userInitiated) {
                try EncryptedBackup.seal(contents, password: password)
            }.value
            document = BackupDocument(data: data)
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
