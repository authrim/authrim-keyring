import SwiftUI

/// Decrypts a backup file chosen in the Files picker and adds its new accounts.
struct ImportBackupView: View {
    let fileURL: URL

    @Environment(AccountStore.self) private var store
    @Environment(\.dismiss) private var dismiss

    @State private var file: Data?
    @State private var password = ""
    @State private var isWorking = false
    @State private var found: [OTPAccount]?
    @State private var passwordError: String?
    @State private var loadError: String?
    @State private var addedCount: Int?

    var body: some View {
        NavigationStack {
            Form {
                if let found {
                    summary(of: found)
                } else {
                    Section {
                        SecureField("Backup Password", text: $password)
                            .onSubmit { Task { await decrypt() } }
                            .onChange(of: password) { passwordError = nil }
                    } footer: {
                        if let passwordError {
                            Text(passwordError)
                                .foregroundStyle(.red)
                        } else {
                            Text("Enter the password that was set when the backup was exported.")
                        }
                    }
                }
            }
            .disabled(isWorking)
            .navigationTitle("Import")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    if isWorking {
                        ProgressView()
                    } else if found == nil {
                        Button("Unlock") { Task { await decrypt() } }
                            .disabled(password.isEmpty || file == nil)
                    }
                }
            }
            .alert("Cannot Import Backup", isPresented: hasLoadError) {
                Button("OK") { dismiss() }
            } message: {
                Text(loadError ?? "")
            }
            .alert("Import Complete", isPresented: hasAdded) {
                Button("OK") { dismiss() }
            } message: {
                Text("Accounts added: \(addedCount ?? 0)")
            }
            .task { await readFile() }
        }
        .interactiveDismissDisabled(isWorking)
    }

    @ViewBuilder
    private func summary(of accounts: [OTPAccount]) -> some View {
        let newCount = accounts.count(where: { !store.containsDuplicate(of: $0) })
        Section {
            LabeledContent("Accounts in Backup", value: accounts.count, format: .number)
            LabeledContent("New", value: newCount, format: .number)
            LabeledContent("Already Added", value: accounts.count - newCount, format: .number)
        } footer: {
            Text("Accounts that are already in Keyring are skipped.")
        }
        Section {
            ForEach(accounts) { account in
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(account.displayTitle)
                        if let subtitle = account.displaySubtitle {
                            Text(subtitle)
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                    }
                    Spacer()
                    if store.containsDuplicate(of: account) {
                        Text("Already Added")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
        Section {
            Button("Add Accounts") {
                let result = store.importAccounts(accounts)
                if let error = result.error {
                    loadError = String(localized: "Accounts added: \(result.added)") + "\n" + error
                } else {
                    addedCount = result.added
                }
            }
            .disabled(newCount == 0)
        }
    }

    private var hasLoadError: Binding<Bool> {
        Binding(get: { loadError != nil }, set: { if !$0 { loadError = nil } })
    }

    private var hasAdded: Binding<Bool> {
        Binding(get: { addedCount != nil }, set: { if !$0 { addedCount = nil } })
    }

    private func readFile() async {
        guard file == nil else { return }
        let url = fileURL
        do {
            file = try await Task.detached(priority: .userInitiated) {
                try Self.contents(of: url)
            }.value
        } catch {
            loadError = error.localizedDescription
        }
    }

    private func decrypt() async {
        guard let file, !password.isEmpty, !isWorking else { return }
        isWorking = true
        defer { isWorking = false }
        let password = password
        do {
            found = try await Task.detached(priority: .userInitiated) {
                try EncryptedBackup.open(file, password: password)
            }.value
            self.password = ""
        } catch EncryptedBackup.BackupError.wrongPassword {
            passwordError = EncryptedBackup.BackupError.wrongPassword.localizedDescription
        } catch {
            loadError = error.localizedDescription
        }
    }

    /// Reads a file from the Files picker, downloading it from iCloud Drive if needed.
    nonisolated private static func contents(of url: URL) throws -> Data {
        let isAccessing = url.startAccessingSecurityScopedResource()
        defer { if isAccessing { url.stopAccessingSecurityScopedResource() } }

        var coordinationError: NSError?
        var result: Result<Data, Error> = .failure(CocoaError(.fileReadUnknown))
        NSFileCoordinator().coordinate(readingItemAt: url, options: [], error: &coordinationError) { readURL in
            result = Result {
                // Reads one byte past the limit instead of trusting the reported file size.
                let handle = try FileHandle(forReadingFrom: readURL)
                defer { try? handle.close() }
                let data = try handle.read(upToCount: EncryptedBackup.maximumFileSize + 1) ?? Data()
                guard data.count <= EncryptedBackup.maximumFileSize else {
                    throw EncryptedBackup.BackupError.tooLarge
                }
                return data
            }
        }
        if let coordinationError { throw coordinationError }
        return try result.get()
    }
}
