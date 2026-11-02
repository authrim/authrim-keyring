import SwiftUI

/// Lists accounts and passkeys read from another app before they are added.
struct ImportPreviewView: View {
    @Environment(AccountStore.self) private var store

    let imported: ImportedAccounts
    let onFinish: () -> Void

    @State private var excluded: Set<Int> = []
    @State private var excludedPasskeys: Set<Int> = []
    @State private var resultMessage: String?
    @State private var isShowingResult = false

    private var newIndices: [Int] {
        imported.accounts.indices.filter { !store.containsDuplicate(of: imported.accounts[$0]) }
    }

    private var selected: [OTPAccount] {
        newIndices.filter { !excluded.contains($0) }.map { imported.accounts[$0] }
    }

    private var selectedPasskeys: [Passkey] {
        imported.passkeys.indices
            .filter { !excludedPasskeys.contains($0) && !store.containsPasskey(like: imported.passkeys[$0]) }
            .map { imported.passkeys[$0] }
    }

    var body: some View {
        Form {
            if !imported.accounts.isEmpty {
                Section {
                    ForEach(imported.accounts.indices, id: \.self) { index in
                        row(index)
                    }
                } header: {
                    Text("Accounts")
                } footer: {
                    if newIndices.count < imported.accounts.count {
                        Text("Accounts that are already in Keyring are not added again.")
                    }
                }
            }
            if !imported.passkeys.isEmpty {
                Section("Passkeys") {
                    ForEach(imported.passkeys.indices, id: \.self) { index in
                        passkeyRow(index)
                    }
                }
            }
            if imported.otherCount > 0 {
                Section {
                    Label("Other items: \(imported.otherCount)", systemImage: "tray")
                } footer: {
                    Text("Keyring keeps only one-time codes and passkeys. Passwords and other items stay in the other app.")
                }
            }

            if !imported.skipped.isEmpty {
                Section {
                    ForEach(imported.skipped, id: \.self) { item in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(item.name.isEmpty ? String(localized: "Unnamed") : item.name)
                            Text(item.reason)
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                    }
                } header: {
                    Text("Cannot Be Added")
                } footer: {
                    Text("Keep these in the other app, or set them up again with the service.")
                }
            }
        }
        .navigationTitle("Import Accounts")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button(String(localized: "Add \(selected.count + selectedPasskeys.count)")) { add() }
                    .disabled(selected.isEmpty && selectedPasskeys.isEmpty)
            }
        }
        .alert("Accounts Added", isPresented: $isShowingResult) {
            Button("OK") { onFinish() }
        } message: {
            Text(resultMessage ?? "")
        }
    }

    private func row(_ index: Int) -> some View {
        let account = imported.accounts[index]
        let isDuplicate = store.containsDuplicate(of: account)
        let isIncluded = !isDuplicate && !excluded.contains(index)
        return Button {
            guard !isDuplicate else { return }
            if excluded.contains(index) {
                excluded.remove(index)
            } else {
                excluded.insert(index)
            }
        } label: {
            HStack {
                Image(systemName: isIncluded ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(isIncluded ? Color.accentColor : .secondary)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(account.displayTitle)
                    if let subtitle = account.displaySubtitle {
                        Text(subtitle)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
                Spacer()
                if isDuplicate {
                    Text("Already Added")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .disabled(isDuplicate)
        .accessibilityAddTraits(isIncluded ? .isSelected : [])
    }

    private func passkeyRow(_ index: Int) -> some View {
        let passkey = imported.passkeys[index]
        let isDuplicate = store.containsPasskey(like: passkey)
        let isIncluded = !isDuplicate && !excludedPasskeys.contains(index)
        return Button {
            guard !isDuplicate else { return }
            if excludedPasskeys.contains(index) {
                excludedPasskeys.remove(index)
            } else {
                excludedPasskeys.insert(index)
            }
        } label: {
            HStack {
                Image(systemName: isIncluded ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(isIncluded ? Color.accentColor : .secondary)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(passkey.displayTitle)
                    if let subtitle = passkey.displaySubtitle {
                        Text(subtitle)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
                Spacer()
                if isDuplicate {
                    Text("Already Added")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                } else if !passkey.isBackupEligible {
                    Text("This iPhone Only")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .disabled(isDuplicate)
        .accessibilityAddTraits(isIncluded ? .isSelected : [])
    }

    private func add() {
        let passkeys = selectedPasskeys
        var result = store.importAccounts(selected, details: imported.details, meta: imported.meta)
        if result.error == nil, !passkeys.isEmpty {
            let passkeyResult = store.importPasskeys(passkeys, meta: imported.meta)
            result.added += passkeyResult.added
            result.error = passkeyResult.error
        }
        if let error = result.error {
            resultMessage = String(localized: "Added: \(result.added)") + "\n" + error
        } else {
            resultMessage = String(localized: "Added: \(result.added)")
        }
        isShowingResult = true
    }
}
