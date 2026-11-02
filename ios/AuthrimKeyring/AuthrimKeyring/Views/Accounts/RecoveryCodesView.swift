import SwiftUI

/// The recovery codes kept for one card. They stay hidden until the device owner
/// confirms, like the secret keys they stand in for.
struct RecoveryCodesView: View {
    @Environment(AccountStore.self) private var store
    @Environment(AppLock.self) private var appLock
    @Environment(\.scenePhase) private var scenePhase

    let accountID: UUID
    @State private var isRevealed = false
    @State private var isAdding = false
    @State private var copiedID: UUID?

    private var details: AccountDetails { store.details(for: accountID) }

    var body: some View {
        List {
            if store.areDetailsUnavailable {
                Label(AccountStore.StoreError.detailsUnavailable.localizedDescription, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            } else if details.recoveryCodes.isEmpty {
                ContentUnavailableView {
                    Label("No Recovery Codes", systemImage: "key.viewfinder")
                } description: {
                    Text("Paste the recovery codes the service gave you when you turned on two-factor authentication. Each one can be used once to sign in without this app.")
                } actions: {
                    Button("Add Recovery Codes") { isAdding = true }
                        .buttonStyle(.borderedProminent)
                }
                .listRowBackground(Color.clear)
            } else if isRevealed {
                Section {
                    ForEach(details.recoveryCodes) { code in
                        row(for: code)
                    }
                    .onDelete(perform: delete)
                } footer: {
                    Text("Tap a code to copy it. Swipe to mark it as used once you have signed in with it.")
                }
            } else {
                Section {
                    LabeledContent("Unused", value: "\(details.unusedRecoveryCodeCount)")
                    LabeledContent("Used", value: "\(details.recoveryCodes.count - details.unusedRecoveryCodeCount)")
                    Button("Show Codes", systemImage: "eye") {
                        Task { await reveal() }
                    }
                }
            }
        }
        .navigationTitle("Recovery Codes")
        .navigationBarTitleDisplayMode(.inline)
        .onChange(of: scenePhase) { _, phase in
            // Hidden again once the app is left. Not on `.inactive`, which the Face ID
            // prompt itself causes.
            if phase == .background {
                isRevealed = false
            }
        }
        .toolbar {
            if !details.recoveryCodes.isEmpty, !store.areDetailsUnavailable {
                ToolbarItem(placement: .primaryAction) {
                    Button("Add", systemImage: "plus") { isAdding = true }
                }
            }
        }
        .sheet(isPresented: $isAdding) {
            AddRecoveryCodesView { text in
                var updated = details
                let wasEmpty = updated.recoveryCodes.isEmpty
                updated.addRecoveryCodes(from: text)
                store.setDetails(updated)
                // Only the codes just pasted are known to the user; earlier ones stay hidden.
                if wasEmpty {
                    isRevealed = true
                }
            }
        }
    }

    private func row(for code: RecoveryCode) -> some View {
        Button {
            Pasteboard.copySensitive(code.code, expiresAfter: 60)
            copiedID = code.id
        } label: {
            HStack {
                Text(code.code)
                    .font(.body.monospaced())
                    .strikethrough(code.isUsed)
                    .foregroundStyle(code.isUsed ? .secondary : .primary)
                    .textSelection(.enabled)
                Spacer()
                if copiedID == code.id {
                    Image(systemName: "checkmark")
                        .foregroundStyle(.tint)
                        .accessibilityLabel("Copied")
                } else if code.isUsed {
                    Text("Used")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .buttonStyle(.plain)
        .swipeActions(edge: .leading) {
            Button(code.isUsed ? "Mark as Unused" : "Mark as Used", systemImage: code.isUsed ? "arrow.uturn.backward" : "checkmark") {
                toggleUsed(code)
            }
            .tint(code.isUsed ? .gray : .green)
        }
        .accessibilityHint("Double-tap to copy the code.")
    }

    private func reveal() async {
        if await appLock.confirmDeviceOwner(reason: String(localized: "Show the recovery codes.")) {
            isRevealed = true
        }
    }

    private func toggleUsed(_ code: RecoveryCode) {
        var updated = details
        guard let index = updated.recoveryCodes.firstIndex(where: { $0.id == code.id }) else { return }
        updated.recoveryCodes[index].usedAt = code.isUsed ? nil : .now
        store.setDetails(updated)
    }

    private func delete(at offsets: IndexSet) {
        var updated = details
        updated.recoveryCodes.remove(atOffsets: offsets)
        store.setDetails(updated)
    }
}

/// Pasting a list of recovery codes.
private struct AddRecoveryCodesView: View {
    @Environment(\.dismiss) private var dismiss
    let onAdd: (String) -> Void
    @State private var text = ""

    private var count: Int { AccountDetails.recoveryCodes(in: text).count }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextEditor(text: $text)
                        .font(.body.monospaced())
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .frame(minHeight: 200)
                } footer: {
                    Text("Paste the whole list. Codes on separate lines, in columns, or separated by commas are split up.")
                }
            }
            .navigationTitle("Add Recovery Codes")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(count == 0 ? String(localized: "Add") : String(localized: "Add \(count)")) {
                        onAdd(text)
                        dismiss()
                    }
                    .disabled(count == 0)
                }
            }
        }
    }
}
