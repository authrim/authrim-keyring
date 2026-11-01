import SwiftUI

struct AccountListView: View {
    @Environment(AccountStore.self) private var store

    @State private var isAdding = false
    @State private var isShowingSettings = false
    @State private var editing: OTPAccount?
    @State private var pendingDeletion: OTPAccount?
    @State private var copiedAccountID: UUID?
    @State private var searchText = ""

    private var filteredAccounts: [OTPAccount] {
        let query = searchText.trimmingCharacters(in: .whitespaces)
        guard !query.isEmpty else { return store.accounts }
        return store.accounts.filter {
            $0.issuer.localizedCaseInsensitiveContains(query)
                || $0.accountName.localizedCaseInsensitiveContains(query)
        }
    }

    var body: some View {
        NavigationStack {
            content
                .navigationTitle("Keyring")
                .toolbar { toolbar }
                .sheet(isPresented: $isAdding) { AddAccountView() }
                .sheet(isPresented: $isShowingSettings) { SettingsView() }
                .sheet(item: $editing) { EditAccountView(account: $0) }
                .confirmationDialog(
                    deletionTitle,
                    isPresented: isConfirmingDeletion,
                    titleVisibility: .visible,
                    presenting: pendingDeletion
                ) { account in
                    Button("Delete", role: .destructive) { store.delete(account.id) }
                } message: { _ in
                    Text("Make sure two-factor authentication is turned off for this account or that you have another way to sign in. This cannot be undone.")
                }
                .alert("Something went wrong", isPresented: hasError) {
                    Button("OK") { store.lastError = nil }
                } message: {
                    Text(store.lastError ?? "")
                }
        }
    }

    @ViewBuilder
    private var content: some View {
        if store.accounts.isEmpty {
            ContentUnavailableView {
                Label("No Accounts", systemImage: "key.horizontal")
            } description: {
                Text("Scan the QR code shown when you turn on two-factor authentication for a service.")
            } actions: {
                Button("Add Account") { isAdding = true }
                    .buttonStyle(.borderedProminent)
            }
        } else {
            TimelineView(.periodic(from: .now, by: 1)) { timeline in
                List {
                    ForEach(filteredAccounts) { account in
                        AccountRowView(
                            account: account,
                            now: timeline.date,
                            isCopied: copiedAccountID == account.id,
                            onCopy: { copy(account) }
                        )
                        .swipeActions {
                            Button("Delete", systemImage: "trash", role: .destructive) {
                                pendingDeletion = account
                            }
                            Button("Edit", systemImage: "pencil") { editing = account }
                        }
                        .contextMenu {
                            Button("Copy Code", systemImage: "doc.on.doc") { copy(account) }
                            Button("Edit", systemImage: "pencil") { editing = account }
                            Button("Delete", systemImage: "trash", role: .destructive) { pendingDeletion = account }
                        }
                    }
                    .onMove(perform: moveAction)
                }
                .listStyle(.insetGrouped)
            }
            .searchable(text: $searchText, prompt: "Search accounts")
        }
    }

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        ToolbarItem(placement: .topBarLeading) {
            Button("Settings", systemImage: "gearshape") { isShowingSettings = true }
        }
        if !store.accounts.isEmpty {
            ToolbarItem(placement: .topBarTrailing) { EditButton() }
        }
        ToolbarItem(placement: .topBarTrailing) {
            Button("Add Account", systemImage: "plus") { isAdding = true }
        }
    }

    /// Reordering is only meaningful on the unfiltered list.
    private var moveAction: ((IndexSet, Int) -> Void)? {
        guard searchText.isEmpty else { return nil }
        return { source, destination in store.move(fromOffsets: source, toOffset: destination) }
    }

    private var deletionTitle: String {
        guard let account = pendingDeletion else { return "" }
        return String(localized: "Delete “\(account.displayTitle)”?")
    }

    private var isConfirmingDeletion: Binding<Bool> {
        Binding(get: { pendingDeletion != nil }, set: { if !$0 { pendingDeletion = nil } })
    }

    private var hasError: Binding<Bool> {
        Binding(get: { store.lastError != nil }, set: { if !$0 { store.lastError = nil } })
    }

    private func copy(_ account: OTPAccount) {
        // Use the current time rather than the timeline tick so a code is never copied stale.
        let code = TOTPGenerator.code(for: account, at: .now)
        Pasteboard.copySensitive(code.value, expiresAfter: 60)
        copiedAccountID = account.id
        Task {
            try? await Task.sleep(for: .seconds(1.5))
            if copiedAccountID == account.id { copiedAccountID = nil }
        }
    }
}
