import SwiftUI

/// Home screen: one slim card per registered item. Tapping a card reveals its details.
struct HomeView: View {
    @Environment(AccountStore.self) private var store
    @Environment(AppLock.self) private var appLock
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    @State private var isAdding = false
    @State private var isShowingSettings = false
    @State private var isReordering = false
    @State private var editing: OTPAccount?
    @State private var pendingDeletion: OTPAccount?
    /// The card the user wants open. `expandedID` (sized open) and `revealedID`
    /// (details shown) catch up with it one animated step at a time.
    @State private var requestedID: UUID?
    @State private var expandedID: UUID?
    @State private var revealedID: UUID?
    @State private var isTransitioning = false
    @State private var copiedAccountID: UUID?
    @State private var copyFeedbackTask: Task<Void, Never>?
    @State private var searchText = ""
    @AppStorage("hasSeenTutorial") private var hasSeenTutorial = false
    /// Index of the tutorial step on screen, nil when the tutorial is not running.
    @State private var tutorialIndex: Int?
    @State private var tutorialAnchors = TutorialAnchors()

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
                .tutorialHost(tutorialAnchors)
                .navigationTitle("Keyring")
                .toolbar { toolbar }
                .sheet(isPresented: $isAdding) { AddAccountView() }
                .sheet(isPresented: $isShowingSettings) { SettingsView() }
                .sheet(isPresented: $isReordering) { ReorderAccountsView() }
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
                .onChange(of: scenePhase) { _, phase in
                    // Don't leave a code on screen for the next time the app is opened.
                    if phase == .background {
                        requestedID = nil
                        expandedID = nil
                        revealedID = nil
                    }
                }
        }
        .overlay {
            if let tutorialIndex {
                TutorialOverlay(
                    steps: TutorialStep.all,
                    // An empty list has no card to point at, so the callout is centered.
                    frame: { target in
                        target == .cards && store.accounts.isEmpty ? nil : tutorialAnchors.frame(of: target)
                    },
                    index: Binding(get: { tutorialIndex }, set: { self.tutorialIndex = $0 }),
                    onFinish: finishTutorial
                )
                .transition(.opacity)
            }
        }
        .task(id: hasSeenTutorial) {
            guard !hasSeenTutorial else { return }
            // Where the toolbar below puts these buttons.
            tutorialAnchors.setBarEdge(.trailing, for: .add)
            tutorialAnchors.setBarEdge(.leading, for: .settings)
            // Lets a closing sheet finish and the screen settle before measuring it.
            try? await Task.sleep(for: .seconds(0.6))
            withAnimation(.easeOut(duration: 0.25)) { tutorialIndex = 0 }
        }
    }

    private func finishTutorial() {
        withAnimation(.easeIn(duration: 0.2)) { tutorialIndex = nil }
        hasSeenTutorial = true
    }

    @ViewBuilder
    private var content: some View {
        if store.accounts.isEmpty {
            ContentUnavailableView {
                Label("No Accounts", systemImage: "key.horizontal")
            } description: {
                if store.iCloudAccountCount > 0 {
                    Text("Accounts were found in iCloud Keychain. Turn on sync to use them on this device.")
                } else {
                    Text("Scan the QR code shown when you turn on two-factor authentication for a service.")
                }
            } actions: {
                if store.iCloudAccountCount > 0 {
                    Button("Turn On iCloud Sync") { Task { await store.enableSync(confirmingWith: appLock) } }
                        .buttonStyle(.borderedProminent)
                    Button("Add Account") { isAdding = true }
                } else {
                    Button("Add Account") { isAdding = true }
                        .buttonStyle(.borderedProminent)
                }
            }
        } else {
            ScrollView {
                LazyVStack(spacing: 12) {
                    ForEach(filteredAccounts) { account in
                        card(for: account)
                            .background {
                                if account.id == filteredAccounts.first?.id {
                                    Color.clear.tutorialTarget(.cards, anchors: tutorialAnchors)
                                }
                            }
                    }
                }
                .padding(.horizontal)
                .padding(.vertical, 8)
            }
            .background(Color(.systemGroupedBackground))
            .searchable(text: $searchText, prompt: "Search accounts")
        }
    }

    private func card(for account: OTPAccount) -> some View {
        KeyringCardView(
            appearance: CardAppearance(base: account.effectiveCardColor),
            title: account.displayTitle,
            subtitle: account.displaySubtitle,
            kind: "2FA",
            isExpanded: expandedID == account.id,
            isDetailVisible: revealedID == account.id,
            onToggle: { toggle(account) }
        ) {
            TOTPCodePanel(account: account, isCopied: copiedAccountID == account.id) {
                copy(account)
            }
        }
        .contextMenu {
            Button("Copy Code", systemImage: "doc.on.doc") { copy(account) }
            Button("Edit", systemImage: "pencil") { editing = account }
            Button("Delete", systemImage: "trash", role: .destructive) { pendingDeletion = account }
        }
    }

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        ToolbarItem(placement: .topBarLeading) {
            Button("Settings", systemImage: "gearshape") { isShowingSettings = true }
        }
        if store.accounts.count > 1 {
            ToolbarItem(placement: .topBarTrailing) {
                Button("Reorder", systemImage: "arrow.up.arrow.down") { isReordering = true }
            }
        }
        ToolbarItem(placement: .topBarTrailing) {
            Button("Add Account", systemImage: "plus") { isAdding = true }
        }
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

    private func toggle(_ account: OTPAccount) {
        requestedID = requestedID == account.id ? nil : account.id
        guard !isTransitioning else { return }
        Task { await settleCards() }
    }

    /// Moves the cards toward `requestedID`, one step at a time: details fade out,
    /// a short pause, the card resizes, a short pause, details fade in. Taps during a
    /// transition only change `requestedID`, so every step still runs in order. The
    /// steps follow a fixed schedule because animation completion callbacks can arrive late.
    private func settleCards() async {
        isTransitioning = true
        defer { isTransitioning = false }

        let resizeDuration = reduceMotion ? 0.12 : 0.2
        // No bounce, so the card is at rest by the time the details fade in.
        let resizeAnimation: Animation = reduceMotion
            ? .easeInOut(duration: resizeDuration)
            : .smooth(duration: resizeDuration)
        let fadeInDuration = 0.14
        let fadeOutDuration = 0.08
        let pause = 0.05

        while expandedID != requestedID || revealedID != requestedID {
            if revealedID != nil, revealedID != requestedID {
                withAnimation(.easeIn(duration: fadeOutDuration)) { revealedID = nil }
                try? await Task.sleep(for: .seconds(fadeOutDuration + pause))
            } else if expandedID != requestedID {
                withAnimation(resizeAnimation) { expandedID = requestedID }
                if requestedID != nil {
                    try? await Task.sleep(for: .seconds(resizeDuration + pause))
                }
            } else {
                withAnimation(.easeOut(duration: fadeInDuration)) { revealedID = requestedID }
                try? await Task.sleep(for: .seconds(fadeInDuration))
            }
        }
    }

    private func copy(_ account: OTPAccount) {
        let code = TOTPGenerator.code(for: account, at: .now)
        Pasteboard.copySensitive(code.value, expiresAfter: 60)
        copiedAccountID = account.id
        // A newer copy restarts the feedback instead of being cut short by the older timer.
        copyFeedbackTask?.cancel()
        copyFeedbackTask = Task {
            do {
                try await Task.sleep(for: .seconds(1.5))
                copiedAccountID = nil
            } catch {}
        }
    }
}
