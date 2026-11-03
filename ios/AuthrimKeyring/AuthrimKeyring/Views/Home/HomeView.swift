import SwiftUI

/// Home screen: one slim card per registered item. Tapping a card reveals its details.
struct HomeView: View {
    @Environment(AccountStore.self) private var store
    @Environment(AppLock.self) private var appLock
    @Environment(WallpaperStore.self) private var wallpaper
    @Environment(WalletModel.self) private var wallet
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    @State private var isAdding = false
    @State private var isShowingSettings = false
    #if DEBUG
    @State private var screenshotSheet: ScreenshotScene?
    #endif
    @State private var editing: OTPAccount?
    @State private var editingPasskey: Passkey?
    @State private var expansion = CardExpansion()
    @State private var copiedAccountID: UUID?
    @State private var copyFeedbackTask: Task<Void, Never>?
    @State private var searchText = ""
    @AppStorage("homeSort") private var sort = HomeSort.custom
    @AppStorage("homePaging") private var paging = HomePaging.favorites
    /// The page last shown, so the app opens where it was left.
    @AppStorage("homePage") private var shownPage = ""
    /// The side the incoming page slides in from.
    @State private var pageEdge = Edge.trailing
    @AppStorage("hasSeenTutorial") private var hasSeenTutorial = false
    /// Index of the tutorial step on screen, nil when the tutorial is not running.
    @State private var tutorialIndex: Int?
    @State private var tutorialAnchors = TutorialAnchors()
    /// Two columns of cards on wide landscape screens, such as an unfolded iPhone Duo.
    @State private var columnCount = 1
    @Environment(\.accessibilityVoiceOverEnabled) private var isVoiceOverEnabled
    @State private var titleScroll = HomeTitleScroll()

    private var filteredItems: [KeyringItem] {
        store.arrangedItems(search: searchText, sort: sort, page: isSearching ? nil : page)
    }

    /// A search looks through every page.
    private var isSearching: Bool {
        !searchText.trimmingCharacters(in: .whitespaces).isEmpty
    }

    private var page: HomePage {
        paging.page(shown: shownPage) { page in
            (page.showsCredentials && !wallet.credentials.isEmpty)
                || store.items.contains { page.contains($0, isFavorite: store.meta(for: $0.id).isFavorite) }
        }
    }

    /// Whether credentials are listed above the cards.
    private var showsCredentials: Bool {
        (isSearching || page.showsCredentials) && wallet.credentials.contains { $0.matches(search: searchText) }
    }

    private func show(_ newPage: HomePage, from edge: Edge) {
        guard newPage != page else { return }
        pageEdge = edge
        withAnimation(reduceMotion ? .easeInOut(duration: 0.15) : .smooth(duration: 0.3)) {
            shownPage = newPage.rawValue
        }
    }

    var body: some View {
        NavigationStack {
            content
                .tutorialHost(tutorialAnchors)
                // The title is the wordmark above the cards; the bar shows it once
                // that has scrolled away.
                .navigationTitle("Keyring")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar { toolbar }
                .hidingSystemTitle(titleScroll.hasSideBar)
                .measuringSideBar(titleScroll)
        }
        // Light or dark text to suit the wallpaper. Sheets and alerts are attached
        // after this, so they keep following the system appearance.
        .environment(\.colorScheme, wallpaper.colorScheme ?? colorScheme)
        .sheet(isPresented: $isAdding) { AddAccountView() }
        .sheet(isPresented: $isShowingSettings) { SettingsView() }
        .sheet(item: $editing) { EditAccountView(account: $0) }
        .sheet(item: $editingPasskey) { EditPasskeyView(passkey: $0) }
        .sheet(item: Bindable(wallet).detail) { CredentialDetailView(credential: $0) }
        // A credential offer opened from a link is presented by RootView, which cannot cover one
        // of these sheets: close them so the offer shows instead of waiting unseen.
        .onChange(of: wallet.incomingOffer?.id) { _, offer in
            guard offer != nil else { return }
            isAdding = false
            isShowingSettings = false
            editing = nil
            editingPasskey = nil
            wallet.detail = nil
            #if DEBUG
            screenshotSheet = nil
            #endif
        }
        #if DEBUG
        .sheet(item: $screenshotSheet) { ScreenshotSceneSheet(scene: $0) }
        .task { await openScreenshotScene() }
        #endif
        .alert("Something went wrong", isPresented: hasError) {
            Button("OK") { store.lastError = nil }
        } message: {
            Text(store.lastError ?? "")
        }
        .alert("Something went wrong", isPresented: hasWalletLoadError) {
            Button("Try Again") { wallet.load() }
            Button("OK", role: .cancel) { wallet.loadError = nil }
        } message: {
            Text(wallet.loadError ?? "")
        }
        .onChange(of: scenePhase) { _, phase in
            // Don't leave a code on screen for the next time the app is opened.
            if phase == .background {
                expansion.closeAll()
            }
        }
        // However the page changed (a swipe, Settings, a card moving): a card left open
        // would show its code again on coming back to it.
        .onChange(of: page, initial: true) { _, newPage in
            expansion.closeAll()
            // Keeps a page picked by default once there are cards, so favoriting one later
            // does not move the screen to another page.
            if shownPage != newPage.rawValue, !store.items.isEmpty || !wallet.credentials.isEmpty {
                shownPage = newPage.rawValue
            }
        }
        .overlay {
            if let tutorialIndex {
                TutorialOverlay(
                    steps: TutorialStep.all,
                    // An empty list has no card to point at, so the callout is centered.
                    frame: { target in
                        target == .cards && store.items.isEmpty ? nil : tutorialAnchors.frame(of: target)
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
            tutorialAnchors.setBarEdge(.bottomTrailing, for: .add)
            tutorialAnchors.setBarEdge(.bottomLeading, for: .settings)
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
        if store.items.isEmpty && wallet.credentials.isEmpty {
            VStack(spacing: 0) {
                HomeTitle(scroll: titleScroll)
                HomeEmptyState { isAdding = true }
            }
            .background { WallpaperFill().ignoresSafeArea() }
            // Nothing scrolls here: not pulled, and the title is in view.
            .onAppear { titleScroll.update(offset: 0) }
        } else {
            ScrollView {
                VStack(spacing: 0) {
                    HomeTitle(scroll: titleScroll)
                    if !isSearching {
                        HomePageBar(pages: paging.pages, current: page) { newPage in
                            let pages = paging.pages
                            let isAhead = (pages.firstIndex(of: newPage) ?? 0) > (pages.firstIndex(of: page) ?? 0)
                            show(newPage, from: isAhead ? .trailing : .leading)
                        }
                        .padding(.horizontal)
                        .padding(.top, 4)
                    }
                    pageContent
                        // A new page slides in from the side it was swiped from.
                        .id(isSearching ? "search" : page.rawValue)
                        .transition(reduceMotion ? .opacity : .asymmetric(
                            insertion: .move(edge: pageEdge),
                            removal: .move(edge: pageEdge == .trailing ? .leading : .trailing)
                        ))
                }
            }
            .onPageSwipe(isEnabled: !isSearching) { step in
                show(paging.page(from: page, by: step), from: step > 0 ? .trailing : .leading)
            }
            .trackingHomeTitle(titleScroll)
            .background {
                WallpaperFill()
                    .ignoresSafeArea()
                    // Measured on the full screen, which the keyboard does not shrink.
                    .onGeometryChange(for: Int.self) { proxy in
                        // Only a wide, landscape screen; a tall one keeps a single column.
                        proxy.size.width >= 640 && proxy.size.width > proxy.size.height ? 2 : 1
                    } action: { columnCount = $0 }
            }
            .searchable(text: $searchText, prompt: "Search accounts")
        }
    }

    /// The credentials and cards of the page on screen, or of every page while searching.
    private var pageContent: some View {
        VStack(spacing: 0) {
            if showsCredentials {
                HomeCredentialsSection(search: searchText).padding(.horizontal).padding(.top, 8)
            }
            Group {
                if numberedItems.isEmpty {
                    if !showsCredentials {
                        NoMatchingCards(search: searchText, page: isSearching ? nil : page)
                    }
                } else if columnCount > 1 && !isVoiceOverEnabled {
                    // Each column stacks on its own, so opening a card moves only
                    // the cards below it. Cards go left and right in turn.
                    HStack(alignment: .top, spacing: 12) {
                        ForEach(0..<columnCount, id: \.self) { column in
                            LazyVStack(spacing: 12) {
                                cards(numberedItems.filter { $0.offset % columnCount == column })
                            }
                        }
                    }
                } else if columnCount > 1 {
                    // Rows, which VoiceOver reads in the list's order; separate
                    // columns would be read one column after the other.
                    LazyVGrid(
                        columns: Array(repeating: GridItem(.flexible(), spacing: 12, alignment: .top), count: columnCount),
                        spacing: 12
                    ) { cards(numberedItems) }
                } else {
                    LazyVStack(spacing: 12) { cards(numberedItems) }
                }
            }
            .padding(.horizontal)
            .padding(.vertical, 8)
        }
    }

    /// The items with their place in the list.
    private var numberedItems: [(offset: Int, element: KeyringItem)] {
        Array(filteredItems.enumerated())
    }

    private func cards(_ items: [(offset: Int, element: KeyringItem)]) -> some View {
        ForEach(items, id: \.element.id) { index, item in
            Group {
                switch item {
                case .account(let account): card(for: account)
                case .passkey(let passkey): card(for: passkey)
                }
            }
            .background {
                if index == 0 {
                    Color.clear.tutorialTarget(.cards, anchors: tutorialAnchors)
                }
            }
        }
    }

    private func card(for passkey: Passkey) -> some View {
        KeyringCardView(
            appearance: CardAppearance(
                base: passkey.effectiveCardColor,
                glass: wallpaper.cardGlass(in: wallpaper.colorScheme ?? colorScheme, isOpen: expansion.expandedID == passkey.id)
            ),
            title: passkey.displayTitle,
            subtitle: passkey.displaySubtitle,
            kind: "Passkey",
            isFavorite: store.meta(for: passkey.id).isFavorite,
            isExpanded: expansion.expandedID == passkey.id,
            isDetailVisible: expansion.revealedID == passkey.id,
            onToggle: { toggle(passkey.id) }
        ) {
            PasskeyPanel(passkey: passkey, isSyncEnabled: store.isSyncEnabled)
        }
        .contextMenu {
            FavoriteButton(id: passkey.id)
            // Deleting is at the bottom of the edit screen, away from a quick touch and hold.
            Button("Edit", systemImage: "pencil") { editingPasskey = passkey }
        }
    }

    private func card(for account: OTPAccount) -> some View {
        KeyringCardView(
            appearance: CardAppearance(
                base: account.effectiveCardColor,
                glass: wallpaper.cardGlass(in: wallpaper.colorScheme ?? colorScheme, isOpen: expansion.expandedID == account.id)
            ),
            title: account.displayTitle,
            subtitle: account.displaySubtitle,
            kind: "2FA",
            isFavorite: store.meta(for: account.id).isFavorite,
            isExpanded: expansion.expandedID == account.id,
            isDetailVisible: expansion.revealedID == account.id,
            onToggle: { toggle(account.id) }
        ) {
            TOTPCodePanel(
                account: account,
                recoveryCodesLeft: store.details[account.id].flatMap { $0.recoveryCodes.isEmpty ? nil : $0.unusedRecoveryCodeCount },
                isCopied: copiedAccountID == account.id
            ) {
                copy($0, of: account.id)
            }
        }
        .contextMenu {
            Button(account.kind.isTimeBased ? "Copy Code" : "Copy Next Code", systemImage: "doc.on.doc") { copy(account) }
            FavoriteButton(id: account.id)
            // Deleting is at the bottom of the edit screen, away from a quick touch and hold.
            Button("Edit", systemImage: "pencil") { editing = account }
        }
    }

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        // With the buttons down the side there is no bar above to show it in.
        if !titleScroll.hasSideBar {
            ToolbarItem(placement: .principal) {
                // Set outside, where the wordmark's scaled size is read.
                Wordmark(style: .bar)
                    .dynamicTypeSize(...Wordmark.maximumTypeSize)
                    .opacity(titleScroll.isUnderBar ? 1 : 0)
                    .accessibilityHidden(!titleScroll.isUnderBar)
            }
        }
        // Settings and Add sit at the bottom corners, within reach of the thumb; from iOS 26
        // the search field is between them.
        ToolbarItem(placement: .bottomBar) {
            Button("Settings", systemImage: "gearshape") { isShowingSettings = true }
        }
        if #available(iOS 26, *) {
            ToolbarSpacer(.fixed, placement: .bottomBar)
            DefaultToolbarItem(kind: .search, placement: .bottomBar)
            ToolbarSpacer(.fixed, placement: .bottomBar)
        } else {
            ToolbarItem(placement: .bottomBar) { Spacer() }
        }
        ToolbarItem(placement: .bottomBar) {
            Button("Add Account", systemImage: "plus") { isAdding = true }
        }
    }

    private var hasWalletLoadError: Binding<Bool> {
        Binding(get: { wallet.loadError != nil }, set: { if !$0 { wallet.loadError = nil } })
    }

    private var hasError: Binding<Bool> {
        Binding(get: { store.lastError != nil }, set: { if !$0 { store.lastError = nil } })
    }

    #if DEBUG
    /// Opens what `-screenshotScene` asks for, once the cards are on screen.
    private func openScreenshotScene() async {
        guard let scene = ScreenshotDemo.scene else { return }
        try? await Task.sleep(for: .seconds(0.5))
        switch scene {
        case .home:
            break
        case .code:
            if let account = store.accounts.first(where: { $0.issuer == ScreenshotDemo.codeIssuer }) {
                await open(.account(account))
            }
        case .passkey:
            if let passkey = store.passkeys.first { await open(.passkey(passkey)) }
        case .settings:
            isShowingSettings = true
        case .importAccounts, .recoveryCodes, .wallpaper:
            screenshotSheet = scene
        }
    }

    /// Opens a card on the page that holds it.
    private func open(_ item: KeyringItem) async {
        let isFavorite = store.meta(for: item.id).isFavorite
        if let holder = paging.pages.first(where: { $0.contains(item, isFavorite: isFavorite) }) {
            shownPage = holder.rawValue
        }
        // After the page change has closed every card.
        try? await Task.sleep(for: .seconds(0.3))
        toggle(item.id)
    }
    #endif

    private func toggle(_ id: UUID) {
        expansion.toggle(id, reduceMotion: reduceMotion)
    }

    private func copy(_ account: OTPAccount) {
        if let code = TOTPGenerator.code(for: account)?.value ?? store.nextCode(for: account.id) {
            copy(code, of: account.id)
        }
    }

    private func copy(_ code: String, of id: UUID) {
        Pasteboard.copySensitive(code, expiresAfter: 60)
        copiedAccountID = id
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
