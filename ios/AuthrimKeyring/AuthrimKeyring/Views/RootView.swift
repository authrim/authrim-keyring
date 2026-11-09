import SwiftUI
import UIKit

/// Hosts the account list and covers every presented screen while the app is
/// locked or shown in the app switcher.
struct RootView: View {
    @Environment(AccountStore.self) private var store
    @Environment(AppLock.self) private var appLock
    @Environment(WalletModel.self) private var wallet
    @Environment(\.scenePhase) private var scenePhase
    @AppStorage("hasCompletedOnboarding") private var hasCompletedOnboarding = false
    @AppStorage(DemoMode.key) private var isDemoModeOn = false
    /// Credentials another app offered, shown once the app is unlocked.
    @State private var credentialImport: CredentialImportRequest?

    /// Offered once, and only when there is a lock to turn on.
    private var needsUnlockSetup: Bool {
        !hasCompletedOnboarding && !appLock.isEnabled && appLock.canUseDeviceAuthentication
    }

    var body: some View {
        Group {
            // Removing the list while locked also dismisses any sheet it presented
            // and keeps codes out of reach of VoiceOver.
            if appLock.isLocked {
                // The cover window appears a moment after launch; until then this
                // continues the launch screen instead of a blank one.
                CoverView()
            } else if needsUnlockSetup {
                UnlockSetupView { hasCompletedOnboarding = true }
            } else {
                HomeView()
            }
        }
        .task {
            // Nothing to offer when the lock is already on or cannot be used, and
            // remembering that keeps the screen from appearing later on.
            if !hasCompletedOnboarding, appLock.isEnabled || !appLock.canUseDeviceAuthentication {
                hasCompletedOnboarding = true
            }
        }
        .background(CoverWindowInstaller(isCovered: appLock.isLocked || scenePhase != .active))
        .onContinueUserActivity("ASCredentialExchangeActivity") { activity in
            credentialImport = CredentialImportRequest(activity)
        }
        // A credential offer opened from a link waits here until the app is unlocked.
        .onOpenURL { wallet.handle(url: $0) }
        // In Demo Mode what arrives would go with the made-up cards, so it is not taken.
        .sheet(item: unlockedOffer, onDismiss: wallet.incomingOfferSheetDidDismiss) { offer in
            if isDemoModeOn {
                DemoModeAddNotice()
            } else if let flow = wallet.incomingOfferFlow {
                CredentialOfferSheet(flow: flow)
            } else {
                CredentialOfferSheet(offer: offer.text)
            }
        }
        .sheet(item: unlockedPresentation) { request in
            if isDemoModeOn { DemoModeAddNotice() } else { PresentationSheet(link: request.text) }
        }
        .sheet(item: unlockedCredentialImport) { request in
            if isDemoModeOn {
                DemoModeAddNotice()
            } else if #available(iOS 26, *) {
                CredentialImportView(token: request.id) { credentialImport = nil }
            }
        }
        .onChange(of: scenePhase) { _, phase in
            switch phase {
            case .background:
                // Keep the offer and its progress, but require the transaction code again after unlock.
                appLock.lock()
                wallet.suspendIncomingOfferForBackground(removesAddAccountSheet: appLock.isEnabled)
            case .active:
                // Picks up accounts that iCloud Keychain synced while the app was away.
                store.load()
                wallet.load()
                Task { await appLock.unlockOnActivation() }
            default:
                break
            }
        }
    }

    /// The pending credential offer, but only while the app is unlocked.
    private var unlockedOffer: Binding<IncomingOffer?> {
        Binding(
            get: { appLock.isLocked || needsUnlockSetup || wallet.cameraOfferWaitsForAddSheet ? nil : wallet.incomingOffer },
            set: { value in
                if let value {
                    wallet.incomingOffer = value
                } else if !appLock.isLocked && scenePhase == .active && !needsUnlockSetup
                            && !wallet.cameraOfferWaitsForAddSheet {
                    // A user dismissal closes the offer; the app lock's temporary dismissal does not.
                    wallet.closeIncomingOffer()
                }
            }
        )
    }

    /// The pending presentation request, but only while the app is unlocked.
    private var unlockedPresentation: Binding<IncomingOffer?> {
        Binding(
            get: { appLock.isLocked || needsUnlockSetup ? nil : wallet.incomingPresentation },
            set: { wallet.incomingPresentation = $0 }
        )
    }

    /// The pending import, but only while the codes may be shown.
    private var unlockedCredentialImport: Binding<CredentialImportRequest?> {
        Binding(
            get: { appLock.isLocked || needsUnlockSetup ? nil : credentialImport },
            set: { credentialImport = $0 }
        )
    }
}

/// Shows `CoverView` in a window above all sheets and alerts of the scene.
private struct CoverWindowInstaller: UIViewRepresentable {
    var isCovered: Bool
    @Environment(AppLock.self) private var appLock

    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeUIView(context: Context) -> UIView {
        let view = UIView()
        view.isHidden = true
        return view
    }

    func updateUIView(_ view: UIView, context: Context) {
        // The host view may not be in a window yet on first update.
        let apply = { [appLock] in
            context.coordinator.update(scene: view.window?.windowScene, isCovered: isCovered, appLock: appLock)
        }
        if view.window == nil {
            DispatchQueue.main.async(execute: apply)
        } else {
            apply()
        }
    }

    final class Coordinator {
        private var window: UIWindow?

        func update(scene: UIWindowScene?, isCovered: Bool, appLock: AppLock) {
            if window == nil, let scene {
                let window = UIWindow(windowScene: scene)
                window.windowLevel = .alert + 1
                let host = UIHostingController(rootView: CoverView().environment(appLock))
                host.view.accessibilityViewIsModal = true
                window.rootViewController = host
                self.window = window
            }
            // No animation: the app switcher snapshot is taken right after this.
            window?.isHidden = !isCovered
        }
    }
}

private struct CoverView: View {
    @Environment(AppLock.self) private var appLock

    var body: some View {
        ZStack {
            Rectangle().fill(.background).ignoresSafeArea()
            // The middle stays empty: the system Face ID indicator appears there.
            VStack(spacing: 0) {
                VStack(spacing: 20) {
                    BrandMark(size: 72)
                    Wordmark(style: .logo)
                    if appLock.isLocked {
                        Label("Locked", systemImage: "lock.fill")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(.top, 72)
                Spacer(minLength: 24)
                if appLock.isLocked {
                    Button {
                        Task { await appLock.unlock() }
                    } label: {
                        Label("Unlock with \(appLock.biometryName)", systemImage: "lock.open")
                            .frame(maxWidth: .infinity, minHeight: 32)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .disabled(appLock.isAuthenticating)
                    .padding(.bottom, 24)
                }
            }
            .padding(.horizontal, 32)
            .frame(maxWidth: 520)
        }
    }
}

/// App mark used on lock and privacy screens: the app icon's artwork.
struct BrandMark: View {
    var size: CGFloat

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: size * 0.225, style: .continuous)
        Image("BrandMark")
            .resizable()
            .interpolation(.high)
            .frame(width: size, height: size)
            .clipShape(shape)
            // The light tile needs an edge on the light background.
            .overlay { shape.strokeBorder(.black.opacity(0.08)) }
            .shadow(color: .black.opacity(0.12), radius: 8, y: 3)
            .accessibilityHidden(true)
    }
}
