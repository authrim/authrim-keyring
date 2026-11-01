import SwiftUI
import UIKit

/// Hosts the account list and covers every presented screen while the app is
/// locked or shown in the app switcher.
struct RootView: View {
    @Environment(AccountStore.self) private var store
    @Environment(AppLock.self) private var appLock
    @Environment(\.scenePhase) private var scenePhase
    @AppStorage("hasCompletedOnboarding") private var hasCompletedOnboarding = false

    /// Offered once, and only when there is a lock to turn on.
    private var needsUnlockSetup: Bool {
        !hasCompletedOnboarding && !appLock.isEnabled && appLock.canUseDeviceAuthentication
    }

    var body: some View {
        Group {
            // Removing the list while locked also dismisses any sheet it presented
            // and keeps codes out of reach of VoiceOver.
            if appLock.isLocked {
                Color(.systemBackground).ignoresSafeArea()
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
        .onChange(of: scenePhase) { _, phase in
            switch phase {
            case .background:
                appLock.lock()
            case .active:
                // Picks up accounts that iCloud Keychain synced while the app was away.
                store.load()
                Task { await appLock.unlockOnActivation() }
            default:
                break
            }
        }
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
            VStack(spacing: 24) {
                BrandMark(size: 72)
                if appLock.isLocked {
                    Text("Authrim Keyring is locked")
                        .font(.headline)
                    Button {
                        Task { await appLock.unlock() }
                    } label: {
                        Label("Unlock with \(appLock.biometryName)", systemImage: "lock.open")
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(appLock.isAuthenticating)
                }
            }
            .padding()
        }
    }
}

/// App mark used on lock and privacy screens.
struct BrandMark: View {
    var size: CGFloat

    var body: some View {
        Image(systemName: "key.horizontal.fill")
            .font(.system(size: size * 0.5, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: size, height: size)
            .background(Color.accentColor.gradient, in: .rect(cornerRadius: size * 0.24))
            .accessibilityHidden(true)
    }
}
