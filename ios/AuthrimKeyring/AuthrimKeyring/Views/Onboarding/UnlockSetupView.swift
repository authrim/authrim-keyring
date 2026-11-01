import SwiftUI

/// First-launch screen that offers to turn on the app lock.
struct UnlockSetupView: View {
    let onFinish: () -> Void

    @Environment(AppLock.self) private var appLock
    @ScaledMetric(relativeTo: .largeTitle) private var symbolSize: CGFloat = 88

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(spacing: 20) {
                    Image(systemName: appLock.biometrySymbol)
                        .font(.system(size: symbolSize, weight: .light))
                        .foregroundStyle(Color.accentColor.gradient)
                        .padding(.top, 72)
                        .padding(.bottom, 12)
                        .accessibilityHidden(true)
                    Text("Choose How to Unlock")
                        .font(.title2.bold())
                        .multilineTextAlignment(.center)
                    Text("Require \(appLock.biometryName) or your passcode each time Keyring opens, so no one else can see your codes.")
                        .multilineTextAlignment(.center)
                        .foregroundStyle(.secondary)
                    Text("You can change this at any time in Settings.")
                        .font(.callout)
                        .multilineTextAlignment(.center)
                        .foregroundStyle(.secondary)
                }
                .padding(.horizontal, 32)
                .frame(maxWidth: 520)
                .frame(maxWidth: .infinity)
            }
            .scrollBounceBehavior(.basedOnSize)

            VStack(spacing: 12) {
                Button {
                    Task {
                        await appLock.setEnabled(true)
                        // A cancelled prompt keeps the user here to choose again.
                        if appLock.isEnabled { onFinish() }
                    }
                } label: {
                    Text("Use \(appLock.biometryName)")
                        .font(.headline)
                        .frame(maxWidth: .infinity, minHeight: 32)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(appLock.isAuthenticating)

                Button("Not Now", action: onFinish)
                    .font(.headline)
                    .frame(minHeight: 44)
                    .disabled(appLock.isAuthenticating)
            }
            .padding(.horizontal, 32)
            .padding(.bottom, 16)
            .frame(maxWidth: 520)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(.systemBackground))
    }
}
