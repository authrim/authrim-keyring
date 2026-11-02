import AuthenticationServices
import SwiftUI

/// What another app sent through the system's credential exchange, before it is added.
@available(iOS 26, *)
struct CredentialImportView: View {
    let token: UUID
    let onFinish: () -> Void

    @State private var imported: ImportedAccounts?
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            Group {
                if let imported, !imported.isEmpty || imported.otherCount > 0 {
                    ImportPreviewView(imported: imported, onFinish: onFinish)
                } else if imported != nil {
                    ContentUnavailableView(
                        "Nothing to Add",
                        systemImage: "tray",
                        description: Text("The other app sent no one-time codes or passkeys.")
                    )
                } else if let errorMessage {
                    ContentUnavailableView("Could Not Import", systemImage: "exclamationmark.triangle", description: Text(errorMessage))
                } else {
                    ProgressView()
                }
            }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: onFinish)
                }
            }
        }
        .task {
            do {
                let data = try await ASCredentialImportManager().importCredentials(token: token)
                imported = try CredentialExchange.read(data)
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }
}

/// A request from another app to hand over credentials, waiting for the app to be unlocked.
struct CredentialImportRequest: Identifiable {
    let id: UUID

    /// The token of a credential exchange activity, as the system sends it.
    init?(_ activity: NSUserActivity) {
        guard #available(iOS 26, *), let token = activity.userInfo?[ASCredentialImportToken] as? UUID else { return nil }
        id = token
    }
}

/// Sends every account and passkey that may leave this device to another app,
/// through the system's credential exchange.
@available(iOS 26, *)
struct CredentialExportButton: View {
    @Environment(AccountStore.self) private var store
    @Environment(AppLock.self) private var appLock
    @State private var isWorking = false
    @State private var message: String?

    var body: some View {
        Button("Export to Another App", systemImage: "arrow.up.forward.app") {
            Task { await export() }
        }
        .disabled(isWorking || store.items.isEmpty)
        .alert("Export", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("OK") { message = nil }
        } message: {
            Text(message ?? "")
        }
    }

    private func export() async {
        isWorking = true
        defer { isWorking = false }
        // The export holds every secret, as a backup file does.
        guard await appLock.confirmDeviceOwner(reason: String(localized: "Export your accounts and passkeys to another app.")) else {
            return
        }
        // Without them, recovery codes, favorites and tags would quietly be missing.
        guard !store.areDetailsUnavailable else {
            message = AccountStore.StoreError.detailsUnavailable.localizedDescription
            return
        }
        guard !store.isMetaUnavailable else {
            message = AccountStore.MetaError.unavailable.localizedDescription
            return
        }
        guard let window = UIApplication.shared.connectedScenes
            .compactMap({ ($0 as? UIWindowScene)?.keyWindow }).first
        else { return }
        do {
            let manager = ASCredentialExportManager(presentationAnchor: window)
            let options = try await manager.requestExport(for: CredentialExchange.extensionBundleIdentifier)
            let export = CredentialExchange.export(
                accounts: store.accounts,
                passkeys: store.passkeys,
                details: store.details,
                meta: store.meta,
                formatVersion: options.formatVersion
            )
            try await manager.exportCredentials(export.data)
            var text = String(localized: "Exported: \(export.exportedCount)")
            if export.leftOutCount > 0 {
                text += "\n" + String(localized: "Not exported: \(export.leftOutCount). Counter-based and Steam codes cannot be moved this way, and passkeys kept on this iPhone only stay on it.")
            }
            message = text
        } catch let error as ASAuthorizationError where error.code == .canceled {
            return
        } catch {
            message = error.localizedDescription
        }
    }
}
