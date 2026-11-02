import AuthenticationServices
import SwiftUI

/// AutoFill for codes and passkeys, and the sites whose passkeys stay on this device.
struct AutoFillSettingsView: View {
    @Environment(\.scenePhase) private var scenePhase

    @State private var isEnabled: Bool?
    @State private var deviceOnlySites = PasskeySyncRules.sites()
    @State private var newSite = ""
    @State private var isInvalid = false

    var body: some View {
        Form {
            Section {
                LabeledContent("AutoFill") {
                    switch isEnabled {
                    case true?: Text("On")
                    case false?: Text("Off")
                    case nil: ProgressView()
                    }
                }
                if isEnabled == false {
                    Button("Turn On AutoFill", systemImage: "key.viewfinder") {
                        Task { await turnOn() }
                    }
                }
            } footer: {
                Text("With AutoFill on, sign-in codes are suggested above the keyboard on the websites set for each card, and Keyring can save and use passkeys.")
            }

            Section {
                ForEach(deviceOnlySites, id: \.self) { site in
                    Text(site)
                }
                .onDelete { offsets in
                    for site in offsets.map({ deviceOnlySites[$0] }) {
                        PasskeySyncRules.setDeviceOnly(false, for: site)
                    }
                    deviceOnlySites = PasskeySyncRules.sites()
                }
                TextField("Add Website", text: $newSite)
                    .keyboardType(.URL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .submitLabel(.done)
                    .onSubmit(addSite)
            } header: {
                Text("Passkeys Kept on This iPhone")
            } footer: {
                if isInvalid {
                    Text("Enter a domain such as example.com.")
                        .foregroundStyle(.red)
                } else {
                    Text("New passkeys for these websites and their subdomains are never synced or backed up. You can also choose this each time you save a passkey. Passkeys already saved are not moved.")
                }
            }
        }
        .navigationTitle("AutoFill & Passkeys")
        .navigationBarTitleDisplayMode(.inline)
        .task(id: scenePhase) {
            // Picks up a change made in the Settings app.
            if scenePhase == .active {
                isEnabled = await ASCredentialIdentityStore.shared.state().isEnabled
            }
        }
    }

    private func turnOn() async {
        if #available(iOS 18, *) {
            isEnabled = await withCheckedContinuation { continuation in
                ASSettingsHelper.requestToTurnOnCredentialProviderExtension { continuation.resume(returning: $0) }
            }
        } else {
            try? await ASSettingsHelper.openCredentialProviderAppSettings()
        }
    }

    private func addSite() {
        guard !newSite.trimmed.isEmpty else { return }
        guard let site = Website.normalized(newSite) else {
            isInvalid = true
            return
        }
        isInvalid = false
        PasskeySyncRules.setDeviceOnly(true, for: site)
        deviceOnlySites = PasskeySyncRules.sites()
        newSite = ""
    }
}
