import SwiftUI

/// Adds an account from a setup key typed or pasted by the user.
struct ManualEntryView: View {
    @Environment(AccountStore.self) private var store

    let onSaved: () -> Void

    @State private var issuer = ""
    @State private var accountName = ""
    @State private var secret = ""
    @State private var isSecretVisible = false
    @State private var algorithm = OTPAlgorithm.sha1
    @State private var digits = 6
    @State private var period = 30

    private var decodedSecret: Data? {
        Base32.decode(secret)
    }

    private var secretIsInvalid: Bool {
        !secret.trimmed.isEmpty && decodedSecret == nil
    }

    private var canSave: Bool {
        decodedSecret != nil && (!issuer.trimmed.isEmpty || !accountName.trimmed.isEmpty)
    }

    private var candidate: OTPAccount? {
        guard let decodedSecret else { return nil }
        return OTPAccount(
            issuer: issuer.trimmed,
            accountName: accountName.trimmed,
            secret: decodedSecret,
            algorithm: algorithm,
            digits: digits,
            period: period
        )
    }

    var body: some View {
        Form {
            Section("Name") {
                TextField("Service (e.g. Example Inc.)", text: $issuer)
                    .textContentType(.organizationName)
                TextField("Account (e.g. name@example.com)", text: $accountName)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
            }
            Section {
                HStack {
                    // Secure entry keeps third-party keyboards away from the key by default.
                    Group {
                        if isSecretVisible {
                            TextField("Setup Key", text: $secret, axis: .vertical)
                        } else {
                            SecureField("Setup Key", text: $secret)
                        }
                    }
                    .font(.body.monospaced())
                    .textInputAutocapitalization(.characters)
                    .autocorrectionDisabled()
                    .keyboardType(.asciiCapable)
                    .privacySensitive()
                    Button {
                        isSecretVisible.toggle()
                    } label: {
                        Image(systemName: isSecretVisible ? "eye.slash" : "eye")
                    }
                    .buttonStyle(.borderless)
                    .accessibilityLabel(isSecretVisible ? Text("Hide Setup Key") : Text("Show Setup Key"))
                }
            } header: {
                Text("Setup Key")
            } footer: {
                if secretIsInvalid {
                    Text("The setup key can contain only the letters A–Z and the digits 2–7.")
                        .foregroundStyle(.red)
                } else {
                    Text("Enter the key shown under the QR code. Spaces are ignored.")
                }
            }
            Section {
                Picker("Algorithm", selection: $algorithm) {
                    ForEach(OTPAlgorithm.allCases) { Text($0.rawValue).tag($0) }
                }
                Picker("Digits", selection: $digits) {
                    ForEach(OTPAccount.supportedDigits, id: \.self) { Text("\($0)").tag($0) }
                }
                Picker("Period", selection: $period) {
                    ForEach(OTPAccount.supportedPeriods, id: \.self) { Text("\($0) seconds").tag($0) }
                }
            } header: {
                Text("Advanced")
            } footer: {
                Text("Most services use SHA1, 6 digits and 30 seconds. Change these only if the service tells you to.")
            }
            if let candidate, store.containsDuplicate(of: candidate) {
                Section {
                    Label("This account has already been added.", systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                }
            }
        }
        .navigationTitle("Enter Setup Key")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Add") {
                    if let candidate, store.add(candidate) { onSaved() }
                }
                .disabled(!canSave)
            }
        }
    }
}
