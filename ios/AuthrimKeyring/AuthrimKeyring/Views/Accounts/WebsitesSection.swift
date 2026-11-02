import SwiftUI

/// The sites where a card's code is offered by AutoFill, edited with the card.
struct WebsitesSection: View {
    @Binding var websites: [String]
    /// Text typed but not yet added; the card's Save adds it too.
    @Binding var newSite: String
    /// A likely site for the service, offered when it is not in the list yet.
    let suggestion: String?

    @State private var isInvalid = false

    var body: some View {
        Section {
            ForEach(websites, id: \.self) { site in
                Text(site)
            }
            .onDelete { websites.remove(atOffsets: $0) }
            if let suggestion, !websites.contains(suggestion) {
                Button("Add \(suggestion)", systemImage: "plus.circle") {
                    websites.append(suggestion)
                }
            }
            if websites.count < Website.maximumPerAccount {
                HStack {
                    TextField("Add Website", text: $newSite)
                        .keyboardType(.URL)
                        .textContentType(.URL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .submitLabel(.done)
                        .onSubmit(add)
                    Button("Add", systemImage: "plus.circle.fill", action: add)
                        .labelStyle(.iconOnly)
                        .disabled(newSite.trimmed.isEmpty)
                }
            }
        } header: {
            Text("Websites")
        } footer: {
            if isInvalid {
                Text("Enter a domain such as example.com.")
                    .foregroundStyle(.red)
            } else {
                Text("With Keyring turned on for AutoFill, the code is suggested above the keyboard on these sites and their subdomains.")
            }
        }
    }

    private func add() {
        guard !newSite.trimmed.isEmpty else { return }
        isInvalid = !Self.add(newSite, to: &websites)
        if !isInvalid {
            newSite = ""
        }
    }

    /// Adds a typed site to the list. Returns false if it is not a domain.
    static func add(_ text: String, to websites: inout [String]) -> Bool {
        guard let site = Website.normalized(text) else { return false }
        if !websites.contains(site), websites.count < Website.maximumPerAccount {
            websites.append(site)
        }
        return true
    }
}
