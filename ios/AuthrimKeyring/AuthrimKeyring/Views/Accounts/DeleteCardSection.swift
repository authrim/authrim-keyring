import SwiftUI

/// The last section of an edit screen: deletes the card once the user confirms.
struct DeleteCardSection: View {
    let label: LocalizedStringKey
    /// The question the confirmation asks.
    let title: String
    let message: Text
    /// Deletes the card. Returns why it could not, or nil once it is gone.
    let onDelete: () -> String?

    @State private var isConfirming = false
    @State private var failure: String?

    var body: some View {
        Section {
            Button(label, role: .destructive) { isConfirming = true }
                .frame(maxWidth: .infinity)
                // Anchored to the button, so it points at what was tapped.
                .confirmationDialog(title, isPresented: $isConfirming, titleVisibility: .visible) {
                    Button("Delete", role: .destructive) { failure = onDelete() }
                } message: {
                    message
                }
        }
        // Shown here: the screen behind this sheet cannot present while it is open.
        .alert("Something went wrong", isPresented: Binding(get: { failure != nil }, set: { if !$0 { failure = nil } })) {
            Button("OK") {}
        } message: {
            Text(failure ?? "")
        }
    }
}
