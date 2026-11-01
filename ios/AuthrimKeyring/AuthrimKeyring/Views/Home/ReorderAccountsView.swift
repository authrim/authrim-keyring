import SwiftUI

struct ReorderAccountsView: View {
    @Environment(AccountStore.self) private var store
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                ForEach(store.accounts) { account in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(account.displayTitle)
                        if let subtitle = account.displaySubtitle {
                            Text(subtitle)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .onMove { source, destination in
                    store.move(fromOffsets: source, toOffset: destination)
                }
            }
            .environment(\.editMode, .constant(.active))
            .navigationTitle("Reorder")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
}
