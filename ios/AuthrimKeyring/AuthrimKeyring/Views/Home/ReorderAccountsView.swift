import SwiftUI

struct ReorderAccountsView: View {
    @Environment(AccountStore.self) private var store
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                ForEach(store.items) { item in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(item.displayTitle)
                            if let subtitle = item.displaySubtitle {
                                Text(subtitle)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        Spacer()
                        if case .passkey = item {
                            Image(systemName: "person.badge.key")
                                .foregroundStyle(.secondary)
                                .accessibilityLabel("Passkey")
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
