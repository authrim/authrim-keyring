import Foundation

/// Collects the QR codes of one Google Authenticator transfer, which may be
/// split across several codes shown one after another.
nonisolated struct MigrationProgress: Sendable {
    let id: Int
    let size: Int
    private(set) var batches: [Int: ImportedAccounts] = [:]

    init(first batch: GoogleAuthMigration.Batch) {
        id = batch.id
        size = batch.size
        batches[batch.index] = batch.accounts
    }

    /// Whether a code is part of this transfer.
    func belongs(_ batch: GoogleAuthMigration.Batch) -> Bool {
        batch.id == id && batch.size == size
    }

    /// Adds another code of this transfer; one seen before is ignored.
    mutating func add(_ batch: GoogleAuthMigration.Batch) throws(ImportError) {
        guard belongs(batch) else { throw .mixedTransfers }
        guard batches[batch.index] == nil else { return }
        let total = batches.values.reduce(0) { $0 + $1.accounts.count + $1.skipped.count }
        guard total + batch.accounts.accounts.count + batch.accounts.skipped.count <= ImportedAccounts.maximumEntries else {
            throw .tooLarge
        }
        batches[batch.index] = batch.accounts
    }

    var scannedCount: Int { batches.count }
    var isComplete: Bool { batches.count == size }

    /// The accounts in the order of the codes.
    var accounts: ImportedAccounts {
        var result = ImportedAccounts()
        for index in batches.keys.sorted() {
            if let batch = batches[index] {
                result.append(contentsOf: batch)
            }
        }
        return result
    }
}
