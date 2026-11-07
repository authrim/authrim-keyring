import Foundation

/// Lets one process at a time read and advance the counter of a counter-based card,
/// so the app and the AutoFill extension never hand out the same code. It is a file
/// lock in the App Group, which the system releases if the holder exits. It is held
/// while a counter is read and written, or while the cards move between iCloud and
/// this device, and a process waits at most two seconds for it.
nonisolated enum CounterLock {
    static let timeout: Duration = .seconds(2)

    /// No code is made without the lock: another process might be making the same one.
    struct Unavailable: LocalizedError {
        var errorDescription: String? {
            String(localized: "This card could not be updated right now. Try again in a moment.")
        }
    }

    static func withLock<T>(_ body: () throws -> T) throws -> T {
        guard let folder = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: SharedDefaults.suiteName)
        else { throw Unavailable() }
        let path = folder.appending(path: "counter.lock").path(percentEncoded: false)
        let descriptor = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw Unavailable() }
        // Closing the file also releases the lock.
        defer { close(descriptor) }
        let deadline = ContinuousClock.now + timeout
        while flock(descriptor, LOCK_EX | LOCK_NB) != 0 {
            guard errno == EWOULDBLOCK || errno == EINTR, ContinuousClock.now < deadline else { throw Unavailable() }
            usleep(10_000)
        }
        defer { flock(descriptor, LOCK_UN) }
        return try body()
    }
}
