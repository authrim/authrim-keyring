import Foundation

/// Sites whose new passkeys stay on this device, never synced or backed up.
/// The list itself is a setting on this device.
///
/// A rule covers a site's subdomains too. A subdomain can opt out of its parent's
/// rule; the most specific rule wins.
nonisolated enum PasskeySyncRules {
    private static let deviceOnlyKey = "passkeyDeviceOnlySites"
    private static let syncedKey = "passkeySyncedSites"
    static let maximumSites = 200

    /// The sites the user chose to keep on this device, as listed in Settings.
    static func sites(in defaults: UserDefaults = SharedDefaults.store) -> [String] {
        defaults.stringArray(forKey: deviceOnlyKey) ?? []
    }

    static func isDeviceOnly(_ relyingParty: String, in defaults: UserDefaults = SharedDefaults.store) -> Bool {
        isDeviceOnly(relyingParty, given: sites(in: defaults), exceptions(in: defaults))
    }

    static func setDeviceOnly(_ deviceOnly: Bool, for site: String, in defaults: UserDefaults = SharedDefaults.store) {
        var deviceOnlySites = sites(in: defaults).filter { $0 != site }
        var syncedSites = exceptions(in: defaults).filter { $0 != site }
        // Decides by the rules that remain, so a parent's rule is followed or overridden.
        let inherited = isDeviceOnly(site, given: deviceOnlySites, syncedSites)
        if deviceOnly, !inherited, deviceOnlySites.count < maximumSites {
            deviceOnlySites.append(site)
        } else if !deviceOnly, inherited, syncedSites.count < maximumSites {
            syncedSites.append(site)
        }
        defaults.set(deviceOnlySites.sorted(), forKey: deviceOnlyKey)
        defaults.set(syncedSites.sorted(), forKey: syncedKey)
    }

    private static func exceptions(in defaults: UserDefaults) -> [String] {
        defaults.stringArray(forKey: syncedKey) ?? []
    }

    private static func isDeviceOnly(_ site: String, given deviceOnlySites: [String], _ syncedSites: [String]) -> Bool {
        let closestDeviceOnly = deviceOnlySites.filter { Website.isSameOrSubdomain(site, of: $0) }.map(\.count).max() ?? 0
        let closestSynced = syncedSites.filter { Website.isSameOrSubdomain(site, of: $0) }.map(\.count).max() ?? 0
        return closestDeviceOnly > closestSynced
    }
}
