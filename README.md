# Authrim Keyring

> Two-factor codes, passkeys, and verifiable credentials for iPhone. Private by design, filled in with AutoFill, and locked with Face ID.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
![Platform: iOS 17+](https://img.shields.io/badge/iOS-17%2B-black?logo=apple)
![Swift](https://img.shields.io/badge/Swift-SwiftUI-orange?logo=swift)

Authrim Keyring is the iPhone companion to [Authrim](https://authrim.com/), an open-source identity hub. It keeps the codes and keys you sign in with in one place, on your device, without an account.

- Website: <https://authrim.com/keyring/>
- Support: <https://authrim.com/keyring/support>
- Privacy policy: <https://authrim.com/keyring/privacy>

## Features

### Two-factor codes
- TOTP (RFC 6238) with SHA-1, SHA-256 and SHA-512, 6 to 8 digits, and periods from 10 to 300 seconds
- Counter-based HOTP (RFC 4226) and Steam Guard codes
- Add accounts by scanning a QR code, picking a screenshot, or typing the setup key
- Recovery codes kept with each account, hidden until Face ID

### Passkeys
- A passkey provider for iOS through the Credential Provider extension: create and use passkeys in Safari and apps, approved with Face ID
- Passkeys sync with iCloud Keychain when sync is on, or stay on this iPhone only (in the Secure Enclave) for the websites you choose
- AAGUID: `6f1c5e2a-7b4d-4e8f-9a3c-2d5b8e1f0a47`

### Verifiable credentials
- Receives credentials through the OpenID for Verifiable Credential Issuance 1.0 pre-authorized code flow, in the SD-JWT VC format
- Shows each issuer as verified, confirmed by you, or unverified, and shows a credential as a card you can hold up to someone

### AutoFill, import and export
- One-time codes and passkeys suggested above the keyboard
- Import from Google Authenticator transfer QR codes, unencrypted Aegis, 2FAS, Bitwarden and Ente Auth exports, and lists of `otpauth://` links
- On iOS 26, import and export codes and passkeys with other apps through the system's Credential Exchange
- Encrypted backup files protected by a password you choose

### Privacy and security
- Secrets are stored in the iOS Keychain, and the app can be locked with Face ID, Touch ID, or the passcode
- No sign-up, ads, analytics, or tracking
- Codes are generated on the device and work offline. The app goes online only to reach a credential issuer when you accept a credential offer
- iCloud Keychain sync is off until you turn it on

## Requirements

- iPhone with iOS 17 or later. Credential Exchange import and export need iOS 26 or later.
- Xcode 27.2 to build. The unit tests run on iOS 26 or later.

## Building

1. Open `ios/AuthrimKeyring/AuthrimKeyring.xcodeproj` in Xcode.
2. To sign with your own team, change the team and these identifiers, which belong to the published app:
   - Bundle IDs: `com.authrim.keyring` (app) and `com.authrim.keyring.autofill` (AutoFill extension)
   - App group: `group.com.authrim.keyring`
   - Keychain access group: `$(AppIdentifierPrefix)com.authrim.keyring`

   The entitlements are in `ios/AuthrimKeyring/Config/`.
3. Run the `AuthrimKeyring` scheme on a simulator or a device.

To try AutoFill and passkeys, turn on Keyring in **Settings > General > AutoFill & Passwords**. In our testing, the iOS 26.5 simulator works for this, while the iOS 27.2 simulator does not register AutoFill entries. Safari offers passkeys and codes only on HTTPS pages.

## Testing

```bash
cd ios/AuthrimKeyring
xcodebuild test -project AuthrimKeyring.xcodeproj -scheme AuthrimKeyring \
  -destination 'platform=iOS Simulator,name=iPhone 18 Pro'
```

Use any simulator on iOS 26 or later. The tests use [Swift Testing](https://developer.apple.com/documentation/testing) and fictional data only.

## Project layout

| Path | Contents |
|---|---|
| `ios/AuthrimKeyring/AuthrimKeyring/` | The app: home screen, cards, import, backup, settings, and the credential wallet (`Wallet/`) |
| `ios/AuthrimKeyring/KeyringAutoFill/` | The AutoFill Credential Provider extension for codes and passkeys |
| `ios/AuthrimKeyring/Shared/` | Code shared by the app and the extension: models, OTP, passkeys (WebAuthn), Keychain storage |
| `ios/AuthrimKeyring/AuthrimKeyringTests/` | Unit tests |
| `ios/AuthrimKeyring/fastlane/` | App Store metadata and screenshot automation |

## Contributing

This repository does not accept pull requests from outside the project. Bug reports and feature requests are welcome in [Issues](https://github.com/authrim/authrim-keyring/issues).

Please do not report security problems in a public issue. Contact us through the [support page](https://authrim.com/keyring/support) instead.

## License

The source code is licensed under the [Apache License 2.0](LICENSE). Copyright 2026 Yuta Hoshina.

Some parts are not covered by it:

- The Cinzel font is under the SIL Open Font License 1.1.
- The bundled Public Suffix List is under the Mozilla Public License 2.0.
- The Authrim and Authrim Keyring names, the deer logo, the app icon and the wordmark are not licensed for use in other products.

See [NOTICE](NOTICE) for details.
