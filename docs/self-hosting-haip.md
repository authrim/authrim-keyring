# Self-hosting HAIP in Keyring

Keyring can receive an Authrim administrator credential and sign in to the Authrim admin console with it, using the OpenID4VC
HAIP 1.0 profile. The Authrim project runs a wallet provider only for its own use. If you distribute your own build, you run
your own provider and set a few build settings; no source change is needed.

## What you create

1. **An Apple Developer app** (your team ID and bundle ID) with the App Attest capability, and, for the https redirect, the
   Associated Domains capability (`applinks:<your-domain>`).
2. **A provider CA** (offline root, online intermediate, ES256 leaf, no extended key usage) and a **wallet provider service** that
   implements the contract in `20261124-keyring-wallet-provider-contract.md` of the Authrim documentation (App Attest registration and
   assertions in, a wallet attestation and a key attestation out).
3. **An app link**: host `/.well-known/apple-app-site-association` for `/oauth/callback` (or your path) on your domain.
4. **A wallet allowlist entry** in your Authrim OP (admin API, with step-up): `clientId` (default `keyring-ios`), the provider root as
   `attestationRoots` and `keyAttestationRoots`, and the https redirect URI.

## Build settings

Set these user-defined build settings (for example in an `.xcconfig`); each fills a key of `Config/AuthrimKeyring-Info.plist`.
Leave them empty and the build runs without HAIP, exactly as before.

| Setting | Meaning |
|---|---|
| `WALLET_PROVIDER_ORIGIN` | https origin of your provider |
| `WALLET_PROVIDER_ISSUER` | the provider's `iss` (defaults to the origin) |
| `WALLET_PROVIDER_ROOT_1`, `_2` | base64 DER of the provider roots the wallet trusts (two for rotation) |
| `WALLET_CREDENTIAL_ISSUER_1`, `_2` | credential issuer identifiers (your Authrim tenants, exact `https://...`) the provider attests for |
| `WALLET_CLIENT_ID` | the attestation `sub` / allowlist `clientId` (default `keyring-ios`) |
| `WALLET_REDIRECT_URI` | the https app-link callback of the authorization code flow |
| `AUTHRIM_ROOT_1`, `_2` | base64 DER of the Authrim root CA that signs your issuer and verifier certificates |
| `AUTHRIM_CONSOLE_HOST_1` | only if the admin console is on another host than the issuer |
| `WALLET_PROVIDER_KIND` | `appAttest` (default). `debugUnattested` works only in debug builds, for a provider that verifies nothing |

A release build refuses to start HAIP issuance when the provider origin, the pinned roots or the issuer list is empty. There is no
fallback to unattested requests. The `debugUnattested` provider kind is compiled out of release builds.

## Testing without Apple setup

Use a debug build with `WALLET_PROVIDER_KIND=debugUnattested` against a test provider that skips App Attest verification and signs
with a throw-away CA. The simulator does not support App Attest. Switch to `appAttest` on a real device before any release; TestFlight
builds use App Attest's production environment.

## Trust

The wallet trusts only roots pinned in the build: the provider roots (to validate attestations before sending them on) and the Authrim
roots (to validate the issuer's `x5c` and the console's signed sign-in request). It never installs a root from an offer, credential or
response. Rolling a root is an app release; pin two for overlap.
