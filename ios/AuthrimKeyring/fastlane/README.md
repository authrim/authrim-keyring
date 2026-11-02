fastlane documentation
----

# Installation

Make sure you have the latest version of the Xcode command line tools installed:

```sh
xcode-select --install
```

For _fastlane_ installation instructions, see [Installing _fastlane_](https://docs.fastlane.tools/#installing-fastlane)

# Available Actions

## iOS

### ios screenshots

```sh
[bundle exec] fastlane ios screenshots
```

Takes the App Store screenshots with fictional accounts. Options: devices (comma-separated simulator names), wait (seconds before each shot), derived_data (a build folder to reuse).

### ios upload_metadata

```sh
[bundle exec] fastlane ios upload_metadata
```

Sends the listing text in metadata/ to App Store Connect, without screenshots or a build.

### ios upload_listing

```sh
[bundle exec] fastlane ios upload_listing
```

Sends the listing text and the screenshots, replacing the screenshots there.

----

This README.md is auto-generated and will be re-generated every time [_fastlane_](https://fastlane.tools) is run.

More information about _fastlane_ can be found on [fastlane.tools](https://fastlane.tools).

The documentation of _fastlane_ can be found on [docs.fastlane.tools](https://docs.fastlane.tools).
