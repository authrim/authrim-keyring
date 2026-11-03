import AVFoundation
import PhotosUI
import SwiftUI
import UniformTypeIdentifiers

/// Entry point for adding a TOTP account by camera, photo or manual entry.
struct AddAccountView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.openURL) private var openURL

    @State private var candidate: OTPAccount?
    /// A credential offer the camera found; handed to the wallet instead of the one-time code flow.
    @State private var credentialOffer: IncomingOffer?
    @State private var isEnteringManually = false
    @State private var photoItem: PhotosPickerItem?
    @State private var isPickingPhoto = false
    @State private var isImportingPhoto = false
    @State private var errorMessage: String?
    @State private var cameraStatus = AVCaptureDevice.authorizationStatus(for: .video)
    /// A Google Authenticator transfer whose remaining QR codes are still to be scanned.
    @State private var migration: MigrationProgress?
    @State private var imported: ImportedAccounts?
    @State private var isShowingImported = false
    @State private var isChoosingFile = false
    /// A chosen file or pasted text being read.
    @State private var isReadingImport = false
    /// A passkey sign-in code for another device being handed to iOS.
    @State private var isHandingOffSignIn = false
    @State private var isShowingCameraHint = false
    /// The camera keeps seeing a code after the hint closes, so it is handed off only once.
    @State private var handedOffSignIn: URL?

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                scanner
                    .frame(maxWidth: .infinity)
                    .aspectRatio(1, contentMode: .fit)
                    .clipShape(.rect(cornerRadius: 20))
                    .overlay {
                        RoundedRectangle(cornerRadius: 20)
                            .strokeBorder(Color.secondary.opacity(0.3))
                    }

                if let migration {
                    migrationBanner(migration)
                } else {
                    Text("Point the camera at the QR code shown by the service you are setting up.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }

                VStack(spacing: 12) {
                    Button {
                        isPickingPhoto = true
                    } label: {
                        Label("Choose QR Code from Photos", systemImage: "photo")
                            .frame(maxWidth: .infinity)
                    }
                    .disabled(isImportingPhoto)
                    Button {
                        isEnteringManually = true
                    } label: {
                        Label("Enter Setup Key", systemImage: "keyboard")
                            .frame(maxWidth: .infinity)
                    }
                    Menu {
                        Button("Choose File", systemImage: "folder") { isChoosingFile = true }
                        Button("Paste from Clipboard", systemImage: "doc.on.clipboard") { importClipboard() }
                    } label: {
                        Label("Import from Another App", systemImage: "square.and.arrow.down")
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.bordered)
                .controlSize(.large)

                Spacer(minLength: 0)
            }
            .padding()
            .navigationTitle("Add Account")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
            .navigationDestination(item: $candidate) { account in
                ConfirmAccountView(candidate: account) { dismiss() }
            }
            .navigationDestination(item: $credentialOffer) { offer in
                CredentialOfferView(offer: offer.text) { dismiss() }
            }
            .navigationDestination(isPresented: $isEnteringManually) {
                ManualEntryView { dismiss() }
            }
            .navigationDestination(isPresented: $isShowingImported) {
                if let imported {
                    ImportPreviewView(imported: imported) { dismiss() }
                }
            }
            .fileImporter(
                isPresented: $isChoosingFile,
                allowedContentTypes: [.json, .plainText, .text, .data]
            ) { result in
                switch result {
                case .success(let url):
                    // Set before the picker closes, so scanning does not resume in between.
                    isReadingImport = true
                    Task { await importFile(url) }
                case .failure(let error): errorMessage = error.localizedDescription
                }
            }
            .alert("Cannot Add Account", isPresented: hasError) {
                Button("OK") { errorMessage = nil }
            } message: {
                Text(errorMessage ?? "")
            }
            .alert("Scan with the Camera App", isPresented: $isShowingCameraHint) {
                Button("OK") {}
            } message: {
                Text("This QR code is for signing in on another device with a passkey. Scan it with the Camera app or the Code Scanner in Control Center, then choose Keyring.")
            }
            .photosPicker(isPresented: $isPickingPhoto, selection: $photoItem, matching: .images)
            .onChange(of: photoItem) { _, item in
                guard let item else { return }
                Task { await importPhoto(item) }
            }
            .onChange(of: scenePhase) { _, phase in
                // Pick up a permission granted in the Settings app.
                if phase == .active {
                    cameraStatus = AVCaptureDevice.authorizationStatus(for: .video)
                }
            }
            .task {
                if cameraStatus == .notDetermined {
                    _ = await AVCaptureDevice.requestAccess(for: .video)
                    cameraStatus = AVCaptureDevice.authorizationStatus(for: .video)
                }
            }
        }
    }

    @ViewBuilder
    private var scanner: some View {
        switch cameraStatus {
        case .authorized where QRScannerView.isAvailable:
            // Pause scanning while another screen or alert is on top.
            QRScannerView(isActive: isScanning) { payload in
                handle(payload)
            }
        case .authorized:
            scannerPlaceholder(
                systemImage: "camera",
                message: String(localized: "A camera is not available on this device.")
            )
        case .notDetermined:
            scannerPlaceholder(systemImage: "camera", message: nil)
        default:
            VStack(spacing: 12) {
                scannerPlaceholder(
                    systemImage: "camera.badge.ellipsis",
                    message: String(localized: "Allow camera access in Settings to scan QR codes.")
                )
                if let url = URL(string: UIApplication.openSettingsURLString) {
                    Link("Open Settings", destination: url)
                        .padding(.bottom)
                }
            }
            .background(Color(.secondarySystemBackground))
        }
    }

    private func scannerPlaceholder(systemImage: String, message: String?) -> some View {
        VStack(spacing: 12) {
            Image(systemName: systemImage)
                .font(.largeTitle)
                .foregroundStyle(.secondary)
            if let message {
                Text(message)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(.secondarySystemBackground))
    }

    /// Scanning pauses while another screen, alert or photo import is in progress.
    private var isScanning: Bool {
        candidate == nil && credentialOffer == nil && !isEnteringManually && errorMessage == nil
            && !isPickingPhoto && !isImportingPhoto && !isShowingImported && !isChoosingFile && !isReadingImport
            && !isHandingOffSignIn && !isShowingCameraHint
    }

    private func migrationBanner(_ progress: MigrationProgress) -> some View {
        VStack(spacing: 8) {
            Text("Scanned \(progress.scannedCount) of \(progress.size) codes from Google Authenticator. Scan the next one.")
                .font(.callout)
                .multilineTextAlignment(.center)
            HStack {
                Button("Start Over") { migration = nil }
                Button("Review Scanned Accounts") { show(progress.accounts) }
            }
            .font(.callout)
        }
    }

    private var hasError: Binding<Bool> {
        Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })
    }

    private func handle(_ payload: String) {
        guard candidate == nil, credentialOffer == nil, !isEnteringManually, errorMessage == nil, !isShowingImported,
              !isHandingOffSignIn, !isShowingCameraHint else { return }
        if let url = HybridSignInLink.url(from: payload) {
            if url != handedOffSignIn { handOffSignIn(url) }
            return
        }
        if CredentialOfferLink.isOffer(payload) {
            credentialOffer = IncomingOffer(text: payload)
            return
        }
        if GoogleAuthMigration.isMigrationURI(payload) {
            handleMigration(payload)
            return
        }
        do {
            candidate = try OTPAuthURI.parse(payload)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    /// Lets iOS sign in on the other device, as the Camera app does with this code.
    /// If iOS does not take it from an app, the user is pointed to the Camera app.
    private func handOffSignIn(_ url: URL) {
        handedOffSignIn = url
        isHandingOffSignIn = true
        openURL(url) { accepted in
            if accepted {
                // Signing in is not adding an account, so nothing is left to do here.
                // Scanning stays paused while the sheet closes.
                dismiss()
            } else {
                isHandingOffSignIn = false
                isShowingCameraHint = true
            }
        }
    }

    private func handleMigration(_ payload: String) {
        let batch: GoogleAuthMigration.Batch
        do {
            batch = try GoogleAuthMigration.parse(payload)
        } catch {
            errorMessage = error.localizedDescription
            return
        }
        if var progress = migration {
            guard progress.belongs(batch) else {
                errorMessage = String(localized: "This code is from a different transfer. Tap Start Over to scan a new transfer.")
                return
            }
            // The camera keeps seeing the same code until the next one is shown.
            guard progress.batches[batch.index] == nil else { return }
            do {
                try progress.add(batch)
            } catch {
                errorMessage = error.localizedDescription
                return
            }
            migration = progress
        } else {
            migration = MigrationProgress(first: batch)
        }
        if let progress = migration, progress.isComplete {
            show(progress.accounts)
        }
    }

    private func show(_ accounts: ImportedAccounts) {
        migration = nil
        imported = accounts
        isShowingImported = true
    }

    private func importClipboard() {
        guard let text = UIPasteboard.general.string, !text.isEmpty else {
            errorMessage = String(localized: "The clipboard does not contain any text.")
            return
        }
        isReadingImport = true
        Task {
            let result = await Task.detached(priority: .userInitiated) {
                Result { () throws(ImportError) in try AppExportReader.readKeyURIs(text) }
            }.value
            finishImport(result.mapError { $0 as Error })
        }
    }

    private func importFile(_ url: URL) async {
        let result = await Task.detached(priority: .userInitiated) { () -> Result<ImportedAccounts, Error> in
            let isScoped = url.startAccessingSecurityScopedResource()
            defer { if isScoped { url.stopAccessingSecurityScopedResource() } }
            return Result {
                let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
                guard size <= AppExportReader.maximumFileSize else { throw ImportError.tooLarge }
                return try AppExportReader.read(Data(contentsOf: url))
            }
        }.value
        finishImport(result)
    }

    private func finishImport(_ result: Result<ImportedAccounts, Error>) {
        isReadingImport = false
        switch result {
        case .success(let accounts): show(accounts)
        case .failure(let error): errorMessage = error.localizedDescription
        }
    }

    private func importPhoto(_ item: PhotosPickerItem) async {
        // Choosing a photo is a deliberate try, so the same sign-in code is handed off again.
        handedOffSignIn = nil
        isImportingPhoto = true
        defer {
            isImportingPhoto = false
            photoItem = nil
        }
        guard let data = try? await item.loadTransferable(type: Data.self) else {
            errorMessage = String(localized: "The photo could not be loaded.")
            return
        }
        let payloads = await Task.detached(priority: .userInitiated) {
            QRCodeDecoder.payloads(in: data)
        }.value
        // Prefer a setup code if the image contains several QR codes.
        if let payload = payloads.first(where: { $0.lowercased().hasPrefix("otpauth") }) ?? payloads.first(where: CredentialOfferLink.isOffer) ?? payloads.first {
            handle(payload)
        } else {
            errorMessage = String(localized: "No QR code was found in the photo.")
        }
    }
}
