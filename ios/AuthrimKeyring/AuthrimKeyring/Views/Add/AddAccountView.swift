import AVFoundation
import PhotosUI
import SwiftUI

/// Entry point for adding a TOTP account by camera, photo or manual entry.
struct AddAccountView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase

    @State private var candidate: OTPAccount?
    @State private var isEnteringManually = false
    @State private var photoItem: PhotosPickerItem?
    @State private var isPickingPhoto = false
    @State private var isImportingPhoto = false
    @State private var errorMessage: String?
    @State private var cameraStatus = AVCaptureDevice.authorizationStatus(for: .video)

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

                Text("Point the camera at the QR code shown by the service you are setting up.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)

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
            .navigationDestination(isPresented: $isEnteringManually) {
                ManualEntryView { dismiss() }
            }
            .alert("Cannot Add Account", isPresented: hasError) {
                Button("OK") { errorMessage = nil }
            } message: {
                Text(errorMessage ?? "")
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
        candidate == nil && !isEnteringManually && errorMessage == nil
            && !isPickingPhoto && !isImportingPhoto
    }

    private var hasError: Binding<Bool> {
        Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })
    }

    private func handle(_ payload: String) {
        guard candidate == nil, !isEnteringManually, errorMessage == nil else { return }
        do {
            candidate = try OTPAuthURI.parse(payload)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func importPhoto(_ item: PhotosPickerItem) async {
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
        if let payload = payloads.first(where: { $0.lowercased().hasPrefix("otpauth:") }) ?? payloads.first {
            handle(payload)
        } else {
            errorMessage = String(localized: "No QR code was found in the photo.")
        }
    }
}
