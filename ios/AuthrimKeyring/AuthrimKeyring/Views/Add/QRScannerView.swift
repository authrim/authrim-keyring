import AVFoundation
import SwiftUI
import UIKit

/// Live camera preview that reports decoded QR code payloads.
struct QRScannerView: UIViewControllerRepresentable {
    var isActive: Bool
    var onFound: (String) -> Void

    static var isAvailable: Bool {
        AVCaptureDevice.default(for: .video) != nil
    }

    func makeUIViewController(context: Context) -> ScannerViewController {
        let controller = ScannerViewController()
        controller.onFound = onFound
        return controller
    }

    func updateUIViewController(_ controller: ScannerViewController, context: Context) {
        controller.onFound = onFound
        controller.setActive(isActive)
    }

    static func dismantleUIViewController(_ controller: ScannerViewController, coordinator: ()) {
        controller.setActive(false)
    }
}

final class ScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onFound: ((String) -> Void)?

    private let session = AVCaptureSession()
    private let sessionQueue = DispatchQueue(label: "com.authrim.keyring.scanner")
    private var previewLayer: AVCaptureVideoPreviewLayer?
    private var rotationCoordinator: AVCaptureDevice.RotationCoordinator?
    private var rotationObservation: NSKeyValueObservation?
    private var isConfigured = false
    private var wantsActive = true

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        configure()
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.bounds
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        updateRunning()
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        stopSession()
    }

    func setActive(_ active: Bool) {
        guard active != wantsActive else { return }
        wantsActive = active
        updateRunning()
    }

    private func configure() {
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input)
        else { return }

        let output = AVCaptureMetadataOutput()
        session.beginConfiguration()
        session.addInput(input)
        guard session.canAddOutput(output) else {
            session.commitConfiguration()
            return
        }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]
        session.commitConfiguration()

        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.videoGravity = .resizeAspectFill
        layer.frame = view.bounds
        view.layer.addSublayer(layer)
        previewLayer = layer
        observeRotation(of: device, previewLayer: layer)
        isConfigured = true
    }

    /// Keeps the preview upright when an iPad is rotated.
    private func observeRotation(of device: AVCaptureDevice, previewLayer layer: AVCaptureVideoPreviewLayer) {
        let coordinator = AVCaptureDevice.RotationCoordinator(device: device, previewLayer: layer)
        rotationCoordinator = coordinator
        applyPreviewRotation(coordinator.videoRotationAngleForHorizonLevelPreview)
        rotationObservation = coordinator.observe(\.videoRotationAngleForHorizonLevelPreview, options: [.new]) { [weak self] _, change in
            guard let angle = change.newValue else { return }
            DispatchQueue.main.async { self?.applyPreviewRotation(angle) }
        }
    }

    private func applyPreviewRotation(_ angle: CGFloat) {
        guard let connection = previewLayer?.connection, connection.isVideoRotationAngleSupported(angle) else { return }
        connection.videoRotationAngle = angle
    }

    private func updateRunning() {
        if wantsActive {
            startSession()
        } else {
            stopSession()
        }
    }

    private func startSession() {
        guard isConfigured else { return }
        let session = session
        sessionQueue.async {
            if !session.isRunning { session.startRunning() }
        }
    }

    private func stopSession() {
        let session = session
        sessionQueue.async {
            if session.isRunning { session.stopRunning() }
        }
    }

    nonisolated func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        let payload = metadataObjects
            .compactMap { ($0 as? AVMetadataMachineReadableCodeObject)?.stringValue }
            .first
        guard let payload else { return }
        // The delegate queue is `.main`.
        MainActor.assumeIsolated {
            guard wantsActive else { return }
            onFound?(payload)
        }
    }
}
