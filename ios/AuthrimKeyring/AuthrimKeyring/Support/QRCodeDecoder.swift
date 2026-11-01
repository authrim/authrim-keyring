import CoreImage
import Foundation

/// Reads QR code payloads from a still image, e.g. a screenshot of a setup page.
enum QRCodeDecoder {
    /// Runs synchronously; call it off the main actor for large photos.
    nonisolated static func payloads(in imageData: Data) -> [String] {
        guard let image = CIImage(data: imageData, options: [.applyOrientationProperty: true]),
              let detector = CIDetector(
                  ofType: CIDetectorTypeQRCode,
                  context: nil,
                  options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]
              )
        else { return [] }
        return detector.features(in: image)
            .compactMap { ($0 as? CIQRCodeFeature)?.messageString }
    }
}
