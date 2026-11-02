import PhotosUI
import SwiftUI

/// Chooses the home screen wallpaper: the system background, a preset, or a photo.
struct WallpaperSettingsView: View {
    @Environment(WallpaperStore.self) private var wallpaper

    @State private var photoItem: PhotosPickerItem?
    @State private var isLoadingPhoto = false
    @State private var photoError = false

    private let columns = [GridItem(.adaptive(minimum: 72), spacing: 12)]

    var body: some View {
        Form {
            // Photo controls come first: they are adjusted while watching the preview.
            Section {
                WallpaperPreview()
                    .frame(maxWidth: .infinity)
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets(top: 8, leading: 0, bottom: 8, trailing: 0))
            }

            Section {
                PhotosPicker(selection: $photoItem, matching: .images) {
                    Label(wallpaper.photo == nil ? "Choose Photo" : "Change Photo", systemImage: "photo")
                }
                .disabled(isLoadingPhoto)
                if wallpaper.settings.kind == .photo {
                    LabeledContent("Blur") {
                        Slider(value: blurBinding, in: 0...1)
                            .frame(maxWidth: 200)
                    }
                    LabeledContent("Dim") {
                        Slider(value: dimBinding, in: 0...WallpaperSettings.maximumDim)
                            .frame(maxWidth: 200)
                    }
                    Button("Remove Photo", role: .destructive) {
                        wallpaper.select(.system)
                    }
                    .disabled(isLoadingPhoto)
                }
            } header: {
                Text("Photo")
            } footer: {
                Text("The photo stays on this device. It is not included in iCloud sync or Keyring backups.")
            }

            Section {
                Toggle("Glass Cards", isOn: glassBinding)
                if wallpaper.settings.glassCards {
                    LabeledContent("Transparency") {
                        Slider(value: transparencyBinding, in: WallpaperSettings.cardTransparencyRange)
                            .frame(maxWidth: 200)
                    }
                }
            } header: {
                Text("Cards")
            } footer: {
                Text("Lets the wallpaper show through the cards.")
            }

            Section("Wallpapers") {
                LazyVGrid(columns: columns, spacing: 16) {
                    swatch(for: .system, name: "Default") { Color(.systemGroupedBackground) }
                    ForEach(WallpaperPreset.all) { preset in
                        swatch(for: .preset(preset.id), name: preset.name) { WallpaperPresetFill(preset: preset, thumbnail: true) }
                    }
                }
                .padding(.vertical, 8)
                .disabled(isLoadingPhoto)
            }
        }
        .navigationTitle("Wallpaper")
        .navigationBarTitleDisplayMode(.inline)
        .onChange(of: photoItem) { _, item in
            guard let item else { return }
            Task { await loadPhoto(item) }
        }
        .alert("Cannot Use Photo", isPresented: $photoError) {
            Button("OK") {}
        } message: {
            Text("This photo could not be loaded.")
        }
    }

    private func swatch(
        for kind: WallpaperSettings.Kind,
        name: LocalizedStringResource,
        @ViewBuilder fill: () -> some View
    ) -> some View {
        let isSelected = wallpaper.settings.kind == kind
        return Button {
            wallpaper.select(kind)
        } label: {
            VStack(spacing: 6) {
                fill()
                    .frame(width: 56, height: 80)
                    .clipShape(.rect(cornerRadius: 12, style: .continuous))
                    .overlay {
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .strokeBorder(isSelected ? Color.accentColor : Color.secondary.opacity(0.3), lineWidth: isSelected ? 3 : 1)
                    }
                Text(name)
                    .font(.caption)
                    .foregroundStyle(isSelected ? .primary : .secondary)
                    .lineLimit(1)
            }
            .frame(minHeight: 44)
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(isSelected ? .isSelected : [])
    }

    private var blurBinding: Binding<Double> {
        Binding(get: { wallpaper.settings.blur }, set: { wallpaper.setBlur($0) })
    }

    private var glassBinding: Binding<Bool> {
        Binding(get: { wallpaper.settings.glassCards }, set: { wallpaper.setGlassCards($0) })
    }

    private var transparencyBinding: Binding<Double> {
        Binding(get: { wallpaper.settings.cardTransparency }, set: { wallpaper.setCardTransparency($0) })
    }

    private var dimBinding: Binding<Double> {
        Binding(get: { wallpaper.settings.dim }, set: { wallpaper.setDim($0) })
    }

    private func loadPhoto(_ item: PhotosPickerItem) async {
        isLoadingPhoto = true
        defer {
            isLoadingPhoto = false
            photoItem = nil
        }
        let choice = wallpaper.beginPhotoChoice()
        guard let data = try? await item.loadTransferable(type: Data.self),
              await wallpaper.setPhoto(data, choice: choice)
        else {
            photoError = true
            return
        }
    }
}

/// A small home screen drawn on the current wallpaper.
private struct WallpaperPreview: View {
    @Environment(WallpaperStore.self) private var wallpaper
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: 24, style: .continuous)
        VStack(alignment: .leading, spacing: 8) {
            Text("Keyring")
                .font(.title2.bold())
                .foregroundStyle(.primary)
                .padding(.bottom, 4)
            ForEach([0, 1, 10], id: \.self) { index in
                card(CardColor.presets[index])
            }
            Spacer(minLength: 0)
        }
        .padding(16)
        .frame(width: 170, height: 300)
        .background { WallpaperFill() }
        .clipShape(shape)
        .overlay { shape.strokeBorder(Color.secondary.opacity(0.3)) }
        .environment(\.colorScheme, wallpaper.colorScheme ?? colorScheme)
        .accessibilityHidden(true)
    }

    private func card(_ color: CardColor) -> some View {
        let shape = RoundedRectangle(cornerRadius: 10, style: .continuous)
        let opacity = wallpaper.cardGlass(in: wallpaper.colorScheme ?? colorScheme)?.opacity
        return Group {
            if let opacity {
                GlassCardFace(shape: shape, tint: Color(color), opacity: opacity)
            } else {
                shape.fill(Color(color))
            }
        }
        .frame(height: 34)
    }
}
