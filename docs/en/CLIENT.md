# Client Documentation (SoftLicence.UI & Core)

The client side locks access to a WPF application and manages secure communication with the server.

## Technical Integration (Lifecycle)

For robust protection, integration should be done in the `App.xaml.cs` file before the main window is even displayed.

### 1. Asynchronous Initialization
The system uses an asynchronous approach to avoid blocking the UI during file loading or network calls.

```csharp
protected override async void OnStartup(StartupEventArgs e)
{
    base.OnStartup(e);

    // 1. Create the ViewModel
    var vm = new LicenseActivationViewModel(PUBLIC_KEY, "ProductName", "https://your-server.com");

    // 2. Load and verify (Offline + Online)
    await vm.InitializeAsync();

    // 3. Window orchestration
    if (vm.IsLicensed) {
        new MainWindow().Show();
    } else {
        new Window { Content = new LicenseActivationView { DataContext = vm } }.ShowDialog();
    }
}
```

### 2. Live Monitoring (Timer)
The `LicenseActivationViewModel` includes an **automatic timer** (every 2 hours by default).
- If the license is revoked on the server while the user is working, the `IsLicensed` property will change to `false`.
- **Reactive Architecture**: It is recommended to subscribe to `PropertyChanged` in your `App.xaml.cs` to react instantly and close the application if the license is revoked during use.

### 3. Auto-Activation (Trial Mode)
If you don't want to ask the user for a key on first launch, you can call the auto-generation API:

**Endpoint**: `POST /api/activation/trial`
**Payload**:
```json
{
  "HardwareId": "ABC-123-HID",
  "AppName": "YourApp",
  "TypeSlug": "TRIAL"
}
```
The server will return the signed license file content directly. If it's a reinstallation, the server will return the existing license.

## Piracy Protection

### Obfuscation (Obfuscar)
.NET code is very easy to decompile. To protect your license logic:
1. Add the `Obfuscar` NuGet package.
2. Configure the `obfuscar.xml` file.
3. Make sure obfuscation runs in **Release** mode.
This will make your DLL unreadable by tools like `dnSpy`.

### Hardware Locking (Hardware ID)
The `HardwareID` is a unique fingerprint of the client's PC.
- A license activated on "PC A" cannot be copied to "PC B".
- The server will return a `HARDWARE_MISMATCH` error.
- **Reset**: The administrator can reset this binding via the dashboard ("Reset HWID"). The client can also do it themselves (Self-Service) via the email reset endpoints.

## Local Storage
The signed license file is stored at:
`%AppData%/Local/[AppName]/license.lic`
It is a cryptographically signed JSON encoded in Base64.

### Available Properties in `LicenseModel`
Once the license is validated, you can access the following information:
- `LicenseKey`: The activation key.
- `TypeSlug`: The type (e.g., PRO, TRIAL).
- `Reference`: Your custom field (e.g., Order ID).
- `ExpirationDate`: Validity expiration date.
- `Features`: Dictionary of optional features.
