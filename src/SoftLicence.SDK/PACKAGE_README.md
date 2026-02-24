# SoftLicence.SDK

The official SDK for integrating **SoftLicence** protection into your .NET applications (WPF, Console, WinForms).

SoftLicence provides an industrial-grade licensing solution using RSA-4096 cryptography and hardware fingerprinting (HWID).

## 🚀 Key Features

- **RSA-4096 Signing**: Ensure your license files are tamper-proof.
- **Hardware Locking**: Bind licenses to specific machines using unique hardware IDs.
- **Trial Support**: Easily implement auto-trial periods for your software.
- **Online & Offline Validation**: Robust verification logic even without an active internet connection.
- **Typed Results**: Modern API with clear success/error states.
- **Custom Parameters**: Inject typed per-license-type parameters (features, limits) signed into the license file.
- **Device Transfer**: Built-in deactivation and email-reset flows for license transfers between machines.

## 🛠️ Quick Start

### 1. Initialize the Client

```csharp
var client = new SoftLicenceClient("https://your-licence-server.com", "YOUR_PUBLIC_KEY_XML");
```

### 2. Activate a License

```csharp
var result = await client.ActivateAsync("YOUR-LICENSE-KEY", "YourAppName",
    customerEmail: "user@example.com",   // optional — stored on the server
    customerName: "John Doe");           // optional — stored on the server
if (result.IsSuccess)
{
    File.WriteAllText("license.lic", result.LicenseFile);
}
```

### 3. Request a Trial

```csharp
var result = await client.RequestTrialAsync("YourAppName",
    customerEmail: "user@example.com",   // optional
    customerName: "John Doe");           // optional
if (result.IsSuccess)
{
    Console.WriteLine("Trial activated!");
    File.WriteAllText("license.lic", result.LicenseFile);
}
```

### 4. Check License Status

```csharp
var status = await client.CheckStatusAsync("YOUR_LICENSE_KEY", "YourAppName");
if (status.IsValid)
{
    Console.WriteLine("License is valid!");
}
```

### 5. Transfer to Another Machine

```csharp
// Option A — Machine is accessible (unlinks this seat only, instant)
var result = await client.DeactivateAsync("YOUR-LICENSE-KEY", "YourAppName");
if (result.IsSuccess)
{
    // Delete local license.lic, user can activate on the new machine
}

// Option B — Machine is lost/inaccessible (unlinks ALL seats via email)
bool sent = await client.ResetRequestAsync("YOUR-LICENSE-KEY", "YourAppName");
// User receives a 6-digit code by email (expires in 15 min)
bool confirmed = await client.ResetConfirmAsync("YOUR-LICENSE-KEY", "YourAppName", "123456");
```

### 5. Read Custom Parameters

Parameters defined per license type on the server are signed into the license and accessible via `GetParam<T>`:

```csharp
var validation = client.ValidateLocal(licenseFile, hardwareId);
if (validation.IsValid)
{
    int maxAccounts = validation.License!.GetParam<int>("maxAccounts", fallback: 1);
    bool withLogo   = validation.License!.GetParam<bool>("withLogo", fallback: true);
}
```

Supported types: `string`, `int`, `long`, `double`, `bool`, `Guid`.

## 📚 Documentation

For full integration guides and server setup, please visit the [Official Repository](https://github.com/feelautom/SoftLicence).

## 📄 License

Distributed under the Elastic License 2.0. See LICENSE file for details.
