# SoftLicence.SDK

The official SDK for integrating **SoftLicence** protection into your .NET applications (WPF, Console, WinForms).

SoftLicence provides an industrial-grade licensing solution using RSA-4096 cryptography and hardware fingerprinting (HWID).

## Structured server errors in SDK 1.1.13

Canonical integration guide: `docs-public/sdk-1.1.13-error-contract-integration.md` in the SoftLicence repository.

Activation and trial failures now prefer the server's canonical `X-SoftLicence-Error-Code` value and expose its opaque support correlation through `ActivationResult.CorrelationId`. Unknown structured values fail closed as `ServerError`; localized text parsing is used only with legacy servers that do not send the structured code header. `ActivationResult.UsedLegacyErrorFallback` can be measured without logging response bodies.

This release does not change HWID authority: legacy and V2 values continue to be sent together, and V2 remains observation-only.

Structured JSON responses keep the deprecated `errorMessage` property as an alias of the canonical `message` property for contract-version-1 compatibility. Applications embedding the SDK DLL must update both their package reference and embedded resource path when adopting 1.1.13.

## 🚀 Key Features

- **RSA-4096 Signing**: Ensure your license files are tamper-proof.
- **Hardware Locking**: Bind licenses to specific machines using unique hardware IDs.
- **Trial Support**: Easily implement auto-trial periods for your software.
- **Online & Offline Validation**: Robust verification logic even without an active internet connection.
- **Typed Results**: Modern API with clear success/error states.
- **Custom Parameters**: Inject typed per-license-type parameters (features, limits) signed into the license file.
- **Plugin/Sub-product Licenses**: Signed plugin metadata for applications that license optional modules.
- **Device Transfer**: Built-in deactivation and email-reset flows for license transfers between machines.

## HWID compatibility introduced in SDK 1.1.11

SDK 1.1.10 changed the primary disk selection to `Win32_DiskDrive WHERE Index=0`.
Although more deterministic, that change could produce a different HWID on machines
already licensed with SDK 1.1.8 or 1.1.9.

SDK 1.1.11 restores the existing licensing contract and exposes the deterministic value
separately for observation:

| API | Contract |
| --- | --- |
| `HardwareInfo.GetHardwareId()` | Returns the legacy contractual HWID compatible with SDK 1.1.8/1.1.9. Continue to use this value for licensing and local validation. |
| `HardwareInfo.GetStableHardwareId()` | Returns the nullable stable/V2 observation based on disk `Index=0`. It returns `null` when that disk value cannot be determined. |
| `HardwareInfo.GetHardwareIdMigrationInfo()` | Returns both values and the availability/divergence flags described below. |

`HardwareIdMigrationInfo` exposes:

- `LegacyHardwareId`: the current contractual license identity.
- `StableHardwareId`: the optional V2 observation value.
- `HasStableHardwareId`: whether V2 could be calculated.
- `HasDistinctHardwareIds`: whether the available V2 value differs from legacy.

`SoftLicenceClient` keeps `HardwareId` set to the legacy value in activation, trial, and
status payloads. When V2 is available, the client also sends `HardwareIdV2` and its
metadata as secondary observation fields. There is no fallback from an unavailable V2
value to legacy in those V2 fields.

> **Important:** V2 is observation-only in SDK 1.1.11. Do not use it as the primary
> license identity, an alternate validation identity, a fallback after a hardware
> mismatch, or a way to bypass licensing decisions. This release performs no automatic
> migration and does not change seats, quotas, activations, or the contractual HWID.
> A future switch to V2 requires an explicitly validated server-side migration.

## Signed expiration contract

The root `IsExpired` property in a license file is a signed compatibility snapshot.
It remains part of the JSON contract so licenses issued by earlier SDK versions keep
the same signed bytes, but it is never trusted to decide whether a license is valid.

Local validation first verifies the RSA signature using the stored snapshot. Only
after that verification succeeds does the SDK evaluate `ExpirationDate` against the
current UTC time. A signed `IsExpired: false` therefore cannot keep a license valid
past its expiration date, and an altered snapshot or expiration date still fails
signature verification.

The existing boundary is preserved: a license is valid at the exact
`ExpirationDate` instant and becomes expired immediately after it. Invalid signatures
remain higher priority than the expiration diagnostic.

## Signed license JSON contract

`LicenseService.GenerateLicense` signs the UTF-8 JSON representation of
`LicenseModel` with the root `Signature` property set to an empty string. The
final license file is the Base64 transport encoding of that JSON after the RSA
signature has been inserted into that root property only.

The generated JSON keeps every other signed byte unchanged. In particular:

- the RSA signature is stored as raw Base64, including `+`, `/`, and `=`;
- Unicode and JSON-escaped characters keep the representation that was signed;
- the root property order and all signed values remain part of the contract;
- during generation, the root `Signature` property must occur exactly once as
  an empty string; an absent, duplicated, non-string, or otherwise ambiguous
  generation contract is rejected rather than guessed.

The exact feature key `Signature` is reserved for this root cryptographic
contract. Do not use it in `LicenseModel.Features`; generation fails explicitly
before signing if that exact key is present. Other feature keys are unaffected.

Treat a generated license file as an opaque signed value. Do not decode and
reformat, reorder, normalize, trim, or reserialize its JSON before passing it to
a validator. Supported managed validators preserve documented historical
compatibility, while exact-byte native validators require the stored JSON
representation to match the bytes covered by the signature.

## Local validation and hardware binding

`LicenseService.ValidateLicense` keeps its historical tuple-based API. Its optional
`currentHardwareId` argument may be omitted only for a signed license whose
`HardwareId` is null or empty, which explicitly represents a license without hardware
binding. A hardware-bound license fails closed when the current HWID is null, empty,
or whitespace. A whitespace-only signed binding is rejected as an invalid contract.

Use the additive detailed API when code needs a stable failure reason:

```csharp
LicenseValidationResult validation = LicenseService.ValidateLicenseDetailed(
    licenseFile,
    publicKeyXml,
    HardwareInfo.GetHardwareId());

if (!validation.IsValid &&
    validation.ErrorCode == LicenseValidationErrorCode.HardwareIdRequired)
{
    // The signed license requires a current contractual HWID.
}
```

Hardware IDs are compared exactly. Do not trim, rewrite, or substitute
`GetStableHardwareId()` after a mismatch. The stable/V2 value remains an
observation-only migration signal.

### Observation-first example

```csharp
string licenseHardwareId = HardwareInfo.GetHardwareId();
HardwareIdMigrationInfo migration = HardwareInfo.GetHardwareIdMigrationInfo();

var hardwareIdObservation = new
{
    HardwareId = licenseHardwareId,
    LegacyHardwareId = migration.LegacyHardwareId,
    StableHardwareId = migration.StableHardwareId,
    HasStableHardwareId = migration.HasStableHardwareId,
    HasDistinctHardwareIds = migration.HasDistinctHardwareIds
};

// Keep licenseHardwareId as the only identity used for license validation.
// Send hardwareIdObservation only to trusted, access-controlled telemetry.
// Do not write complete HWIDs to general-purpose application logs.
```

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
var status = await client.CheckStatusAsync(
    "YOUR_LICENSE_KEY",
    "YourAppName",
    appVersion: "1.1.9"); // optional, enables server-side minimum-version checks
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

### 6. Read Plugin / Sub-product Metadata

SDK `1.1.9` adds optional signed metadata for plugin or sub-product licenses:

```csharp
var validation = client.ValidateLocal(licenseFile, hardwareId);
if (validation.IsValid)
{
    string? pluginId = validation.License!.PluginId;
    string? pluginVersion = validation.License.PluginVersion;
    string? minAppVersion = validation.License.MinAppVersion;
    string[]? allowedFeatures = validation.License.AllowedFeatures;
}
```

Compatibility rule: standard product licenses omit these fields when they are `null`.
Applications that do not use plugin/sub-product licenses can ignore them safely.

## 📚 Documentation

For full integration guides and server setup, please visit the [Official Repository](https://github.com/feelautom/SoftLicence).

## 📄 License

Distributed under the Elastic License 2.0. See LICENSE file for details.
