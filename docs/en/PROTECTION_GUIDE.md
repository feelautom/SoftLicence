# Guide: Protecting a New Application

This guide explains step by step how to turn a standard WPF application into a version protected by SoftLicence.

## Step 1: Server Setup
1. Log into your SoftLicence dashboard.
2. Go to the **Products** tab.
3. Click "Create" for your new software (e.g., "MyTool v1").
4. **Copy the Public XML Key** (the one starting with `<RSAKeyValue>`). You'll need it in Step 3.

## Step 2: Adding Libraries
In your Visual Studio project (WPF):
1. Add references to the projects (or DLLs):
   - `SoftLicence.Core` (Cryptographic engine)
   - `SoftLicence.UI` (Activation interfaces)
2. Add the `CommunityToolkit.Mvvm` NuGet package (used by the UI).

## Step 3: Startup Wiring
Open `App.xaml.cs` and replace the content with a robust state machine:

```csharp
public partial class App : Application
{
    private const string MyPublicKey = @"<RSAKeyValue>...PASTE YOUR KEY HERE...</RSAKeyValue>";
    private LicenseActivationViewModel _vm;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        ShutdownMode = ShutdownMode.OnExplicitShutdown;

        _vm = new LicenseActivationViewModel(MyPublicKey, "MyTool", "https://your-server.com");
        _vm.PropertyChanged += (s, args) => {
            if (args.PropertyName == nameof(_vm.IsLicensed) && !_vm.IsLicensed) {
                // License revoked during use!
                MessageBox.Show("Your license is no longer valid.");
                Shutdown();
            }
        };

        await _vm.InitializeAsync();

        if (_vm.IsLicensed) {
            new MainWindow().Show();
        } else {
            var win = new Window {
                Content = new LicenseActivationView { DataContext = _vm },
                SizeToContent = SizeToContent.WidthAndHeight
            };
            win.ShowDialog();
            if (_vm.IsLicensed) new MainWindow().Show(); else Shutdown();
        }
    }
}
```

## Step 4: Hardening (Obfuscation)
There's no point in adding a license if anyone can remove it by modifying a line of code.
1. Add the `Obfuscar` NuGet package.
2. Create an `obfuscar.xml` file at the root of your project (see example in `samples/SoftLicence.Samples.SimpleApp/obfuscar.xml`).
3. Configure it to obfuscate your main DLL and the SoftLicence DLLs.
4. **Always compile in Release mode** for protection to be applied.

### Understanding Obfuscation Results
After compilation, an `Obfuscated` folder is created in your output directory (`bin/Release/...`).
- **Protected DLLs**: These are the files you should distribute.
- **Mapping.txt**: This is your "Rosetta Stone". It contains the mapping between original names (e.g., `ValidateLicense`) and obfuscated names (e.g., `a`).
  **Keep this file safe**, it is essential for understanding error reports (stack traces) sent by your customers.

## Step 5: Delivery
Distribute to your customer:
1. Your `.exe` and its DLLs (from the `Obfuscated` folder).
2. To activate the software, the customer will need to request a key from you.
3. Generate this key in the **Products** tab of the server and send it to them.
