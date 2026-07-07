# Repository Guidelines

## Project Structure & Module Organization

This repository is a .NET 9 solution centered on `src/SoftLicence.sln`.

- `src/SoftLicence.SDK`: shared licensing, cryptography, and client-facing APIs.
- `src/SoftLicence.Server`: ASP.NET Core server, admin/API logic, EF Core data access, and server data assets.
- `src/SoftLicence.UI`: WPF desktop UI using `CommunityToolkit.Mvvm`.
- `src/SoftLicence.KeyGen` and `src/SoftLicence.Template`: key generation and integration template projects.
- `tests/SoftLicence.Tests`: xUnit test project for SDK and server behavior.
- `samples/SoftLicence.Samples.SimpleApp`: minimal sample consumer app.
- `Docker`, `docker-compose.dev.yml`, and `deploy.ps1`: deployment and local infrastructure assets.
- `docs-public`, `docs-internal`, `screens`, `logo`, and `keys`: documentation, visual assets, and key material placeholders.

## Build, Test, and Development Commands

Run commands from the repository root unless noted.

- `dotnet restore src/SoftLicence.sln`: restore NuGet packages.
- `dotnet build src/SoftLicence.sln -c Release`: build all projects; warnings are treated as errors.
- `dotnet test tests/SoftLicence.Tests/SoftLicence.Tests.csproj`: run the xUnit suite.
- `dotnet run --project src/SoftLicence.Server/SoftLicence.Server.csproj`: start the server locally.
- `dotnet run --project src/SoftLicence.UI/SoftLicence.UI.csproj`: start the WPF UI on Windows.
- `docker compose -f docker-compose.dev.yml up`: start development services when needed.

## Coding Style & Naming Conventions

Use C# with nullable reference types enabled. Keep implicit usings where the project already enables them. Prefer 4-space indentation, PascalCase for types/methods/properties, camelCase for locals/parameters, and `Async` suffixes for asynchronous methods. Keep project boundaries clear: SDK code should not depend on server or UI implementation details.

No repository-level `.editorconfig` is currently present, so follow existing file style and run `dotnet format src/SoftLicence.sln` before broad formatting changes.

## Testing Guidelines

Tests use xUnit, `Microsoft.AspNetCore.Mvc.Testing`, Moq, and coverlet. Place tests under `tests/SoftLicence.Tests`, matching the feature or class under test. Use descriptive names such as `ValidateLicense_WhenExpired_ReturnsInvalid`. Add regression tests for security, activation, renewal, telemetry, and API behavior changes.

## Commit & Pull Request Guidelines

Recent history follows Conventional Commits, often with scopes: `fix(security): ...`, `feat(fingerprints): ...`, `docs(security): ...`. Use the same style and keep subjects specific.

Pull requests should include a concise description, test results, linked issue or reason for the change, and screenshots for UI/admin changes. Call out configuration, database, deployment, or security-sensitive changes explicitly.

## Security & Configuration Tips

Do not commit real secrets, private keys, production passwords, or customer data. Replace README placeholders such as `CHANGE_ME_DB_PASSWORD`, `CHANGE_ME_RANDOM_SECRET`, and `CHANGE_ME_MAXMIND_KEY` before deployment. Treat files under `keys` as sensitive unless they are known-safe examples.
