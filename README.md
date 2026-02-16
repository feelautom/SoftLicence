# 🛡️ SoftLicence - Industrial DRM for the .NET Ecosystem

**SoftLicence** is a comprehensive platform for protecting, distributing, and monitoring your WPF software. It combines the power of RSA cryptography with a modern and reactive administration interface.

## 🚀 Features in v1.1

- **Subscriptions & Renewals**: Manage recurring licenses via the secure renewal API. Easily integrate your Stripe/PayPal payments to automatically extend your customers' access.
- **Custom Fields (Reference)**: Link each license to an order ID or an internal customer reference. This field is encrypted and included in the signed license file.
- **Auto-Trial Generation**: Allow your software to self-activate upon first launch via a "Magic Key" or a dedicated endpoint.
- **Analytics & Telemetry**: Track your activations and receive real-time error and diagnostic reports.
- **Recovery Management**: Intelligent reactivation (Recovery) counting system to identify abuse.
- **Self-Service Reset**: Allow your customers to unlink their licenses themselves via email.
- **Industrial Security**: RSA-4096, Rate Limiting, Full Audit, and automatic time zone detection.

## 📚 Documentation

- [**Protection Guide**](docs/PROTECTION_GUIDE.md): Step-by-step integration.
- [**Client Documentation**](docs/CLIENT.md): Technical operation.
- [**Server Documentation**](docs/SERVER.md): Deployment and API.
- [**Internationalization**](docs/I18N.md): Multi-language and offline assets.
- [**Roadmap**](docs/ROADMAP.md): Development tracking.

## ⚡ Quick Start

1. **Deployment**: Use `Docker/docker-compose.yml` to bring your server online in 2 minutes.
2. **Software**: Create your first software in the admin and retrieve its public key.
3. **Protection**: Follow the WPF integration guide and compile in Release mode with Obfuscar.

## ⚙️ Configuration & Personalization

This repository uses placeholders to ensure your security and the tool's customization. Here is the list of terms you must search and replace before your first deployment:

| Term to search | Description |
| :--- | :--- |
| `YOUR_APP_NAME` | Your software's name (e.g., YOUR_APP_NAME). |
| `YOUR_COMPANY_NAME` | Your name or company for copyrights and emails. |
| `EXAMPLE.COM` | Your real domain name for links and SMTP settings. |
| `CHANGE_ME_DB_PASSWORD` | Password for the PostgreSQL database. |
| `CHANGE_ME_ADMIN_PASSWORD` | Initial password for the Admin account. |
| `CHANGE_ME_RANDOM_SECRET` | Mandatory secret key to secure API communications. |
| `CHANGE_ME_SECRET_LOGIN_PATH` | Custom URL to hide your login page (e.g., `my-secret-door`). |
| `CHANGE_ME_MAXMIND_KEY` | Your MaxMind license key for IP geolocation. |

---
Developed with ❤️ for robust industrial deployment.
