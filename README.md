# CertMaker

A basic Certificate Authority server. It does __NOT__ implement the ACME 
protocol and is intentionally kept very simple.
It is meant to be use programmatically to automate certificate distribution.
Perfect for your homelab or self-hosted infrastructure.

### Features

* Programmatically obtain fresh certificates (and optionally private keys as well)
* Programmatically obtain the root certificate (currently no intermediate certificates are used) (coming M2)
* Manage your CertMaker instance with a simple web UI (optional)
* Adjustable certificate validity (1 - 182 days)
* Certificates can be created for domains as well as IP addresses
* [CertMaker Bot](https://github.com/KaiserWerk/CertMaker-Bot), command line helper to obtain 
certificates for 3rd-party apps which cannot obtain certificates themselves (in development)
* [The Go SDK](https://github.com/KaiserWerk/CertMaker-Go-SDK) (in development)
* The .NET SDK (in planning)

### Documentation

- API: See Swagger docs (coming soon)
- UI: coming soon

