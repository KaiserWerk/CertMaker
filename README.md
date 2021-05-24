# CertMaker

A basic Certificate Authority server. It does __NOT__ implement the ACME 
protocol and is intentionally kept very simple.
It is meant to be use programmatically to automate certificate distribution.
Perfect for your homelab or self-hosted infrastructure.

### Features

* Programmatically obtain fresh certificates (and optionally private keys as well)
* Programmatically obtain the root certificate (currently no intermediate certificates are used)
* Manage your CertMaker instance with a simple web UI (optional)
* Adjustable certificate validity (5 - 182 days)
* Certificates can be created for domains as well as IP addresses
* [CertMaker Bot](https://github.com/KaiserWerk/CertMaker-Bot),  command line helper to obtain 
certificates for 3rd-party apps which cannot obtain certificates themselves
* [The Go SDK](https://github.com/KaiserWerk/CertMaker-Go-SDK)
* The .NET SDK (in planning)

### API Documentation

See Swagger docs (coming soon)

### CertMaker Bot
This is a command line tool to automate the process of requesting and fetching 
fresh certificates for all you apps and programs.

Repo: [CertMaker Bot](https://github.com/KaiserWerk/CertMaker-Bot)
