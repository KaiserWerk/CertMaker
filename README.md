# CertMaker

A basic Certificate Authority server. It does __NOT__ implement the ACME 
protocol and is intentionally kept very simple.
It is meant to be use programmatically to automate certificate distribution.
Perfect for your homelab or self-hosted infrastructure.

### Features

* Obtain fresh certificates via UI and API
  * With optional DNS name/IP ownership verification
* Obtain the root certificate via UI and API (coming M2)
* Manage your CertMaker instance with a simple web UI (optional) 
* Adjustable certificate validity (1 - 182 days)
  * Default validity is 7 days
* Certificates can be created for domains, IP addresses and email addresses

### Documentation

* [UI](docs/ui-documentation.md)
* [API](docs/api-documentation.md)
* [Security](docs/security-documentation.md)

### Tools
* [CertMaker Bot](https://github.com/KaiserWerk/CertMaker-Bot)
* [Go SDK](https://github.com/KaiserWerk/CertMaker-Go-SDK)

