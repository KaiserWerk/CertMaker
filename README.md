# CertMaker

A simple, yet powerful Certificate Authority (and VA) server. It does intentionally __NOT__ 
implement the *ACME* protocol and is intentionally kept very simple.
It is meant to be used programmatically to automate certificate distribution.
Perfect for your homelab or self-hosted infrastructure.

### Features

* Obtain fresh certificates via UI and API
  * With optional DNS name/IP ownership verification
* Obtain the root certificate via UI and API
* Adjustable certificate validity (1 - 182 days)
  * Default validity is 7 days
* Certificates can be created for domains, IP addresses and email addresses
* Manage your CertMaker instance with a simple web UI
* Revoke certificates programmatically or manually via UI

### Documentation

* [Setup](docs/setup.md)
* [Configuration](docs/configuration.md)
* [API](docs/api.md)
* [Security](docs/security.md)

### Tools
* [CertMaker Bot](https://github.com/KaiserWerk/CertMaker-Bot)

  A simple sidecar app to automate fetching new certificates based on configuration files.

* [CertMaker CLI](https://github.com/KaiserWerk/CertMaker-CLI)

  A command line tool to obtain certificates from CertMaker instances and to handle general certificate needs.

* [Go SDK](https://github.com/KaiserWerk/CertMaker-Go-SDK)
  
  The Golang software development kit for *CertMaker*. It allows you to build custom apps for your specific 
  certificate needs without having to use the HTTP API directly.

