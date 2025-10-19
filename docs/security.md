# Security Documentation

### Authentication

There are two modes of authentication:

1. Username and Password (UI)
1. API Token (API)

### Authorization

There are just two simple levels of authorization. More specifically, there are two access
levels for user accounts. Normal users and administrators. The difference is that 
administrators can change system settings, manage user accounts and see all created
certificates in the web UI.

### Certificate request modes

There are two modes for requesting new certificates. The normal mode requires the use of a
Certificate Signing Request and only generates a certificate.
The simple mode has no special requirements and generates a certificate as well as a
private key.

If either mode is disabled, certificates cannot be requested that way. Both modes are 
disabled by default.

### Generation of private keys

*CertMaker* uses the key algorithm which is set in the configuration. If not set, default 'rsa' is assumed. 
Other possible values are 'ecdsa' and 'ed25519'.
