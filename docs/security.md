# Security Documentation

### Authentication

There are two modes of authentication which can be enabled and disabled separately.

1. Username and Password (UI)
1. API Token (API)

If 1. is disabled, everyone can access the web UI at will. If 2. is disabled, everyone 
can use the API without any token.
Both modes are disabled by default.

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

*CertMaker* currently uses ECDSA for private key generation. That goes for the root private key 
as well.

I consider adding a system setting so you can switch the algorith via web UI, possible 
algorithms will be RSA, ECDSA and ED25519.