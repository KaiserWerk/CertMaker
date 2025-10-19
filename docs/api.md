# API Documentation (v1)

All current API routes have the route prefix ``/api/v1``.

### Authentication

All calls to the API have to originate from a valid user. Set the HTTP header ``X-Auth-Token`` to
your API token and you're good to go, if your account isn't disabled. No need to be admin.
Accounts that are locked can still use the API but they cannot be used for logging into the UI.

All routes return a ``401 Unauthorized`` in case the authentication goes wrong, a ``404 Not Found``
in case a user account corresponding to the supplied API token cannot be found, a ``400 Bad Request``
if the request was malformed or incorrectly formatted or lastly a ``500 Internal Server Error``
if something wrong happened at the server.

### Routes

### ``GET /root-certificate/obtain`` 
returns a ``200 OK``. The response body contains the root 
certificate with content type ``application/x-pem-file``.

### ``POST /certificate/request-with-simplerequest`` 
accepts a JSON encoded ``SimpleRequest`` and returns either
- a ``201 Created`` and returns a fresh certificate with its private key in the response JSON
- a ``202 Accepted`` which presents at least one challenge to solve. After preparations are done, the call to either `POST /http-01/{challengeID}/solve` or `GET /dns-01/{challengeID}/solve` signals the *CertMaker* instance that the appropriate DNS name checks can be performed now. On success, certificate (and private key) are created and returned.

For the HTTP-01 challenge the provided challenge token bust be returned in the body with the content type "text/plain" by the location
``GET <requested-domain-or-ip>/.well-known/certmaker-challenge/token`` for every DNS name and IP address, excluding 'localhost',
'127.0.0.1' and '::1' which are never validated.

For IP address validation, only the `HTTP-01` challenge can be used.

### ``POST /certificate/request-with-csr``
Accepts a *Certificate Signing Request* which must be placed in the request body.
Regarding validation, the same rules apply. For obvious reasons, only a certificate is created, but no private key.

### ``GET /ocsp/{base64}`` and ``POST /ocsp``
represent a functional OCSP responder which responds to OCSP request with the certificate 
status in a proper OCSP response

### ``POST /certificate/{sn}/revoke``
revokes a certificate with the supplied serial number (in decimal format). If the process was 
successful, a ``200 OK`` status will be returned. If the certificate was already revoked,
a status ``410 Gone`` is returned instead.