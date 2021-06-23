# API Documentation (v1)

All API routes have the route prefix ``/api/v1``.

### Authentication

All calls to the API have to originate from a valid user. Set the HTTP header ``X-Auth-Token`` to
your API token and you're good to go, if your account isn't disabled. No need to be admin.

All routes return a ``401 Unauthorized`` in case the authentication goes wrong, a ``404 Not Found``
in case a user account corresponding to the supplied API token cannot be found, a ``400 Bad Request``
if the request was malformed or incorrectly formatted or lastly a ``500 Internal Server Error``
if something wrong happened at the server.

### Routes

### ``GET /root-certificate/obtain`` 
returns a ``200 OK``. The response body contains the root 
certificate with content type ``application/x-pem-file``.

### ``POST /certificate/request`` 
accepts a JSON encoded ``SimpleRequest`` and returns a ``200 OK`` and the ``X-Certificate-Location`` and
``X-Privatekey-Location`` headers to obtain the newly created certificate and private key. 
If the verification challenge is enabled it returns a ``202 Accepted``, the challenge 
token in the response body and the ``X-Challenge-Location`` header containing the URL
to solve the challenge. Before your do, make sure the challenge token is reachable via 
GET request under the url 
``<requested-domain-or-ip>/.well-known/certmaker-challenge/token.txt``.
Make sure this works for every requested DNS name/IP address, excluding 'localhost',
'127.0.0.1' and '::1' which are never validated.

### ``POST /certificate/request-with-csr``
is the same as the previous route, but for a *Certificate Signing Request* which must be placed 
in the request body.

### ``GET /certificate/{id}/obtain`` 
returns ``200 OK`` and the certificate, corresponding to the supplied id, in the response body.

### ``GET /privatekey/{id}/obtain`` 
returns ``200 OK`` and the private key, corresponding to the supplied id, in the response body.

### ``GET /challenge/{id}/solve``
Tries so solve the supplied challenge. It will try to read the token from the 'well-known' 
location via every domain name and IP address (exceptions apply, see above).
The request can contain an ``X-Challenge-Port`` header stating which HTTP port to use for the
challenge. The default port is 80.
If successful, returns ``200 OK`` and respective certificate and private key location headers.
If any validation attempt for a domain or IP address fails, the whole process is stopped and
``417 Expectation Failed`` is returned. It can be tried again (a time limit is coming at a 
later milestone).

### ``GET /ocsp/{base64}`` and ``POST /ocsp``
represent a functional OCSP responder which responds to OCSP request with the certificate 
status in a proper OCSP response

### ``POST /certificate/{sn}/revoke``
revokes a certificate with the supplied serial number (in decimal format). If the process was 
successful, a ``200 OK`` status will be returned. If the certificate was already revoked,
a status ``410 Gone`` is returned instead.