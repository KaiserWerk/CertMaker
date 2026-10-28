# Configuration

At initial startup (when the file doesn't exist yet), the ``config.yaml`` file is created 
and filled with default values which there aren't a lot of.

Refer to the dist file located at internal/assets/config/config.dist.yaml

Make sure the configuration file is only readable by the user running your 
*CertMaker* instance.

## Environment variable overrides

The values from `config.yaml` are loaded first. Afterwards, selected environment
variables can override database settings:

- `DB_DRIVER` (optional, e.g. `mysql`, `sqlite`, `pgsql`, `mssql`)
- `DB_DSN` (optional, full DSN; highest priority)
- `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`, `DB_PARAMS`

If `DB_DSN` is set, it is used directly.

If `DB_DSN` is not set and any of the `DB_*` MySQL variables are provided,
CertMaker expects at least `DB_HOST`, `DB_USER`, `DB_PASSWORD`, and `DB_NAME`.
If one of those required values is missing, startup fails with a clear error.

`DB_PORT` defaults to `3306` when omitted and `DB_PARAMS` defaults to
`parseTime=true&charset=utf8`.

## Bootstrap admin user

CertMaker creates a bootstrap admin user when no user with the configured
bootstrap username exists.

You can override bootstrap credentials via:

- `CERTMAKER_BOOTSTRAP_ADMIN_USER`
- `CERTMAKER_BOOTSTRAP_ADMIN_PASSWORD`

Both variables must be set together (or both left unset). If both are unset,
CertMaker falls back to `admin` / `admin`.