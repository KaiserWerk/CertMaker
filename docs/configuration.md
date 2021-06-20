# Configuration

At initial startup (when the file doesn't exist yet), the ``config.yaml`` file is created 
and filled with default values which there aren't a lot of.

It looks similar like this:

```yaml
# The public-facing host address. Used to construct external links referencing your CertMaker installation
server_host: http://localhost:8880
# The data directory where certs are stored. When not absolute, it is interpreted as relative to the binary
data_dir: data
# Details for the database connection
database:
  # The database system driver to use. Can be either sqlite, mysql, mssql or pgsql. Change the DSN accordingly
  driver: mysql
  # The connection string for the chosen database system
  dsn: 'user:password@tcp(127.0.0.1:3306)/certmaker_db?parseTime=true&charset=utf8'
```

1. ``server_host`` is important to construct URLs referencing your *CertMaker* instance, e.g.
  in ``Location`` HTTP headers. Please pay attention to the schema (http or https) and the port,
  especially.
   
1. ``data_dir`` is where the root certificate and subsequently all leaf certificates are stored
  as files. It should only be readable by the user running your *CertMaker* instance.
   
1. ``database:driver`` states which DB system should be used. Easy.

1. ``database:dsn`` stores the connection string for your DB system.

Make sure the configuration file is only readable by the user running your 
*CertMaker* instance.