# Setup

1. Download the latest [release](https://github.com/KaiserWerk/CertMaker/releases) or build it 
yourself (in that case, refer to ``build.ps1``).
1. Place the binary into the designated folder.
1. Create the folders ``data`` and ``data/leafcerts``.
1. Running the binary will create the files ``certmaker.log`` and ``config.yaml``. Change 
   configuration values according to your needs. At next startup, all the necessary database 
   tables will be created automatically.
1. Open your favourite browser and navigate to ``http://localhost:8880`` to access the web UI.
1. Create a new user with admin flag set. Make sure you remember the password.
1. Enable the *Username and Password (UI)* authentication provider.

That's about it for initial setup. Make sure all files and folder can be written and read by 
the user running the binary.

I strongly suggest you create a separate user account for every app / client that will
be using your *CertMaker* instance.

#### Command line flags

There are a few command line flags you can modify the binary's behaviour with.
This can be used with either one or two dashes and with or without equal sign between name
and value.

1. ``./certmaker --config="/some/path/to/configfile.yaml"`` allows you to change the path 
to the configuration file. Make sure the user has read access. The default value is
   **config.yaml**.
   
1. ``./certmaker --logfile="/other/path/to/certmaker-logfile"`` changes the path to the *CertMaker* log
   file. Make sure the user has write access. The default value is **certmaker.log**.
   
1. ``./certmaker --port=1234`` With this flag, you can change the port your *CertMaker* instance will run at. The default 
port is __8880__.
   
1. ``./certmaker --ui=false`` With this parameter you can disable the Web UI (headless). 
Default value is **true**.

1. ``./certmaker --debug=true`` Runs the app in debug mode. That means the log formatter will be text-based
instead of JSON-based. Also, log entries with level ``TRACE`` and higher will be display, instead of
``INFO`` and higher. No log entry will be written to the log file, just shown on the console.
Default value is **false**.

Those command line parameters can be combined as necessary.

### Setup as a linux service

With a little initial handiwork, you can easily run *CertMaker* as a linux service.
This is an example for Debian-based operating systems.

Place the following file content into the file ``/etc/systemd/system/certmaker.service``:

```
[Unit]
Description=CertMaker (The Dead-Simple Certificate Authority)
After=network.target
Wants=mysql.service

[Service]
Type=simple
ExecStart=/home/certmaker/bin/certmaker
WorkingDirectory=/home/certmaker/bin
User=certmaker
Group=certmaker
Restart=always
RestartSec=15

[Install]
WantedBy=multi-user.target
```

In this example the system user/group ``certmaker`` is running the *CertMaker* instance from the 
homedir's subfolder ``bin``. Also, the service will wait for MySQL to be started first.
Change that according to your requirements.
``ExecStart`` is the exact path to the binary while ``WorkingDirectory`` is the exact path to the binary.


Afterwards, reload the systemctl daemon, enable and start the new service:

```bash
$ sudo systemctl daemon-reload
$ sudo systemctl enable certmaker.service
$ sudo systemctl start certmaker.service
```

Your *CertMaker* instance should now start whenever the server starts, e.g. after reboot.