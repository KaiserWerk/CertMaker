# Setup

1. Download the latest [release](https://github.com/KaiserWerk/CertMaker/releases) or build it 
yourself (in that case, refer to ``build.ps1``).
1. Place the binary into the designated folder.
1. Create the folders ``data`` and ``data/leafcerts``.
1. Running the binary will create the files ``certmaker.log`` and ``config.yaml``.

That's about it for initial setup. Make sure all files and folder can be written and read by 
the user running the binary.

#### Command line flags

There are a few command line flags you can modify the binary's behaviour with.
This can be used with either one or two dashes and with or without equal sign between name
and value.

1. ``./certmaker --config="/some/path/to/configfile.yaml"`` allows you to change the path 
to the configuration file. Make sure the user has read access.
   
1. ``./certmaker --logfile="/path/to/certmaker-logfile"`` changes the path to the *CertMaker* log
   file. Make sure the user has write access.
   
1. ``./certmaker --port=1234`` With this flag, you can change the port your *CertMaker* instance will run at. The default 
port is __8880__.
   
1. ``./certmaker --ui=false`` With this parameter you can enable/disable the Web UI. Default is ``true``.

1. ``./certmaker --debug=true`` Runs the app in debug mode. That means the log formatter will be text-based
instead of JSON-based. Also, log entries with level ``TRACE`` and higher will be display, instead of
``INFO`` and higher. No log entry will be written to the log file, just shown on the console.

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