# dns-monitoring
This is a mini DNS filtering running as an osquery extension in Linux.

Please install osquery to make it work correctly.
## Build
>$go get github.com/google/gopacket

>$go get github.com/osquery/osquery-go

>$go build -o network_monitor.ext


## Run
### Configure 
Create directory "/var/osquery/extensions/v2-security" if there is no matching.
And update network interface that matches your case.
>$sudo cp ./conf.json /var/osquery/extensions/v2-security

>$sudo systemctl start osqueryd

>$sudo osqueryi --verbose --allow_unsafe --extension network_monitor.ext

## Query data in Osquery
>osquery> select * from benkyo;

There is an option from Osquery to check which application using IP from DNS result. It is good enough to check who uses DNS's result rather than who ordered it.

>osquery> SELECT processes.pid, uid, name, processes.path, protocol, start_time, remote_address, cmdline FROM process_open_sockets, processes 
	WHERE protocol > 0 and uid > 0 and remote_address!='::' and remote_address!='0.0.0.0' and  processes.pid = process_open_sockets.pid;
