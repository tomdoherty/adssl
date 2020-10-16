# adssl

[![](https://goreportcard.com/badge/github.com/tomdoherty/adssl)](https://goreportcard.com/report/github.com/tomdoherty/adssl)
[![](https://img.shields.io/github/release/tomdoherty/govid.svg)](https://github.com/tomdoherty/govid/releases/latest)
[![](https://github.com/tomdoherty/adssl/workflows/Go/badge.svg)](https://github.com/tomdoherty/adssl/actions)

## Usage
```shell
NAME:
   adssl - Generate SSL certificates against Active Directory

USAGE:
   adssl [global options] command [command options] [arguments...]

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --endpoint value, -e value  endpoint to use [$ENDPOINT]
   --username value, -u value  username to authenticate with (default: "$(whoami)") [$USER]
   --password value, -p value  username to authenticate with [$PASSWORD]
   --hosts value, -l value     comma delimited list of hosts to add to cert [$HOSTS]
   --k8s-secret, -k            output as a kubernetes secret (default: false)
   --help, -h                  show help (default: false)
```

### Example
```shell
$ adssl -e myad.example.com -p p4ssw0rd -l host1,host2 -k | kubectl apply -f -
```
