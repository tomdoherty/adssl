# gobblah

[![Go Report Card](https://goreportcard.com/badge/github.com/tomdoherty/gobblah)](https://goreportcard.com/report/github.com/tomdoherty/gobblah)
[![Go Actions Status](https://github.com/tomdoherty/gobblah/workflows/Go/badge.svg)](https://github.com/tomdoherty/gobblah/actions)

## Usage
```shell
NAME:
   gobblah - Generate SSL certificates against Active Directory

USAGE:
   gobblah [global options] command [command options] [arguments...]

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
$ gobblah -e myad.example.com -p p4ssw0rd -l host1,host2 -k | kubectl apply -f -
```
