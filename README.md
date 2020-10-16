# adssl

[![](https://goreportcard.com/badge/github.com/tomdoherty/adssl)](https://goreportcard.com/report/github.com/tomdoherty/adssl)
[![](https://img.shields.io/github/release/tomdoherty/govid.svg)](https://github.com/tomdoherty/govid/releases/latest)
[![](https://github.com/tomdoherty/adssl/workflows/Go/badge.svg)](https://github.com/tomdoherty/adssl/actions)

## Usage

```
NAME:
   adssl - Generate SSL certificates against Active Directory

USAGE:
   adssl [global options] command [command options] [arguments...]

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --endpoint value, -e value    endpoint to use [$ENDPOINT]
   --username value, -u value    username to authenticate with (default: "tom") [$USER]
   --password value, -p value    username to authenticate with [$PASSWORD]
   --commonname value, -c value  common name [$COMMON]
   --hosts value, -l value       comma delimited list of hosts to add to cert [$HOSTS]
   --ips value, -i value         comma delimited list of IPAddresses to add to cert [$IPADDRS]
   --k8s-secret, -k              output as a kubernetes secret (default: false)
   --help, -h                    show help (default: false)

```

### Example
```shell
adssl -e myad.example.com -p p4ssw0rd -c host1 -l host2,host3 -i 1.1.1.1 -k | kubectl apply -f -

```
