# adssl

[![](https://goreportcard.com/badge/github.com/tomdoherty/adssl)](https://goreportcard.com/report/github.com/tomdoherty/adssl)
[![](https://github.com/tomdoherty/adssl/workflows/Go/badge.svg)](https://github.com/tomdoherty/adssl/actions)
[![](https://img.shields.io/github/release/tomdoherty/adssl.svg)](https://github.com/tomdoherty/adssl/releases/latest)

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
   --country value, -C value     cert country [$COUNTRY]
   --province value, -P value    cert province [$PROVINCE]
   --locality value, -L value    cert locality [$LOCALITY]
   --commonname value, -c value  common name [$COMMON]
   --hosts value, -l value       comma delimited list of hosts to add to cert [$HOSTS]
   --ips value, -i value         comma delimited list of IPAddresses to add to cert [$IPADDRS]
   --prefix value, -f value      prefix output files [$PREFIX]
   --csronly, -O                 write csr/key only (default: false)
   --k8s-secret, -k              output as a kubernetes secret (default: false)
   --help, -h                    show help (default: false)

```

### Example
```shell
adssl -e https://ad -u tom -p sup3rs3cur3 --country US --province "New Jersey" --locality Weehawken --commonname host1 --hosts host1,host2 --ips 1.1.1.1,1.1.1.2

```
