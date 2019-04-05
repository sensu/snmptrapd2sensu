# snmptrapd2Sensu

## Overview

The `snmptrapd2sensu` utility is a NET-SNMP `snmptrapd` trap handler that takes
notifications from `snmptrapd`, converts them to Sensu Events, and posts them to
a Sensu Agent HTTP API (`POST /events`).

## Installation

1. Download the `snmptrapd2sensu` tarball, install the binary on the system at
   `/usr/bin/snmptrapd2sensu`.

   ```
   $ curl -LO https://github.com/sensu/snmptrapd2sensu/releases/download/0.1/snmptrapd2sensu_0.1_linux_amd64.tar.gz
   $ tar -xzf snmptrapd2sensu_0.1_linux_amd64.tar.gz
   $ cp snmptrapd2sensu /usr/bin/
   $ rm snmptrapd2sensu_0.1_linux_amd64.tar.gz
   ```

   _NOTE: see [here][releases] for binaries for other platforms and/or system
   architectures (e.g. linux 32-bit, linux ARM, freebsd, macos, etc)._

   [releases]: https://github.com/sensu/snmptrapd2sensu/releases

## Configuration

1. Configure `snmptrapd2sensu`.

   Create a JSON configuration file at `/etc/sensu/snmptrapd2sensu.json` with
   the following contents:

   ```json
   {
     "snmptrapd": {
       "defaults": {
         "device": {
           "host": "unknown-snmp-device"
         },
         "trap": {
           "name": "unknown-snmp-trap",
           "status": 0
         }
       }
     },
     "sensu": {
       "agent": {
         "api": {
           "host": "127.0.0.1",
           "port": 3031
         }
       },
       "check": {
         "namespace": "default",
         "label_prefix": "snmp",
         "status": 1
       }
     }
   }
   ```

2. Configure `snmptrapd` to send notifications to `snmptrapd2sensu`.

   Add the following line to your `snmptrapd.conf` configuration:

   ```conf
   traphandle default /usr/bin/snmptrapd2sensu
   ```

   > _NOTE: the default `snmptrapd.conf` file is typically located at
   > `/etc/snmp/snmptrapd.conf` (on linux systems)._

## Troubleshooting

- Run `snmptrapd` in the foreground to observe it receive SNMP traps and forward
  notifications to `snmptrapd2sensu` (and see the log output of
  `snmptrapd2sensu`).

  ```
  $ sudo /usr/sbin/snmptrapd -c /etc/snmp/snmptrapd.conf -f -Lo
  NET-SNMP version 5.6.2.1

  SNMPv2-MIB::snmpTrapOID.0 = OID: NET-SNMP-EXAMPLES-MIB::netSnmpExampleHeartbeatNotification     NET-SNMP-EXAMPLES-MIB::netSnmpExampleHeartbeatRate = INTEGER: 123456

  2019/03/27 12:16:29 INFO: Parsing notification HOSTNAME: localhost
  2019/03/27 12:16:29 INFO: Parsing notification IPADDRESS: UDP: [127.0.0.1]:64983->[0.0.0.0]:0
  2019/03/27 12:16:29 INFO: Parsing notification VARBIND(1): SNMPv2-MIB::snmpTrapOID.0 NET-SNMP-EXAMPLES-MIB::netSnmpExampleHeartbeatNotification
  2019/03/27 12:16:29 INFO: Parsing notification VARBIND(2): NET-SNMP-EXAMPLES-MIB::netSnmpExampleHeartbeatRate 123456
  2019/03/27 12:16:29 INFO: Found required SNMP Trap OID: SNMPv2-MIB::snmpTrapOID.0!
  2019/03/27 12:16:29 INFO: Sensu Event JSON output:
  {
    "check": {
      "handlers": [],
      "high_flap_threshold": 0,
      "interval": 1,
      "low_flap_threshold": 0,
      "publish": false,
      "runtime_assets": null,
      "subscriptions": [],
      "proxy_entity_name": "",
      "check_hooks": null,
      "stdin": false,
      "subdue": null,
      "ttl": 0,
      "timeout": 0,
      "round_robin": false,
      "executed": 0,
      "history": null,
      "issued": 0,
      "output": "{\n  \"NET-SNMP-EXAMPLES-MIB::netSnmpExampleHeartbeatRate\": \"123456\",\n  \"SNMPv2-MIB::snmpTrapOID.0\": \"NET-SNMP-EXAMPLES-MIB::netSnmpExampleHeartbeatNotification\"\n}",
      "status": 1,
      "total_state_change": 0,
      "last_ok": 0,
      "occurrences": 0,
      "occurrences_watermark": 0,
      "output_metric_format": "",
      "output_metric_handlers": null,
      "env_vars": null,
      "metadata": {
        "name": "NET-SNMP-EXAMPLES-MIB--netSnmpExampleHeartbeatNotification",
        "namespace": "default",
        "annotations": {
          "snmp_SNMPv2-MIB--snmpTrapOID-0": "NET-SNMP-EXAMPLES-MIB::netSnmpExampleHeartbeatNotification",
          "snmp_NET-SNMP-EXAMPLES-MIB--netSnmpExampleHeartbeatRate": "123456"
        }
      }
    },
    "metadata": {}
  }
  ```

  _NOTE: if properly configured, `snmptrapd` will handle the translation of OIDs
  to their descriptive names as found in a MIB file; see `snmptrapd -h` for more
  information on how to configure `snmptrapd` to read MIB files._
