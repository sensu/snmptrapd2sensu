# snmptrapd2Sensu

## Overview

The `snmptrapd2sensu` utility is a NET-SNMP `snmptrapd` trap handler that takes
notifications from `snmptrapd`, converts them to Sensu Events, and posts them to
a Sensu Agent HTTP API (`POST /events`).

## Installation

1. Download the `snmptrapd2sensu` tarball, install the binary on the system at
   `/usr/bin/snmptrapd2sensu`.

## Configuration

1. Configure `snmptrapd2sensu`.

   Create a JSON configuration file at `/etc/sensu/snmptrapd2sensu.json` with
   the following contents:

   ```json
   {
     "snmptrapd": {
       "defaults": {
         "device": {
           "host": "poop"
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
  ```

  _NOTE: if properly configure, `snmptrapd` will handle the translation of OIDs
  to their descriptive names as found in a MIB file; see `snmptrapd -h` for more
  information on how to configure `snmptrapd` to read MIB files._
