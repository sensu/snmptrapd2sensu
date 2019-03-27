// A simple utility for parsing snmptrapd notifications and creating Sensu Go
// events (using the Sensu Go Agent HTTP API).
//
// Reference documentation: http://www.net-snmp.org/docs/man/snmptrapd.conf.html

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/calebhailey/snmptrapd2sensu/config"
	"github.com/calebhailey/snmptrapd2sensu/parsers"
	snmptypes "github.com/calebhailey/snmptrapd2sensu/types"
	"github.com/calebhailey/snmptrapd2sensu/utils"

	"github.com/sensu/sensu-go/types"
)

var SystemUptimeOIDs = []string{
	// The various incantations of the sysUpTime OID - a required VARBIND in any
	// valid SNMPv2 Trap.
	"1.3.6.1.2.1.1.3.0",
	"1.3.6.1.4.1.3.6.1.2.1.1.3.0",
	"iso.3.6.1.2.1.1.3.0",
	"SNMPv2-MIB::sysUpTime.0",
}
var SnmpTrapOidOIDs = []string{
	// The various incantations of the snmpTrapOID OID - a required VARBIND in
	// any valid SNMPv2 Trap.
	"1.3.6.1.6.3.1.1.4.1.0",
	"1.3.6.1.4.1.3.6.1.6.3.1.1.4.1.0",
	"iso.3.6.1.6.3.1.1.4.1.0",
	"SNMPv2-MIB::snmpTrapOID.0",
}
var settings *config.Settings = config.LoadConfig("/etc/sensu/snmptrapd2sensu.json")
var SnmpDefaultHostname string = settings.Snmptrapd.Defaults.Device.Host
var SnmpDefaultTrapName string = settings.Snmptrapd.Defaults.Trap.Name
var SensuNamespace string = settings.Sensu.Check.Namespace
var SensuAgentApiHost string = settings.Sensu.Agent.API.Host
var SensuAgentApiPort int = settings.Sensu.Agent.API.Port
var SensuCheckLabelPrefix string = settings.Sensu.Check.LabelPrefix

func validateNotification(notification *snmptypes.SnmptrapdNotification) {
	IpReplacer := strings.NewReplacer(".", "_")
	switch notification.HOSTNAME {
	case "<UNKONWN>":
		notification.HOSTNAME = IpReplacer.Replace(notification.IPADDRESS.SourceIP)
	case "\u003cUNKNOWN\u003e":
		notification.HOSTNAME = IpReplacer.Replace(notification.IPADDRESS.SourceIP)
	}
}

func getVarbind(notification *snmptypes.SnmptrapdNotification, oids []string) *snmptypes.SnmptrapdNotificationVarbind {
	// Lookup a VARBIND by OID from notification.VARBINDS
	//
	var varbind *snmptypes.SnmptrapdNotificationVarbind

	for i, v := range notification.VARBINDS {
		index := utils.IndexOf(oids, v.OID)
		if index >= 0 {
			varbind = notification.VARBINDS[i]
			break
		} else {
			varbind = nil
		}
	}
	return varbind
}

func processNotification(notification *snmptypes.SnmptrapdNotification) *types.Event {
	// Construct a Sensu Go Event from the parsed SnmptrapdNotification object,
	// mapping the Notification attributes to the corresponding Event fields.
	//
	var event *types.Event
	event = new(types.Event)
	var eventOutput map[string]string
	eventOutput = make(map[string]string)

	event.Check = new(types.Check)
	eventOID := getVarbind(notification, SnmpTrapOidOIDs)
	if eventOID != nil {
		log.Printf("INFO: Found required SNMP Trap OID: %s!\n", eventOID.OID)
		OidReplacer := strings.NewReplacer(".", "-", ":", "-")
		event.Check.Name = OidReplacer.Replace(eventOID.Value)
	} else {
		log.Printf("ERROR: No matching VARBIND for required OIDs %s\n", SnmpTrapOidOIDs)
		event.Check.Name = SnmpDefaultTrapName
	}
	event.Check.Namespace = SensuNamespace
	event.Check.Interval = 1
	event.Check.Annotations = make(map[string]string)
	for _, v := range notification.VARBINDS {
		eventOutput[v.OID] = v.Value
		OidReplacer := strings.NewReplacer(".", "-", ":", "-")
		oid := OidReplacer.Replace(v.OID)
		key := strings.Join([]string{SensuCheckLabelPrefix, oid}, "_")
		event.Check.Annotations[key] = v.Value
	}
	eventOutputJson, err := json.MarshalIndent(eventOutput, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	event.Check.Output = string(eventOutputJson)

	if notification.HOSTNAME != "localhost" {
		event.Entity = new(types.Entity)
		event.Entity.Name = notification.HOSTNAME
		event.Entity.Namespace = SensuNamespace
	}

	sensuEvent, err := json.MarshalIndent(event, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("INFO: Sensu Event JSON output:\n%s\n", string(sensuEvent))
	return event
}

func postEvent(event *types.Event) {
	// Post the event to the Sensu Agent HTTP API
	postBody, err := json.Marshal(event)
	if err != nil {
		log.Fatal(err)
	}
	body := bytes.NewReader(postBody)
	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("http://%s:%v/events", SensuAgentApiHost, SensuAgentApiPort),
		body,
	)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	fmt.Println(string(b))
}

func main() {
	var stdin *os.File
	var notification *snmptypes.SnmptrapdNotification
	var event *types.Event

	stdin = os.Stdin

	notification = parsers.ParseNotification(stdin)
	validateNotification(notification)
	event = processNotification(notification)
	postEvent(event)
}
