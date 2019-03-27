// A simple utility for parsing snmptrapd notifications and creating Sensu Go
// events (using the Sensu Go Agent HTTP API).
//
// Reference documentation: http://www.net-snmp.org/docs/man/snmptrapd.conf.html

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/calebhailey/snmptrapd2sensu/config"
	snmptypes "github.com/calebhailey/snmptrapd2sensu/types"
	"github.com/calebhailey/snmptrapd2sensu/utils"

	"github.com/sensu/sensu-go/types"
)

var (
	SystemUptimeOIDs = []string{
		// The various incantations of the sysUpTime OID - a required VARBIND in any
		// valid SNMPv2 Trap.
		"1.3.6.1.2.1.1.3.0",
		"1.3.6.1.4.1.3.6.1.2.1.1.3.0",
		"iso.3.6.1.2.1.1.3.0",
		"SNMPv2-MIB::sysUpTime.0",
	}
	SnmpTrapOidOIDs = []string{
		// The various incantations of the snmpTrapOID OID - a required VARBIND in
		// any valid SNMPv2 Trap.
		"1.3.6.1.6.3.1.1.4.1.0",
		"1.3.6.1.4.1.3.6.1.6.3.1.1.4.1.0",
		"iso.3.6.1.6.3.1.1.4.1.0",
		"SNMPv2-MIB::snmpTrapOID.0",
	}
	settings              *config.Settings = config.LoadConfig("/etc/sensu/snmptrapd2sensu.json")
	SnmpDefaultHostname   string           = settings.Snmptrapd.Defaults.Device.Host
	SnmpDefaultTrapName   string           = settings.Snmptrapd.Defaults.Trap.Name
	SensuNamespace        string           = settings.Sensu.Check.Namespace
	SensuAgentApiHost     string           = settings.Sensu.Agent.API.Host
	SensuAgentApiPort     int              = settings.Sensu.Agent.API.Port
	SensuCheckLabelPrefix string           = settings.Sensu.Check.LabelPrefix
)

func parseVarbind(varbind string) *snmptypes.SnmptrapdNotificationVarbind {
	// Parse an snmptrapd VARBIND (string) and return a SnmptrapdNotificationVarbind object.
	//
	var v *snmptypes.SnmptrapdNotificationVarbind
	var tokenSet []string

	// Do some stuff.
	v = new(snmptypes.SnmptrapdNotificationVarbind)
	tokenSet = strings.Fields(varbind)
	v.OID = tokenSet[0]
	v.Value = strings.Join(tokenSet[1:], " ")

	return v
}

func parseIpAddress(ipaddress string) *snmptypes.SnmptrapdNotificationIpAddress {
	// parse an snmptrapd IPADDRESS (string) and retun a
	// SnmptrapdNotificationIpAddress object.
	//
	var ip *snmptypes.SnmptrapdNotificationIpAddress
	var addresses []string
	var tokenSet []string

	// Do some stuff.
	// UDP: [127.0.0.1]:57099->[127.0.0.1]:162
	ip = new(snmptypes.SnmptrapdNotificationIpAddress)
	tokenSet = strings.Fields(ipaddress)
	addresses = strings.Split(tokenSet[1], "->")

	ip.Protocol = tokenSet[0]
	ip.SourceIP = strings.TrimLeft(strings.Split(addresses[0], "]")[0], "[")
	ip.SourcePort = strings.Split(addresses[0], ":")[1]
	ip.TargetIP = strings.TrimLeft(strings.Split(addresses[1], "]")[0], "[")
	ip.TargetPort = strings.Split(addresses[1], ":")[1]

	return ip
}

func parseNotification(stdin *os.File) *snmptypes.SnmptrapdNotification {
	// parse the Notification (consumed via stdin) and return a
	// SnmptrapdNotification object.
	//
	defer stdin.Close()
	var n *snmptypes.SnmptrapdNotification
	var row int

	// Save the original notification message for later use.
	// n.OriginalMessage = stdin

	// Do some stuff.
	n = new(snmptypes.SnmptrapdNotification)
	scanner := bufio.NewScanner(stdin)
	row = 0
	for scanner.Scan() {
		line := scanner.Text()
		switch row {
		case 0:
			// This is the first line in the Notification, thus the HOSTNAME
			log.Printf("INFO: Parsing notification HOSTNAME: %v\n", line)
			n.HOSTNAME = line
		case 1:
			// This is the second line in the Notification, thus the IPADDRESS
			log.Printf("INFO: Parsing notification IPADDRESS: %v\n", line)
			n.IPADDRESS = parseIpAddress(line)
		default:
			// Every other line in the Notification is a VARBIND
			log.Printf("INFO: Parsing notification VARBIND(%v): %v\n", row-1, line)
			varbind := parseVarbind(line)
			n.VARBINDS = append(n.VARBINDS, varbind)
		}
		row++
	}

	return n
}

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

func processNotification(notification *snmptypes.SnmptrapdNotification) {
	// Construct a Sensu Go Event from the parsed SnmptrapdNotification object,
	// mapping the Notification attributes to the corresponding Event fields; then
	// HTTP POST the event to a Sensu Agent HTTP API for processing.
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

	stdin = os.Stdin

	notification = parseNotification(stdin)
	validateNotification(notification)
	processNotification(notification)
}
