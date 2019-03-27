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

	"github.com/sensu/sensu-go/types"
)

type SnmptrapdNotificationVarbind struct {
	OID   string `json:"oid"`
	Value string `json:"value"`
	Type  string `json:"type"`
}

type SnmptrapdNotificationIpAddress struct {
	Protocol   string `json:"protocol"`
	SourceHost string `json:"source_host"`
	SourcePort string `json:"source_port"`
	TargetHost string `json:"target_host"`
	TargetPort string `json:"target_port"`
}

type SnmptrapdNotification struct {
	HOSTNAME  string                          `json:"hostname"`
	IPADDRESS *SnmptrapdNotificationIpAddress `json:"ipaddress"`
	VARBINDS  []*SnmptrapdNotificationVarbind `json:"varbinds"`
}

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
	SnmpDefaultHostname   string = getenv("SNMP_DEFAULT_HOSTNAME", "unknown-network-device")
	SnmpDefaultTrapName   string = getenv("SNMP_DEFAULT_TRAP_NAME", "unknown-snmp-trap")
	SensuNamespace        string = getenv("SENSU_NAMESPACE", "default")
	SensuAgentApiHost     string = getenv("SENSU_AGENT_API_HOST", "127.0.0.1")
	SensuAgentApiPort     string = getenv("SENSU_AGENT_API_PORT", "3031")
	SensuCheckLabelPrefix string = getenv("SENSU_CHECK_LABEL_PREFIX", "snmp")
)

func getenv(key string, fallback string) string {
	value := os.Getenv(key)
	if len(value) == 0 {
		return fallback
	}
	return value
}

func indexOf(s []string, k string) int {
	// return the []string slice index value of the first occurence of key (k).
	for i, v := range s {
		if v == k {
			return i
		}
	}
	return -1
}

func (object *SnmptrapdNotification) String() string {
	var output strings.Builder
	fmt.Fprintf(&output, "HOSTNAME: %v\n", object.HOSTNAME)
	fmt.Fprintf(&output, "IPADDRESS: %v:%v\n", object.IPADDRESS.SourceHost, object.IPADDRESS.SourcePort)
	for _, v := range object.VARBINDS {
		fmt.Fprintf(&output, "VARBIND: %v: %v\n", v.OID, v.Value)
	}
	return output.String()
}

func parseVarbind(varbind string) *SnmptrapdNotificationVarbind {
	// Parse an snmptrapd VARBIND (string) and return a SnmptrapdNotificationVarbind object.
	//
	var v *SnmptrapdNotificationVarbind
	var tokenSet []string

	// Do some stuff.
	v = new(SnmptrapdNotificationVarbind)
	tokenSet = strings.Fields(varbind)
	v.OID = tokenSet[0]
	v.Value = strings.Join(tokenSet[1:], " ")

	return v
}

func parseIpAddress(ipaddress string) *SnmptrapdNotificationIpAddress {
	// parse an snmptrapd IPADDRESS (string) and retun a
	// SnmptrapdNotificationIpAddress object.
	//
	var ip *SnmptrapdNotificationIpAddress
	var addresses []string
	var tokenSet []string

	// Do some stuff.
	// UDP: [127.0.0.1]:57099->[127.0.0.1]:162
	ip = new(SnmptrapdNotificationIpAddress)
	tokenSet = strings.Fields(ipaddress)
	addresses = strings.Split(tokenSet[1], "->")

	ip.Protocol = tokenSet[0]
	ip.SourceHost = strings.TrimLeft(strings.Split(addresses[0], "]")[0], "[")
	ip.SourcePort = strings.Split(addresses[0], ":")[1]
	ip.TargetHost = strings.TrimLeft(strings.Split(addresses[1], "]")[0], "[")
	ip.TargetPort = strings.Split(addresses[1], ":")[1]

	return ip
}

func parseNotification(stdin *os.File) *SnmptrapdNotification {
	// parse the Notification (consumed via stdin) and return a
	// SnmptrapdNotification object.
	//
	// Details of the notification are fed to the program via its standard input.
	// Note that this will always use the SNMPv2-style notification format, with
	// SNMPv1 traps being converted as per RFC 2576, before being passed to the
	// program. The input format is as follows, one entry per line:
	//
	// HOSTNAME
	// The name of the host that sent the notification, as determined by
	// gethostbyaddr(3).
	//
	// IPADDRESS
	// The IP address of the host that sent the notification.
	//
	// VARBINDS
	// A list of variable bindings describing the contents of the notification,
	// one per line. The first token on each line (up until a space) is the OID of
	// the varind, and the remainder of the line is its value. The format of both
	// of these are controlled by the outputOption directive (or similar
	// configuration). The first OID should always be SNMPv2-MIB::sysUpTime.0, and
	// the second should be SNMPv2-MIB::snmpTrapOID.0. The remaining lines will
	// contain the payload varbind list. For SNMPv1 traps, the final OID will be
	// SNMPv2-MIB::snmpTrapEnterprise.0.
	//
	defer stdin.Close()
	var n *SnmptrapdNotification
	var row int

	// Save the original notification message for later use.
	// n.OriginalMessage = stdin

	// Do some stuff.
	n = new(SnmptrapdNotification)
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

func validateNotification(notification *SnmptrapdNotification) {
	switch notification.HOSTNAME {
	case "<UNKONWN>":
		notification.HOSTNAME = SnmpDefaultHostname
	case "\u003cUNKNOWN\u003e":
		notification.HOSTNAME = SnmpDefaultHostname
	}
}

func getVarbind(notification *SnmptrapdNotification, oids []string) *SnmptrapdNotificationVarbind {
	// Lookup a VARBIND by OID from notification.VARBINDS
	//
	var varbind *SnmptrapdNotificationVarbind

	for i, v := range notification.VARBINDS {
		index := indexOf(oids, v.OID)
		if index >= 0 {
			varbind = notification.VARBINDS[i]
			break
		} else {
			varbind = nil
		}
	}
	return varbind
}

func processNotification(notification *SnmptrapdNotification) {
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
	event.Check.Labels = make(map[string]string)
	for _, v := range notification.VARBINDS {
		eventOutput[v.OID] = v.Value
		OidReplacer := strings.NewReplacer(".", "-", ":", "-")
		oid := OidReplacer.Replace(v.OID)
		key := strings.Join([]string{SensuCheckLabelPrefix, oid}, "_")
		event.Check.Labels[key] = v.Value
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
		fmt.Sprintf("http://%s:%s/events", SensuAgentApiHost, SensuAgentApiPort),
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
	var notification *SnmptrapdNotification

	stdin = os.Stdin

	notification = parseNotification(stdin)
	validateNotification(notification)
	processNotification(notification)
}
