package parsers

import (
	"bufio"
	"log"
	"os"
	"strings"

	snmptypes "github.com/calebhailey/snmptrapd2sensu/types"
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

func ParseNotification(stdin *os.File) *snmptypes.SnmptrapdNotification {
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
