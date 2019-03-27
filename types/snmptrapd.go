package types

import (
  "fmt"
  "strings"
)

type SnmptrapdNotificationVarbind struct {
	OID   string `json:"oid"`
	Value string `json:"value"`
	Type  string `json:"type"`
}

type SnmptrapdNotificationIpAddress struct {
	Protocol   string `json:"protocol"`
	SourceIP   string `json:"source_ip"`
	SourcePort string `json:"source_port"`
	TargetIP   string `json:"target_ip"`
	TargetPort string `json:"target_port"`
}

type SnmptrapdNotification struct {
	HOSTNAME  string                          `json:"hostname"`
	IPADDRESS *SnmptrapdNotificationIpAddress `json:"ipaddress"`
	VARBINDS  []*SnmptrapdNotificationVarbind `json:"varbinds"`
}

func (object *SnmptrapdNotification) String() string {
	var output strings.Builder
	fmt.Fprintf(&output, "HOSTNAME: %v\n", object.HOSTNAME)
	fmt.Fprintf(&output, "IPADDRESS: %v:%v\n", object.IPADDRESS.SourceIP, object.IPADDRESS.SourcePort)
	for _, v := range object.VARBINDS {
		fmt.Fprintf(&output, "VARBIND: %v: %v\n", v.OID, v.Value)
	}
	return output.String()
}
