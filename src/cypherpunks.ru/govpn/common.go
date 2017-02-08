/*
GoVPN -- simple secure free software virtual private network daemon
Copyright (C) 2014-2017 Sergey Matveev <stargrave@stargrave.org>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package govpn

import (
	"encoding/hex"
	"encoding/json"
	"runtime"
	"strings"
	"time"

	"github.com/pkg/errors"
)

const (
	// ProtocolUDP is UDP transport protocol
	ProtocolUDP Protocol = iota
	// ProtocolTCP is TCP transport protocol
	ProtocolTCP
	// ProtocolALL is TCP+UDP transport protocol
	ProtocolALL

	EtherSize = 14
	// MTUMax is maximum MTU size of Ethernet packet
	MTUMax = 9000 + EtherSize + 1
	// MTUDefault is default MTU size of Ethernet packet
	MTUDefault = 1500 + EtherSize + 1

	ENV_IFACE  = "GOVPN_IFACE"
	ENV_REMOTE = "GOVPN_REMOTE"

	wrapNewProtocolFromString = "NewProtocolFromString"
)

var (
	// Version holds release string set at build time
	Version      string
	protocolText = map[Protocol]string{
		ProtocolUDP: "udp",
		ProtocolTCP: "tcp",
		ProtocolALL: "all",
	}
	// TimeoutDefault is default timeout value for various network operations
	TimeoutDefault = 60 * time.Second
)

// Protocol is a GoVPN supported protocol: either UDP, TCP or both
type Protocol int

// String converts a Protocol into a string
func (p Protocol) String() string {
	return protocolText[p]
}

// MarshalJSON returns a JSON string from a protocol
func (p Protocol) MarshalJSON() ([]byte, error) {
	str := p.String()
	output, err := json.Marshal(&str)
	return output, errors.Wrap(err, "json.Marshal")
}

// UnmarshalJSON converts a JSON string into a Protocol
func (p *Protocol) UnmarshalJSON(encoded []byte) error {
	var str string
	if err := json.Unmarshal(encoded, &str); err != nil {
		return errors.Wrapf(err, "Can't unmarshall to string %q", hex.EncodeToString(encoded))
	}
	proto, err := NewProtocolFromString(str)
	if err != nil {
		return errors.Wrap(err, wrapNewProtocolFromString)
	}
	*p = proto
	return nil
}

// UnmarshalYAML converts a YAML string into a Protocol
func (p *Protocol) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var str string
	err := unmarshal(&str)
	if err != nil {
		return errors.Wrap(err, "unmarshall")
	}

	proto, err := NewProtocolFromString(str)
	if err != nil {
		return errors.Wrap(err, wrapNewProtocolFromString)
	}
	*p = proto
	return nil
}

// NewProtocolFromString converts a string into a govpn.Protocol
func NewProtocolFromString(p string) (Protocol, error) {
	lowP := strings.ToLower(p)
	for k, v := range protocolText {
		if strings.ToLower(v) == lowP {
			return k, nil
		}
	}

	choices := make([]string, len(protocolText))
	var index = 0
	for k, v := range protocolText {
		if v == p {
			z := k
			p = &z
			return nil
		}
		choices[index] = v
		index++
	}

	return Protocol(-1), errors.Errorf("Invalid protocol %q: %s", p, strings.Join(choices, ","))
}

// SliceZero zeros each byte.
func SliceZero(data []byte) {
	for i := 0; i < len(data); i++ {
		data[i] = 0
	}
}

func VersionGet() string {
	return "GoVPN version " + Version + " built with " + runtime.Version()
}
