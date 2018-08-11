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
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/agl/ed25519"
)

// PeerConf is configuration of a single GoVPN Peer (client)
type PeerConf struct {
	ID       *PeerID
	Name     string
	Iface    string
	MTU      int
	PreUp    TunnelPreUpAction
	Up       TunnelAction
	Down     TunnelAction
	Timeout  time.Duration
	Noise    bool
	CPR      int
	Encless  bool
	TimeSync int

	// This is passphrase verifier, client side only
	Verifier *Verifier
	// This field exists only on client's side
	DSAPriv *[ed25519.PrivateKeySize]byte
}

// LogFields return a logrus compatible logging context
func (pc *PeerConf) LogFields(rootPrefix string) logrus.Fields {
	p := rootPrefix + "peerconf_"
	output := logrus.Fields{
		p + "peer_name": pc.Name,
		p + "mtu":       pc.MTU,
		p + "interface": pc.Iface,
		p + "noise":     pc.Noise,
		p + "cpr":       pc.CPR,
		p + "encless":   pc.Encless,
		p + "timesync":  pc.TimeSync,
		p + "timeout":   pc.Timeout.String(),
		p + "pre_up":    pc.PreUp != nil,
		p + "up":        pc.Up != nil,
		p + "down":      pc.Down != nil,
	}
	if pc.ID != nil {
		output[p+"id"] = pc.ID.String()
	}
	return output
}
