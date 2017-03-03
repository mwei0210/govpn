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

package client

import (
	"net"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"

	"cypherpunks.ru/govpn"
)

func (c *Client) startUDP() {
	l := c.logger.WithField("func", "startUDP")

	// TODO move resolution into the loop, as the name might change over time
	l.Debug("Resolving UDP address")
	remote, err := net.ResolveUDPAddr("udp", c.config.RemoteAddress)
	if err != nil {
		c.Error <- errors.Wrapf(err, "net.ResolveUDPAddr %s", c.config.RemoteAddress)
		return
	}
	l.WithField("remote", remote.String()).Debug("dial")
	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		c.Error <- errors.Wrapf(err, "net.DialUDP %s", c.config.RemoteAddress)
		return
	}
	l.WithFields(c.config.LogFields()).Info("Connected")

	l.Debug("Handshake starting")
	hs, err := govpn.HandshakeStart(c.config.RemoteAddress, conn, c.config.Peer)
	if err != nil {
		govpn.CloseLog(conn, c.logger, c.LogFields())
		c.Error <- errors.Wrap(err, "govpn.HandshakeStart")
		return
	}
	l.Debug("Handshake completed")

	buf := make([]byte, c.config.Peer.MTU*2)
	var n int
	var timeouts int
	var peer *govpn.Peer
	var deadLine time.Time
	var terminator chan struct{}
	timeout := int(c.config.Peer.Timeout.Seconds())
	l.Debug("Main cycle")

MainCycle:
	for {
		select {
		case <-c.termination:
			break MainCycle
		default:
		}

		deadLine = time.Now().Add(time.Second)
		if err = conn.SetReadDeadline(deadLine); err != nil {
			c.Error <- errors.Wrapf(err, "conn.SetReadDeadline %s", deadLine.String())
			break MainCycle
		}
		l.Debug("conn.Read")
		n, err = conn.Read(buf)
		if timeouts >= timeout {
			l.WithFields(c.LogFields()).Debug("Connection timeouted")
			c.timeouted <- struct{}{}
			break
		}
		if err != nil {
			l.WithError(err).WithFields(c.LogFields()).Debug("Can not read from connection")
			timeouts++
			continue
		}
		if peer != nil {
			c.logger.WithFields(c.LogFields()).Debug("No peer yet, processing packet")
			if peer.PktProcess(buf[:n], c.tap, true) {
				l.WithFields(c.LogFields()).Debug("Packet processed")
				timeouts = 0
			} else {
				l.WithFields(c.LogFields()).Debug("Packet unauthenticated")
				timeouts++
			}
			if atomic.LoadUint64(&peer.BytesIn)+atomic.LoadUint64(&peer.BytesOut) > govpn.MaxBytesPerKey {
				l.WithFields(c.LogFields()).Debug("Rehandshake required")
				c.rehandshaking <- struct{}{}
				break MainCycle
			}
			continue
		}
		if _, err = c.idsCache.Find(buf[:n]); err != nil {
			l.WithError(err).WithFields(c.LogFields()).Debug("Identity invalid")
			continue
		}
		timeouts = 0
		peer, err = hs.Client(buf[:n])
		if err != nil {
			c.Error <- errors.Wrap(err, "hs.Client")
			continue
		}
		// no error, but handshake not yet completed
		if peer == nil {
			continue
		}
		l.WithFields(c.LogFields()).Info("Handshake completed")
		c.knownPeers = govpn.KnownPeers(map[string]**govpn.Peer{c.config.RemoteAddress: &peer})
		if err = c.postUpAction(); err != nil {
			c.Error <- errors.Wrap(err, "c.postUpAction")
			continue
		}
		hs.Zero()
		terminator = make(chan struct{})
		go govpn.PeerTapProcessor(peer, c.tap, terminator)
	}
	if terminator != nil {
		terminator <- struct{}{}
	}
	if hs != nil {
		hs.Zero()
	}
	if err = conn.Close(); err != nil {
		c.Error <- errors.Wrap(err, "conn.Close")
	}
	if err = c.tap.Close(); err != nil {
		c.Error <- errors.Wrap(err, logFuncPrefix+"Client.tap.Close")
	}
}
