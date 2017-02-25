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
	"bytes"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/pkg/errors"

	"cypherpunks.ru/govpn"
)

func (c *Client) startTCP() {
	var conn net.Conn
	l := c.logger.WithField("func", logFuncPrefix+"Client.startTCP")
	// initialize using a file descriptor
	if c.config.FileDescriptor > 0 {
		l.WithField("fd", c.config.FileDescriptor).Debug("Connect using file descriptor")
		var err error
		conn, err = net.FileConn(os.NewFile(
			uintptr(c.config.FileDescriptor),
			fmt.Sprintf("fd[%s]", c.config.RemoteAddress),
		))
		if err != nil {
			c.Error <- errors.Wrapf(err, "net.FileConn fd:%d", c.config.FileDescriptor)
			return
		}
	} else {
		// TODO move resolution into the loop, as the name might change over time
		l.WithField("fd", c.config.RemoteAddress).Debug("Connect using TCP")
		remote, err := net.ResolveTCPAddr("tcp", c.config.RemoteAddress)
		if err != nil {
			c.Error <- errors.Wrapf(err, "net.ResolveTCPAdd %s", c.config.RemoteAddress)
			return
		}
		l.WithField("remote", remote.String()).Debug("dial")
		conn, err = net.DialTCP("tcp", nil, remote)
		if err != nil {
			c.Error <- errors.Wrapf(err, "net.DialTCP: %s", remote.String())
			return
		}
	}
	l.WithFields(c.config.LogFields()).Info("Connected")
	c.handleTCP(conn)
}

func (c *Client) handleTCP(conn net.Conn) {
	hs, err := govpn.HandshakeStart(c.config.RemoteAddress, conn, c.config.Peer)
	if err != nil {
		govpn.CloseLog(conn, c.logger, c.LogFields())
		c.Error <- errors.Wrap(err, "govpn.HandshakeStart")
		return
	}
	buf := make([]byte, 2*(govpn.EnclessEnlargeSize+c.config.Peer.MTU)+c.config.Peer.MTU)

	var n int
	var prev int
	var peer *govpn.Peer
	var deadLine time.Time
	var terminator chan struct{}
	fields := logrus.Fields{"func": logFuncPrefix + "Client.handleTCP"}
HandshakeCycle:
	for {
		select {
		case <-c.termination:
			break HandshakeCycle
		default:
		}
		if prev == len(buf) {
			c.logger.WithFields(fields).WithFields(
				c.LogFields(),
			).Debug("Packet timeouted")
			c.timeouted <- struct{}{}
			break HandshakeCycle
		}

		deadLine = time.Now().Add(c.config.Peer.Timeout)
		if err = conn.SetReadDeadline(deadLine); err != nil {
			c.Error <- errors.Wrapf(err, "conn.SetReadDeadline %s", deadLine.String())
			break HandshakeCycle
		}
		n, err = conn.Read(buf[prev:])
		if err != nil {
			c.logger.WithFields(
				fields,
			).WithFields(
				c.LogFields(),
			).Debug("Packet timeouted")
			c.timeouted <- struct{}{}
			break HandshakeCycle
		}

		prev += n
		_, err = c.idsCache.Find(buf[:prev])
		if err != nil {
			c.logger.WithFields(
				fields,
			).WithFields(
				c.LogFields(),
			).WithError(err).Debug("Can't find peer in ids")
			continue
		}
		peer, err = hs.Client(buf[:prev])
		prev = 0
		if err != nil {
			c.logger.WithFields(
				fields,
			).WithError(
				err,
			).WithFields(
				c.LogFields(),
			).Debug("Can't create new peer")
			continue
		}
		c.logger.WithFields(fields).WithFields(c.LogFields()).Info("Handshake completed")
		c.knownPeers = govpn.KnownPeers(map[string]**govpn.Peer{c.config.RemoteAddress: &peer})
		if c.firstUpCall {
			if err = c.postUpAction(); err != nil {
				c.Error <- errors.Wrap(err, "c.postUpAction")
				break HandshakeCycle
			}
			c.firstUpCall = false
		}
		hs.Zero()
		terminator = make(chan struct{})
		go govpn.PeerTapProcessor(peer, c.tap, terminator)
		break HandshakeCycle
	}
	if hs != nil {
		hs.Zero()
	}
	if peer == nil {
		return
	}

	prev = 0
	var i int
TransportCycle:
	for {
		select {
		case <-c.termination:
			break TransportCycle
		default:
		}
		if prev == len(buf) {
			c.logger.WithFields(
				c.LogFields(),
			).Debug("Packet timeouted")
			c.timeouted <- struct{}{}
			break TransportCycle
		}
		if err = conn.SetReadDeadline(time.Now().Add(c.config.Peer.Timeout)); err != nil {
			c.Error <- errors.Wrap(err, "conn.SetReadDeadline")
			break TransportCycle
		}
		n, err = conn.Read(buf[prev:])
		if err != nil {
			c.logger.WithError(
				err,
			).WithFields(
				c.LogFields(),
			).Debug("Connection timeouted")
			c.timeouted <- struct{}{}
			break TransportCycle
		}
		prev += n
	CheckMore:
		if prev < govpn.MinPktLength {
			continue
		}
		i = bytes.Index(buf[:prev], peer.NonceExpect)
		if i == -1 {
			continue
		}
		if !peer.PktProcess(buf[:i+govpn.NonceSize], c.tap, false) {
			c.logger.WithFields(c.LogFields()).Debug("Packet unauthenticated")
			c.timeouted <- struct{}{}
			break TransportCycle
		}
		if atomic.LoadUint64(&peer.BytesIn)+atomic.LoadUint64(&peer.BytesOut) > govpn.MaxBytesPerKey {
			c.logger.WithFields(c.LogFields()).Debug("Rehandshake required")
			c.rehandshaking <- struct{}{}
			break TransportCycle
		}
		copy(buf, buf[i+govpn.NonceSize:prev])
		prev = prev - i - govpn.NonceSize
		goto CheckMore
	}
	if terminator != nil {
		terminator <- struct{}{}
	}
	peer.Zero()
	if err = conn.Close(); err != nil {
		c.Error <- errors.Wrap(err, "conn.Close")
	}
	if err = c.tap.Close(); err != nil {
		c.Error <- errors.Wrap(err, logFuncPrefix+"Client.tap.Close")
	}
}
