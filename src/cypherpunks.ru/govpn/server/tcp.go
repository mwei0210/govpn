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

package server

import (
	"bytes"
	"net"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/pkg/errors"

	"cypherpunks.ru/govpn"
)

func (s *Server) startTCP() {
	bind, err := net.ResolveTCPAddr("tcp", s.configuration.BindAddress)
	if err != nil {
		s.Error <- errors.Wrap(err, "net.ResolveTCPAddr")
		return
	}
	listener, err := net.ListenTCP("tcp", bind)
	if err != nil {
		s.Error <- errors.Wrapf(err, "net.ListenTCP %q", bind.String())
		return
	}
	fields := logrus.Fields{
		"func": logFuncPrefix + "Server.startTCP",
		"bind": bind.String(),
	}
	s.logger.WithFields(
		fields,
	).WithFields(
		s.LogFields(),
	).WithFields(
		s.configuration.LogFields(),
	).Info("Listen")
	go func() {
		for {
			conn, err := listener.AcceptTCP()
			if err != nil {
				s.logger.WithError(err).WithFields(
					fields,
				).WithFields(
					s.LogFields(),
				).Error("Failed to accept TCP connection")
				continue
			}
			go s.handleTCP(conn)
		}
	}()
}

func (s *Server) handleTCP(conn net.Conn) {
	addr := conn.RemoteAddr().String()
	buf := make([]byte, govpn.EnclessEnlargeSize+2*govpn.MTUMax)
	var n int
	var err error
	var prev int
	var hs *govpn.Handshake
	var ps *PeerState
	var peer *govpn.Peer
	var deadLine time.Time
	var tap *govpn.TAP
	var conf *govpn.PeerConf
	fields := logrus.Fields{
		"func":   logFuncPrefix + "Server.handleTCP",
		"remote": addr,
	}
	for {
		if prev == len(buf) {
			// TODO log why
			break
		}

		deadLine = time.Now().Add(govpn.TimeoutDefault)
		if err = conn.SetReadDeadline(deadLine); err != nil {
			s.Error <- errors.Wrapf(err, "conn.SetReadDeadline %s", deadLine.String())
			return
		}
		n, err = conn.Read(buf[prev:])
		if err != nil {
			s.logger.WithFields(
				fields,
			).WithFields(
				s.LogFields(),
			).WithError(
				err,
			).Debug("Can not read connection: either EOFed or timeouted")
			break
		}
		prev += n
		peerID, err := s.idsCache.Find(buf[:prev])
		if err != nil {
			s.logger.WithFields(
				fields,
			).WithFields(
				s.LogFields(),
			).WithError(err).Debug("Can not lookup for peer in ids")
			continue
		}
		if peerID == nil {
			s.logger.WithFields(
				fields,
			).WithFields(
				s.LogFields(),
			).Debug("Can not find peer")
			continue
		}
		if hs == nil {
			conf = s.confs.Get(*peerID)
			if conf == nil {
				s.logger.WithFields(
					fields,
				).WithFields(
					s.LogFields(),
				).WithFields(
					s.configuration.LogFields(),
				).Error("Configuration get failed")
				break
			}
			hs = govpn.NewHandshake(addr, conn, conf)
		}
		peer, err = hs.Server(buf[:prev])
		if err != nil {
			s.logger.WithFields(
				fields,
			).WithError(err).WithFields(
				s.LogFields(),
			).Error("Can not create new peer")
			continue
		}
		prev = 0
		if peer == nil {
			continue
		}

		s.logger.WithFields(
			fields,
		).WithFields(
			s.LogFields(),
		).WithFields(
			peer.LogFields(),
		).Info("Handshake completed")

		hs.Zero()
		s.peersByIDLock.RLock()
		addrPrev, exists := s.peersByID[*peer.ID]
		s.peersByIDLock.RUnlock()

		if exists {
			s.peersLock.Lock()
			s.peers[addrPrev].terminator <- struct{}{}
			tap = s.peers[addrPrev].tap
			ps = &PeerState{
				peer:       peer,
				tap:        tap,
				terminator: make(chan struct{}),
			}
			peer.Protocol = govpn.ProtocolTCP
			go govpn.PeerTapProcessor(ps.peer, ps.tap, ps.terminator)
			s.peersByIDLock.Lock()
			s.kpLock.Lock()
			delete(s.peers, addrPrev)
			delete(s.knownPeers, addrPrev)
			s.peers[addr] = ps
			s.knownPeers[addr] = &peer
			s.peersByID[*peer.ID] = addr
			s.peersLock.Unlock()
			s.peersByIDLock.Unlock()
			s.kpLock.Unlock()
			s.logger.WithFields(
				fields,
			).WithFields(
				s.LogFields(),
			).WithFields(
				peer.LogFields(),
			).Debug("Rehandshake completed")
		} else {
			tap, err = s.callUp(peer, govpn.ProtocolTCP)
			if err != nil {
				s.logger.WithFields(
					fields,
				).WithFields(
					s.LogFields(),
				).WithFields(
					peer.LogFields(),
				).WithError(err).Error("TAP failed")
				peer = nil
				break
			}
			ps = &PeerState{
				peer:       peer,
				tap:        tap,
				terminator: make(chan struct{}, 1),
			}
			peer.Protocol = govpn.ProtocolTCP
			go govpn.PeerTapProcessor(ps.peer, ps.tap, ps.terminator)
			s.peersLock.Lock()
			s.peersByIDLock.Lock()
			s.kpLock.Lock()
			s.peers[addr] = ps
			s.peersByID[*peer.ID] = addr
			s.knownPeers[addr] = &peer
			s.peersLock.Unlock()
			s.peersByIDLock.Unlock()
			s.kpLock.Unlock()
			s.logger.WithFields(
				fields,
			).WithFields(
				s.LogFields(),
			).WithFields(
				peer.LogFields(),
			).Info("Peer created")
		}
		break
	}
	if hs != nil {
		hs.Zero()
	}
	if peer == nil {
		return
	}

	prev = 0
	var i int
	for {
		if prev == len(buf) {
			break
		}
		deadLine = time.Now().Add(conf.Timeout)
		if err = conn.SetReadDeadline(deadLine); err != nil {
			s.Error <- errors.Wrapf(err, "conn.SetReadDeadline %s", deadLine.String())
			return
		}
		n, err = conn.Read(buf[prev:])
		if err != nil {
			s.logger.WithFields(
				fields,
			).WithFields(
				s.LogFields(),
			).WithError(
				err,
			).Debug("Can not read connection: either EOFed or timeouted")
			break
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
		if !peer.PktProcess(buf[:i+govpn.NonceSize], tap, false) {
			s.logger.WithFields(
				fields,
			).WithFields(
				s.LogFields(),
			).WithFields(
				peer.LogFields(),
			).Warn("Packet unauthenticated")
			break
		}
		copy(buf, buf[i+govpn.NonceSize:prev])
		prev = prev - i - govpn.NonceSize
		goto CheckMore
	}
	peer.Zero()
}
