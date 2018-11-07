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
	"net"

	"github.com/sirupsen/logrus"
	"github.com/pkg/errors"

	"cypherpunks.ru/govpn"
)

type udpSender struct {
	conn *net.UDPConn
	addr *net.UDPAddr
}

func (c udpSender) Write(data []byte) (int, error) {
	return c.conn.WriteToUDP(data, c.addr)
}

func (s *Server) startUDP() {
	bind, err := net.ResolveUDPAddr("udp", s.configuration.BindAddress)
	if err != nil {
		s.Error <- errors.Wrap(err, "net.ResolveUDPAddr")
		return
	}
	conn, err := net.ListenUDP("udp", bind)
	if err != nil {
		s.Error <- errors.Wrapf(err, "net.ListenUDP %q", bind.String())
		return
	}

	logger := s.logger.WithFields(s.configuration.LogFields()).WithFields(logrus.Fields{
		"func": logFuncPrefix + "Server.startUDP",
		"bind": bind.String(),
	})

	logger.WithFields(s.LogFields()).Info("Listen")

	udpBufs := make(chan []byte, 1<<8)
	udpBufs <- make([]byte, govpn.MTUMax)
	go func() {
		var buf []byte
		var raddr *net.UDPAddr
		var addr string
		var n int
		var err error
		var ps *PeerState
		var hs *govpn.Handshake
		var addrPrev string
		var exists bool
		var peerID *govpn.PeerID
		var conf *govpn.PeerConf
		for {
			logger.Debug("Waiting for UDP buffer")
			buf = <-udpBufs
			n, raddr, err = conn.ReadFromUDP(buf)
			if err != nil {
				logger.WithFields(s.LogFields()).WithError(err).Debug("Receive failed")
				break
			}
			addr = raddr.String()
			loggerLoop := logger.WithField("addr", addr)

			loggerLoop.Debug("Got UDP buffer, checking if peer exists")
			s.peersLock.RLock()
			ps, exists = s.peers[addr]
			s.peersLock.RUnlock()
			if exists {
				loggerLoop.WithFields(ps.LogFields()).Debug("Already known peer, PktProcess")
				// peer can be mark to delete, but haven't deleted and user reconnect
				// reuse peer in this case
				ps.peer.UnmarkDeletion()
				go func(peer *govpn.Peer, tap *govpn.TAP, buf []byte, n int) {
					if !peer.PktProcess(buf[:n], tap, true) {
						s.Error <- errors.New("peer.PktProcess: failed to process packet")
					}
					udpBufs <- buf
				}(ps.peer, ps.tap, buf, n)
				continue
			}

			loggerLoop.Debug("New peer")
			s.hsLock.RLock()
			hs, exists = s.handshakes[addr]
			s.hsLock.RUnlock()
			if !exists {
				loggerLoop.Debug("No handshake yet, trying to figure peer ID")
				peerID, err = s.idsCache.Find(buf[:n])
				if err != nil {
					loggerLoop.WithFields(s.LogFields()).WithError(err).Debug("Can not lookup for peer in ids")
					udpBufs <- buf
					continue
				}
				if peerID == nil {
					loggerLoop.WithFields(s.LogFields()).Debug("Identity unknown")
					udpBufs <- buf
					continue
				}

				loggerLoop = loggerLoop.WithField("peer_id", peerID.String())
				loggerLoop.Debug("Peer ID found")
				conf = s.confs.Get(*peerID)
				if conf == nil {
					loggerLoop.WithFields(s.configuration.LogFields()).Error("Peer try to connect, but not configured")
					udpBufs <- buf
					continue
				}

				loggerLoop = loggerLoop.WithFields(conf.LogFields(""))
				loggerLoop.Debug("Got configuration, performing handshake")
				hs = govpn.NewHandshake(
					addr,
					udpSender{conn: conn, addr: raddr},
					conf,
				)
				_, err := hs.Server(buf[:n])
				udpBufs <- buf
				if err != nil {
					loggerLoop.WithError(err).WithFields(s.LogFields()).Error("Can not create new peer: handshake failed")
					continue
				}
				loggerLoop.WithFields(s.LogFields()).Info("Hashshake started, continuing for the next packet")

				s.hsLock.Lock()
				s.handshakes[addr] = hs
				s.hsLock.Unlock()
				continue
			}

			loggerLoop.Debug("Already got handshake, finishing it")
			peer, err := hs.Server(buf[:n])
			if err != nil {
				loggerLoop.WithError(err).WithFields(s.LogFields()).Error("Can not create new peer: handshake failed")
				udpBufs <- buf
				continue
			}
			if peer == nil {
				loggerLoop.WithFields(s.LogFields()).Error("Can not continue handshake")
				udpBufs <- buf
				continue
			}

			loggerLoop = loggerLoop.WithFields(peer.LogFields()).WithFields(peer.ConfigurationLogFields())
			loggerLoop.WithFields(s.LogFields()).Info("Handshake completed")

			hs.Zero()
			s.hsLock.Lock()
			delete(s.handshakes, addr)
			s.hsLock.Unlock()

			go func() {
				udpBufs <- make([]byte, govpn.MTUMax)
				udpBufs <- make([]byte, govpn.MTUMax)
			}()
			s.peersByIDLock.RLock()
			addrPrev, exists = s.peersByID[*peer.ID]
			s.peersByIDLock.RUnlock()

			var peerPrev *PeerState
			if exists {
				loggerLoop.Debug("Peer already exists")
				s.peersLock.Lock()

				peerPrev = s.peers[addrPrev]
				if peerPrev == nil {
					exists = false
					s.peersLock.Unlock()
				}
			}

			if exists {
				peerPrev.terminator <- struct{}{}
				psNew := &PeerState{
					peer:       peer,
					tap:        peerPrev.tap,
					terminator: make(chan struct{}),
				}
				peer.Protocol = govpn.ProtocolUDP

				go func(peer *govpn.Peer, tap *govpn.TAP, terminator chan struct{}) {
					govpn.PeerTapProcessor(peer, tap, terminator)
					<-udpBufs
					<-udpBufs
				}(psNew.peer, psNew.tap, psNew.terminator)

				s.peersByIDLock.Lock()
				s.kpLock.Lock()
				delete(s.peers, addrPrev)
				delete(s.knownPeers, addrPrev)
				s.peers[addr] = psNew
				s.knownPeers[addr] = &peer
				s.peersByID[*peer.ID] = addr
				s.peersLock.Unlock()
				s.peersByIDLock.Unlock()
				s.kpLock.Unlock()

				loggerLoop.WithFields(s.LogFields()).Debug("Rehandshake completed")
			} else {
				go func(addr string, peer *govpn.Peer) {
					loggerLoop.Debug("Peer does not exist")
					tap, err := s.callUp(peer, govpn.ProtocolUDP)
					if err != nil {
						loggerLoop.WithFields(s.LogFields()).WithError(err).Error("TAP failed")
						return
					}
					psNew := &PeerState{
						peer:       peer,
						tap:        tap,
						terminator: make(chan struct{}),
					}
					peer.Protocol = govpn.ProtocolUDP
					go func(peer *govpn.Peer, tap *govpn.TAP, terminator chan struct{}) {
						govpn.PeerTapProcessor(peer, tap, terminator)
						<-udpBufs
						<-udpBufs
					}(psNew.peer, psNew.tap, psNew.terminator)
					s.peersLock.Lock()
					s.peersByIDLock.Lock()
					s.kpLock.Lock()
					s.peers[addr] = psNew
					s.knownPeers[addr] = &peer
					s.peersByID[*peer.ID] = addr
					s.peersLock.Unlock()
					s.peersByIDLock.Unlock()
					s.kpLock.Unlock()
					loggerLoop.WithFields(s.LogFields()).Info("Peer initialized")
				}(addr, peer)
			}
			udpBufs <- buf
		}
	}()
}
