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
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/pkg/errors"

	"cypherpunks.ru/govpn"
)

// PeerConfigurer is used by a GoVPN server to figure the configuration
// of a single peer
type PeerConfigurer interface {
	Get(govpn.PeerID) *govpn.PeerConf
}

// MACPeerFinder is used by GoVPN server to figure the PeerID from
// handshake data
type MACPeerFinder interface {
	Find([]byte) (*govpn.PeerID, error)
}

// PeerState hold server side state of a single connecting/connected peer
type PeerState struct {
	peer       *govpn.Peer
	terminator chan struct{}
	tap        *govpn.TAP
}

func (ps *PeerState) LogFields() logrus.Fields {
	fields := ps.peer.LogFields()
	for k, v := range ps.tap.LogFields() {
		fields[k] = v
	}
	return fields
}

// Configuration hold GoVPN server configuration
type Configuration struct {
	BindAddress  string
	ProxyAddress string
	Protocol     govpn.Protocol
	Timeout      time.Duration
}

// Validate return an error if a configuration is invalid
func (c *Configuration) Validate() error {
	if len(c.BindAddress) == 0 {
		return errors.New("Missing BindAddress")
	}
	return nil
}

// LogFields return a logrus compatible logging context
func (c *Configuration) LogFields() logrus.Fields {
	const prefix = "srv_conf_"
	f := logrus.Fields{
		prefix + "bind":     c.BindAddress,
		prefix + "protocol": c.Protocol.String(),
		prefix + "timeout":  c.Timeout.String(),
	}
	if len(c.ProxyAddress) > 0 {
		f[prefix+"proxy"] = c.ProxyAddress
	}
	return f
}

// Server is a GoVPN server instance
type Server struct {
	configuration Configuration
	termSignal    chan interface{}

	idsCache MACPeerFinder
	confs    PeerConfigurer

	handshakes map[string]*govpn.Handshake
	hsLock     sync.RWMutex

	peers     map[string]*PeerState
	peersLock sync.RWMutex

	peersByID     map[govpn.PeerID]string
	peersByIDLock sync.RWMutex

	knownPeers govpn.KnownPeers
	kpLock     sync.RWMutex

	logger *logrus.Logger

	// Error channel receives any kind of routine errors
	Error chan error
}

// LogFields return a logrus compatible logging context
func (s *Server) LogFields() logrus.Fields {
	const prefix = "srv_"
	return logrus.Fields{
		prefix + "hs":    len(s.handshakes),
		prefix + "peers": len(s.peers),
		prefix + "known": len(s.knownPeers),
	}
}

// KnownPeers return GoVPN peers.
// used to get client statistics.
func (s *Server) KnownPeers() *govpn.KnownPeers {
	return &s.knownPeers
}

// NewServer return a configured GoVPN server, to listen network
// connection MainCycle must be executed
func NewServer(serverConf Configuration, peerConfs PeerConfigurer, idsCache MACPeerFinder, logger *logrus.Logger, termSignal chan interface{}) *Server {
	govpn.SetLogger(logger)
	return &Server{
		configuration: serverConf,
		confs:         peerConfs,
		termSignal:    termSignal,
		idsCache:      idsCache,
		handshakes:    make(map[string]*govpn.Handshake),
		peers:         make(map[string]*PeerState),
		peersByID:     make(map[govpn.PeerID]string),
		knownPeers:    govpn.KnownPeers(make(map[string]**govpn.Peer)),
		Error:         make(chan error, 1),
		logger:        logger,
	}
}

// MainCycle main loop that handle connecting/connected client
func (s *Server) MainCycle() {
	switch s.configuration.Protocol {
	case govpn.ProtocolUDP:
		s.startUDP()
	case govpn.ProtocolTCP:
		s.startTCP()
	case govpn.ProtocolALL:
		s.startUDP()
		s.startTCP()
	default:
		s.Error <- errors.New("Unknown protocol specified")
		return
	}

	if len(s.configuration.ProxyAddress) > 0 {
		go s.proxyStart()
	}
	fields := logrus.Fields{"func": logFuncPrefix + "Server.MainCycle"}

	s.logger.WithFields(
		fields,
	).WithFields(
		s.LogFields(),
	).WithFields(
		s.configuration.LogFields(),
	).Info("Starting")

	var needsDeletion bool
	var err error
	hsHeartbeat := time.Tick(s.configuration.Timeout)
	go func() { <-hsHeartbeat }()

MainCycle:
	for {
		select {
		case <-s.termSignal:
			s.logger.WithFields(
				fields,
			).WithFields(
				s.LogFields(),
			).WithFields(
				s.configuration.LogFields(),
			).Info("Terminating")
			for _, ps := range s.peers {
				if err = s.callDown(ps); err != nil {
					s.logger.WithFields(
						fields,
					).WithError(err).WithFields(
						ps.peer.LogFields(),
					).Error("Failed to run callDown")
				}
				if err = ps.tap.Close(); err != nil {
					logrus.WithError(err).WithFields(
						fields,
					).WithFields(
						ps.peer.LogFields(),
					).Error("Can not close TAP")
				}
			}
			// empty value signals that everything is fine
			s.Error <- nil
			break MainCycle
		case <-hsHeartbeat:
			logrus.WithFields(fields).Debug("Heartbeat")
			now := time.Now()
			s.hsLock.Lock()
			for addr, hs := range s.handshakes {
				if hs.LastPing.Add(s.configuration.Timeout).Before(now) {
					logrus.WithFields(
						fields,
					).WithFields(
						hs.LogFields(),
					).Debug("Handshake is expired, deleting")
					hs.Zero()
					delete(s.handshakes, addr)
				}
			}
			s.peersLock.Lock()
			s.peersByIDLock.Lock()
			s.kpLock.Lock()
			for addr, ps := range s.peers {
				ps.peer.BusyR.Lock()
				logrus.WithFields(
					fields,
				).WithFields(
					ps.peer.LogFields(),
				).Debug("Checking peer")
				if ps.peer.LastPing.Add(
					s.configuration.Timeout,
				).Before(now) {
					logrus.WithFields(
						fields,
					).WithFields(
						ps.peer.LogFields(),
					).WithField("now", now.String()).Info("Peer timedout")
					needsDeletion = true
				}
				if ps.peer.IsMarkedForDeletion() {
					logrus.WithFields(
						fields,
					).WithFields(
						ps.peer.LogFields(),
					).Info("Peer is marked as deletion")
					needsDeletion = true
				}
				ps.peer.BusyR.Unlock()
				if needsDeletion {
					logrus.WithFields(
						fields,
					).WithFields(
						ps.peer.LogFields(),
					).Info("Delete peer")
					delete(s.peers, addr)
					delete(s.knownPeers, addr)
					delete(s.peersByID, *ps.peer.ID)
					if err = s.callDown(ps); err != nil {
						logrus.WithError(err).WithFields(
							fields,
						).WithFields(
							ps.peer.LogFields(),
						).Error("Can not execute callDown")
					}
					if err = ps.tap.Close(); err != nil {
						logrus.WithError(err).WithFields(
							fields,
						).WithFields(
							ps.peer.LogFields(),
						).Error("Can not close TAP")
					}
					ps.terminator <- struct{}{}
					needsDeletion = false
				}
			}
			s.hsLock.Unlock()
			s.peersLock.Unlock()
			s.peersByIDLock.Unlock()
			s.kpLock.Unlock()
		}
	}
}
