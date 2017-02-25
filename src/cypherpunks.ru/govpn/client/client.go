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
	"fmt"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/agl/ed25519"
	"github.com/pkg/errors"

	"cypherpunks.ru/govpn"
)

const logFuncPrefix = "govpn/client."

// Configuration holds GoVPN client configuration
type Configuration struct {
	PrivateKey          *[ed25519.PrivateKeySize]byte
	Peer                *govpn.PeerConf
	Protocol            govpn.Protocol
	ProxyAddress        string
	ProxyAuthentication string
	RemoteAddress       string
	NoReconnect         bool
	// FileDescriptor allows creating Client from a pre-existing file
	// descriptor. Required for Android. Requires TCP transport.
	FileDescriptor int
}

// Validate returns an error if a configuration is invalid
func (c *Configuration) Validate() error {
	if c.Peer.MTU > govpn.MTUMax {
		return errors.Errorf(
			"Invalid MTU %d, maximum allowable is %d",
			c.Peer.MTU,
			govpn.MTUMax,
		)
	}
	if len(c.RemoteAddress) == 0 {
		return errors.New("Missing RemoteAddress")
	}
	if len(c.Peer.Iface) == 0 && c.Peer.PreUp == nil {
		return errors.New("Missing InterfaceName or PreUp")
	}
	if c.Protocol != govpn.ProtocolTCP && c.Protocol != govpn.ProtocolUDP {
		return errors.Errorf("Invalid protocol %d for client", c.Protocol)
	}
	if c.FileDescriptor > 0 && c.Protocol != govpn.ProtocolTCP {
		return errors.Errorf(
			"Connect with file descriptor requires protocol %s",
			govpn.ProtocolTCP.String(),
		)
	}
	return nil
}

// LogFields returns a logrus compatible logging context
func (c *Configuration) LogFields() logrus.Fields {
	const prefix = "client_conf_"
	f := c.Peer.LogFields(prefix)
	f[prefix+"protocol"] = c.Protocol.String()
	f[prefix+"no_reconnect"] = c.NoReconnect
	if len(c.ProxyAddress) > 0 {
		f[prefix+"proxy"] = c.ProxyAddress
	}
	if c.FileDescriptor > 0 {
		f[prefix+"remote"] = fmt.Sprintf(
			"fd:%d(%s)", c.FileDescriptor, c.RemoteAddress,
		)
	} else {
		f[prefix+"remote"] = c.RemoteAddress
	}
	return f
}

func (c *Configuration) isProxy() bool {
	return len(c.ProxyAddress) > 0
}

// Client is a GoVPN client
type Client struct {
	idsCache      *govpn.MACCache
	tap           *govpn.TAP
	knownPeers    govpn.KnownPeers
	timeouted     chan struct{}
	rehandshaking chan struct{}
	termination   chan struct{}
	firstUpCall   bool
	termSignal    chan interface{}
	config        Configuration
	logger        *logrus.Logger

	// Error channel receives any kind of routine errors
	Error chan error
}

// LogFields returns a logrus compatible logging context
func (c *Client) LogFields() logrus.Fields {
	const prefix = "client_"
	f := logrus.Fields{
		prefix + "remote": c.config.RemoteAddress,
	}
	if c.tap != nil {
		f[prefix+"interface"] = c.tap.Name
	}
	if c.config.Peer != nil {
		f[prefix+"id"] = c.config.Peer.ID.String()
	}
	return f
}

func (c *Client) postDownAction() error {
	if c.config.Peer.Down == nil {
		return nil
	}
	err := c.config.Peer.Down(govpn.PeerContext{
		RemoteAddress: c.config.RemoteAddress,
		Protocol:      c.config.Protocol,
		Config:        *c.config.Peer,
	})
	return errors.Wrap(err, "c.config.Peer.Down")
}

func (c *Client) postUpAction() error {
	if c.config.Peer.Up == nil {
		return nil
	}
	err := c.config.Peer.Up(govpn.PeerContext{
		RemoteAddress: c.config.RemoteAddress,
		Protocol:      c.config.Protocol,
		Config:        *c.config.Peer,
	})
	return errors.Wrap(err, "c.config.Peer.Up")
}

// KnownPeers returns GoVPN peers. Always 1. Used to get client statistics.
func (c *Client) KnownPeers() *govpn.KnownPeers {
	return &c.knownPeers
}

// MainCycle main loop of a connecting/connected client
func (c *Client) MainCycle() {
	var err error
	l := c.logger.WithFields(logrus.Fields{"func": logFuncPrefix + "Client.MainCycle"})
	l.WithFields(
		c.LogFields(),
	).WithFields(
		c.config.LogFields(),
	).Info("Starting...")

	// if available, run PreUp, it might create interface
	if c.config.Peer.PreUp != nil {
		l.Debug("Running PreUp")
		if c.tap, err = c.config.Peer.PreUp(govpn.PeerContext{
			RemoteAddress: c.config.RemoteAddress,
			Protocol:      c.config.Protocol,
			Config:        *c.config.Peer,
		}); err != nil {
			c.Error <- errors.Wrap(err, "c.config.Peer.PreUp")
			return
		}
		l.Debug("PreUp success")
	} else {
		l.Debug("No PreUp to run")
	}

	// if TAP wasn't set by PreUp, listen here
	if c.tap == nil {
		l.WithField("asking", c.config.Peer.Iface).Debug("No interface, try to listen")
		c.tap, err = govpn.TAPListen(c.config.Peer.Iface, c.config.Peer.MTU)
		if err != nil {
			c.Error <- errors.Wrapf(
				err,
				"govpn.TAPListen inteface:%s mtu:%d",
				c.config.Peer.Iface, c.config.Peer.MTU,
			)
			return
		}
	}
	c.config.Peer.Iface = c.tap.Name
	l.WithFields(c.LogFields()).Debug("Got interface, start main loop")

MainCycle:
	for {
		c.timeouted = make(chan struct{})
		c.rehandshaking = make(chan struct{})
		c.termination = make(chan struct{})
		switch c.config.Protocol {
		case govpn.ProtocolUDP:
			l.Debug("Start UDP")
			go c.startUDP()
		case govpn.ProtocolTCP:
			l.Debug("Start TCP")
			if c.config.isProxy() {
				go c.proxyTCP()
			} else {
				go c.startTCP()
			}
		}
		select {
		case <-c.termSignal:
			l.WithFields(c.LogFields()).Debug("Finish")
			c.termination <- struct{}{}
			// empty value signals that everything is fine
			c.Error <- nil
			break MainCycle
		case <-c.timeouted:
			if c.config.NoReconnect {
				l.Debug("No reconnect, stop")
				c.Error <- nil
				break MainCycle
			}
			l.WithField("timeout", c.config.Peer.Timeout.String()).Debug("Sleep")
			time.Sleep(c.config.Peer.Timeout)
		case <-c.rehandshaking:
		}
		close(c.timeouted)
		close(c.rehandshaking)
		close(c.termination)
	}
	l.WithFields(c.config.LogFields()).Debug("Run post down action")
	if err = c.postDownAction(); err != nil {
		c.Error <- errors.Wrap(err, "c.postDownAction")
	}
}

// NewClient returns a configured GoVPN client, to trigger connection
// MainCycle must be executed.
func NewClient(conf Configuration, logger *logrus.Logger, termSignal chan interface{}) (*Client, error) {
	client := Client{
		idsCache:    govpn.NewMACCache(),
		firstUpCall: true,
		config:      conf,
		termSignal:  termSignal,
		Error:       make(chan error, 1),
		knownPeers:  govpn.KnownPeers(make(map[string]**govpn.Peer)),
		logger:      logger,
	}
	govpn.SetLogger(client.logger)
	confs := map[govpn.PeerID]*govpn.PeerConf{*conf.Peer.ID: conf.Peer}
	if err := client.idsCache.Update(&confs); err != nil {
		return nil, errors.Wrap(err, "client.idsCache.Update")
	}
	return &client, nil
}
