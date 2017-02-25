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
	"github.com/pkg/errors"

	"cypherpunks.ru/govpn"
)

const logFuncPrefix = "govpn/server."

var (
	errMisconfiguredTap = errors.New("No PreUp and no Iface, can't create interface")
	errPreUpNoTap       = errors.New("PreUp didn't returned an interface, and Iface is unset")
)

func (s *Server) callUp(peer *govpn.Peer, proto govpn.Protocol) (*govpn.TAP, error) {
	var (
		tap           *govpn.TAP
		conf          = s.confs.Get(*peer.ID)
		err           error
		isConfigIface = len(conf.Iface) != 0
		fields        = s.LogFields()
	)
	fields["func"] = logFuncPrefix + "Server.callUp"

	if !isConfigIface && conf.PreUp == nil {
		return nil, errors.Wrapf(errMisconfiguredTap, "interface:%q, PreUp:%q", conf.Iface, conf.PreUp)
	}

	if conf.PreUp != nil {
		s.logger.WithFields(fields).Debug("PreUp defined, execute it")
		tap, err = conf.PreUp(govpn.PeerContext{
			RemoteAddress: peer.Addr,
			Protocol:      proto,
			Config:        *conf,
		})
		if err != nil {
			return nil, errors.Wrap(err, "conf.PreUp")
		}
		s.logger.WithFields(fields).WithField("tap", tap).Debug("PreUp finished")
	} else {
		s.logger.WithFields(fields).Debug("No PreUp defined, skip")
	}

	if tap == nil {
		s.logger.WithFields(fields).Debug("PreUp didn't returned an interface, create one")
		if !isConfigIface {
			return nil, errors.Wrapf(errPreUpNoTap, "interface:%q tap:%q", conf.Iface, tap)
		}

		if tap, err = govpn.TAPListen(conf.Iface, peer.MTU); err != nil {
			return nil, errors.Wrap(err, "govpn.TAPListen")
		}
	}

	conf.Iface = tap.Name

	if conf.Up == nil {
		s.logger.WithFields(fields).Debug("Got interface, no Up")
		return tap, nil
	}
	s.logger.WithFields(fields).Debug("Got interface, execute Up")

	err = conf.Up(govpn.PeerContext{
		RemoteAddress: peer.Addr,
		Protocol:      proto,
		Config:        *conf,
	})
	if err != nil {
		return nil, errors.Wrap(err, "conf.Up")
	}
	s.logger.WithFields(fields).Debug("Got interface, Up executed")
	return tap, nil
}

func (s *Server) callDown(ps *PeerState) error {
	fields := s.LogFields()
	fields["func"] = logFuncPrefix + "Server.callDown"

	conf := s.confs.Get(*ps.peer.ID)
	if conf == nil {
		s.logger.WithFields(fields).Error("Couldn't get configuration")
		return nil
	}
	if conf.Down == nil {
		s.logger.WithFields(fields).Debug("No Down, skip")
		return nil
	}
	s.logger.WithFields(fields).Debug("Execute Down")
	err := conf.Down(govpn.PeerContext{
		RemoteAddress: ps.peer.Addr,
		Config:        *conf,
		Protocol:      ps.peer.Protocol,
	})
	s.logger.WithFields(fields).Debug("Down executed")
	return errors.Wrap(err, "peer.Down")
}
