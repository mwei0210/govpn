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
	"io"

	"github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
)

const (
	interfaceTap = "tap"
	interfaceTun = "tun"
)

// TAP is a TUN or a TAP interface.
// TODO: rename to something more... generic?
type TAP struct {
	Name   string
	Sink   chan []byte
	dev    io.ReadWriteCloser
	closed bool
}

var (
	taps                    = make(map[string]*TAP)
	errUnsupportedInterface = errors.New("Unsupported interface")
	logTapPrefix            = "tap_"
)

// NewTAP creates a new TUN/TAP virtual interface
func NewTAP(ifaceName string, mtu int) (*TAP, error) {
	tapRaw, err := newTAPer(&ifaceName)
	if err != nil {
		return nil, errors.Wrap(err, "newTAPer")
	}
	tap := TAP{
		Name: ifaceName,
		dev:  tapRaw,
		Sink: make(chan []byte),
	}
	go func() {
		var n int
		var err error
		var buf []byte
		buf0 := make([]byte, mtu)
		buf1 := make([]byte, mtu)
		bufZ := false
		for {
			if bufZ {
				buf = buf0
			} else {
				buf = buf1
			}
			bufZ = !bufZ
			n, err = tap.dev.Read(buf)
			if err != nil {
				if tap.closed {
					return
				}
				logger.WithError(err).WithFields(logrus.Fields{
					"func": logFuncPrefix + "TAP read sink loop",
					"name": tap.Name,
					"mtu":  mtu,
				}).Error("Can not read interface")
				return
				// TODO: need a way to warn consumer that something is wrong
				// TODO: to force peer to just disconnect
				// TODO: use the client/server error channel?
			}
			tap.Sink <- buf[:n]
		}
	}()
	return &tap, nil
}

func (t *TAP) Write(data []byte) (int, error) {
	n, err := t.dev.Write(data)
	return n, errors.Wrapf(err, "t.dev.Write %d", len(data))
}

// Close close TAP/TUN virtual network interface
func (t *TAP) Close() error {
	if t.closed {
		return nil
	}
	err := t.dev.Close()
	if err != nil {
		return errors.Wrap(err, "water.Interface.Close")
	}
	t.closed = true
	return nil
}

// TAPListen opens an existing TAP (creates if none exists)
func TAPListen(ifaceName string, mtu int) (*TAP, error) {
	tap, exists := taps[ifaceName]
	if exists {
		return tap, nil
	}
	tap, err := NewTAP(ifaceName, mtu)
	if err != nil {
		return nil, errors.Wrap(err, "NewTAP")
	}
	taps[ifaceName] = tap
	return tap, nil
}

// LogFields returns a logrus compatible Fields to identity a single
// tap in logs
func (t *TAP) LogFields() logrus.Fields {
	return logrus.Fields{logTapPrefix + "name": t.Name}
}
