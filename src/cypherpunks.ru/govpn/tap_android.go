/*
GoVPN -- simple secure free software virtual private network daemon
Copyright (C) 2016-2017 Bruno Clermont <bruno@robotinfra.com>

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
	"os"
	"syscall"
	"time"

	"github.com/Sirupsen/logrus"
)

func TapListenFileDescriptor(fd uintptr, ifaceName string, mtu int) *TAP {
	tap, exists := taps[ifaceName]
	if exists {
		return tap
	}

	tap = &TAP{
		Name: ifaceName,
		dev:  os.NewFile(fd, ifaceName),
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

				e, ok := err.(*os.PathError)
				if ok && e.Err == syscall.EAGAIN {
					time.Sleep(time.Millisecond * 20)
					continue
				}

				logger.WithError(err).WithFields(logrus.Fields{
					"func": logFuncPrefix + "TUN read sink loop",
					"name": tap.Name,
					"mtu":  mtu,
				}).Error("Can not read interface, stop")
				return
				// TODO: need a way to warn consumer that something is wrong
				// TODO: to force peer to just disconnect
				// TODO: use the client/server error channel?
			} else {
				tap.Sink <- buf[:n]
			}
		}
	}()
	taps[ifaceName] = tap
	return tap
}
