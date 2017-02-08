/*
GoVPN -- simple secure free software virtual private network daemon
Copyright (C) 2014-2016 Sergey Matveev <stargrave@stargrave.org>

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
	"crypto/rand"
	"io"
	"net"

	"github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
)

// Rand is a source of entropy
var Rand = rand.Reader

// EGDRand is a EGD source of entropy
type EGDRand string

// Read n bytes from EGD, blocking mode.
func (egdPath EGDRand) Read(b []byte) (int, error) {
	conn, err := net.Dial("unix", string(egdPath))
	if err != nil {
		return 0, errors.Wrapf(err, "net.Dial unix:%q", string(egdPath))
	}
	defer CloseLog(conn, logger, logrus.Fields{"func": logFuncPrefix + "EGDRand.Read"})
	n, err := conn.Write([]byte{0x02, byte(len(b))})
	if err != nil {
		return 0, errors.Wrapf(err, "conn.Write unix:%q", string(egdPath))
	}
	if n, err = io.ReadFull(conn, b); err != nil {
		return 0, errors.Wrapf(err, wrapIoReadFull, string(egdPath))
	}
	return n, nil
}

// EGDInit set random source to a EGD socket
func EGDInit(path string) {
	Rand = EGDRand(path)
}
