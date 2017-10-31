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
	"io"
	"strings"

	"github.com/pkg/errors"
	"github.com/songgao/water"
)

func newTAPer(ifaceName *string) (io.ReadWriteCloser, error) {
	if strings.HasPrefix(*ifaceName, interfaceTun) {
		return nil, errors.Wrap(errUnsupportedInterface, *ifaceName)
	}
	config := water.Config{}
	config.DeviceType = water.TUN
	config.PlatformSpecificParams.ComponentID = *ifaceName
	config.PlatformSpecificParams.Network = "192.168.1.10/24" // TODO: Bruno figure how to fix that
	output, err := water.New(config)
	return output, errors.Wrap(err, "water.NewTAP")
}
