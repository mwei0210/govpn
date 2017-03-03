/*
GoVPN -- simple secure free software virtual private network daemon
Copyright (C) 2014-2017 Sergey Matveev <stargrave@stargrave.org>
              2016-2017 Bruno Clermont <bruno@robotinfra.com>

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
	config := water.Config{}

	if len(*ifaceName) == 0 {
		return nil, errors.New("Can not figure interface type, empty name")
	}

	if strings.HasPrefix(*ifaceName, interfaceTap) {
		config.DeviceType = water.TAP
		if len(*ifaceName) > len(interfaceTap) {
			config.Name = *ifaceName
		}
	} else if strings.HasPrefix(*ifaceName, interfaceTun) {
		config.DeviceType = water.TUN
		if len(*ifaceName) > len(interfaceTun) {
			config.Name = *ifaceName
		}
	} else {
		return nil, errors.Errorf("Unrecognized interface name %q", *ifaceName)
	}

	output, err := water.New(config)
	if err != nil {
		return nil, errors.Wrap(err, "water.New")
	}
	*ifaceName = output.Name()
	return output, nil
}
