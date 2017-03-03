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

package main

import (
	"bytes"

	"github.com/pkg/errors"

	"cypherpunks.ru/govpn"
)

func preUpAction(path string) govpn.TunnelPreUpAction {
	if len(path) == 0 {
		return nil
	}

	return func(ctx govpn.PeerContext) (*govpn.TAP, error) {
		result, err := govpn.ScriptCall(path, ctx.Config.Iface, ctx.RemoteAddress)
		if err != nil {
			return nil, errors.Wrap(err, "govpn.ScriptCall")
		}
		if len(ctx.Config.Iface) == 0 {
			sepIndex := bytes.Index(result, []byte{'\n'})
			if sepIndex < 0 {
				sepIndex = len(result)
			}
			ctx.Config.Iface = string(result[:sepIndex])
		}

		if len(ctx.Config.Iface) == 0 {
			return nil, errors.Errorf("Script %q didn't return interface name", path)
		}

		tap, err := govpn.TAPListen(ctx.Config.Iface, ctx.Config.MTU)
		if err != nil {
			return nil, errors.Wrap(err, "govpn.TAPListen")
		}
		return tap, nil
	}
}
