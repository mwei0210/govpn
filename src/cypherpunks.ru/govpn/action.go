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
	"os"
	"os/exec"

	"github.com/pkg/errors"
)

// PeerContext hold info about a peer that connect or disconnect
// used for Up, PreUp and Down
type PeerContext struct {
	RemoteAddress string
	Protocol      Protocol
	Config        PeerConf
}

// TunnelAction is an action for either client or server that is
// executed when tunnel goes down
type TunnelAction func(PeerContext) error

// TunnelPreUpAction is an action for client or server that is executed
// after user is authenticated
type TunnelPreUpAction func(PeerContext) (*TAP, error)

// RunScriptAction convert the path to a script into a TunnelAction
func RunScriptAction(path *string) TunnelAction {
	if path == nil {
		return nil
	}
	return func(ctx PeerContext) error {
		_, err := ScriptCall(*path, ctx.Config.Iface, ctx.RemoteAddress)
		return errors.Wrapf(err, "ScriptCall path=%q interface=%q remote=%q", *path, ctx.Config.Iface, ctx.RemoteAddress)
	}
}

// ScriptCall call external program/script.
// You have to specify path to it and (inteface name as a rule) something
// that will be the first argument when calling it. Function will return
// it's output and possible error.
func ScriptCall(path, ifaceName, remoteAddr string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	if _, err := os.Stat(path); err != nil && os.IsNotExist(err) {
		return nil, errors.Wrap(err, "os.Path")
	}
	cmd := exec.Command(path)
	cmd.Env = append(cmd.Env, environmentKeyInterface+"="+ifaceName)
	cmd.Env = append(cmd.Env, environmentKeyRemote+"="+remoteAddr)
	out, err := cmd.CombinedOutput()
	return out, errors.Wrap(err, "cmd.CombinedOutput")
}
