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

package main

import (
	"io/ioutil"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"

	"cypherpunks.ru/govpn"
)

const refreshRate = time.Minute

var (
	confs    peerConfigurations
	idsCache *govpn.MACCache
	logger   *logrus.Logger
)

type peerConfigurations map[govpn.PeerID]*govpn.PeerConf

func (peerConfs peerConfigurations) Get(peerID govpn.PeerID) *govpn.PeerConf {
	pc, exists := peerConfs[peerID]
	if !exists {
		return nil
	}
	return pc
}

type peerConf struct {
	Name        string `yaml:"name"`
	Iface       string `yaml:"iface"`
	MTU         int    `yaml:"mtu"`
	Up          string `yaml:"up"`
	Down        string `yaml:"down"`
	TimeoutInt  int    `yaml:"timeout"`
	Noise       bool   `yaml:"noise"`
	CPR         int    `yaml:"cpr"`
	Encless     bool   `yaml:"encless"`
	TimeSync    int    `yaml:"timesync"`
	VerifierRaw string `yaml:"verifier"`
}

func confRead() (*map[govpn.PeerID]*govpn.PeerConf, error) {
	data, err := ioutil.ReadFile(*confPath)
	if err != nil {
		return nil, errors.Wrap(err, "ioutil.ReadFile")
	}
	confsRaw := new(map[string]peerConf)
	err = yaml.Unmarshal(data, confsRaw)
	if err != nil {
		return nil, errors.Wrap(err, "yaml.Unmarshal")
	}

	confs := make(map[govpn.PeerID]*govpn.PeerConf, len(*confsRaw))
	for name, pc := range *confsRaw {
		verifier, err := govpn.VerifierFromString(pc.VerifierRaw)
		if err != nil {
			return nil, errors.Wrap(err, "govpn.VerifierFromString")
		}
		if pc.Encless {
			pc.Noise = true
		}
		if pc.MTU == 0 {
			pc.MTU = govpn.MTUDefault
		}
		if pc.MTU > govpn.MTUMax {
			logger.WithFields(logrus.Fields{
				"bind":         *bindAddr,
				"previous_mtu": pc.MTU,
				"new_mtu":      govpn.MTUMax,
			}).Warning("Overriden MTU")
			pc.MTU = govpn.MTUMax
		}
		conf := govpn.PeerConf{
			Verifier: verifier,
			ID:       verifier.ID,
			Name:     name,
			Iface:    pc.Iface,
			MTU:      pc.MTU,
			PreUp:    preUpAction(pc.Up),
			Down:     govpn.RunScriptAction(&pc.Down),
			Noise:    pc.Noise,
			CPR:      pc.CPR,
			Encless:  pc.Encless,
			TimeSync: pc.TimeSync,
		}
		if pc.TimeoutInt <= 0 {
			conf.Timeout = govpn.TimeoutDefault
		} else {
			conf.Timeout = time.Second * time.Duration(pc.TimeoutInt)
		}
		confs[*verifier.ID] = &conf
	}
	return &confs, nil
}

func confRefresh() error {
	fields := logrus.Fields{
		"func": "confRefresh",
	}
	logger.WithFields(fields).Debug("Checking configuration file")
	newConfs, err := confRead()
	if err != nil {
		return errors.Wrap(err, "confRead")
	}
	confs = *newConfs
	logger.WithFields(
		fields,
	).WithField(
		"newConfs",
		len(confs),
	).Debug("idsCache.Update")
	if err = idsCache.Update(newConfs); err != nil {
		return errors.Wrap(err, "idsCache.Update")
	}
	logger.WithFields(fields).Debug("Done")
	return nil
}

func confInit() {
	idsCache = govpn.NewMACCache()
	err := confRefresh()
	fields := logrus.Fields{"func": "confInit"}
	if err != nil {
		logger.WithError(err).WithFields(
			fields,
		).Fatal("Can not perform initial configuration read")
	}
	go func() {
		for {
			time.Sleep(refreshRate)
			if err = confRefresh(); err != nil {
				logger.WithError(err).WithFields(
					fields,
				).Error("Can not refresh configuration")
			}
		}
	}()
}
