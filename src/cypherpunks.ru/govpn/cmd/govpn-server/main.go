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

// Simple secure, DPI/censorship-resistant free software VPN daemon.
package main

import (
	"flag"
	"fmt"

	"github.com/Sirupsen/logrus"

	"cypherpunks.ru/govpn"
	"cypherpunks.ru/govpn/server"
)

var (
	bindAddr = flag.String("bind", "[::]:1194", "Bind to address")
	proto    = flag.String("proto", "udp", "Protocol to use: udp, tcp or all")
	confPath = flag.String("conf", "peers.yaml", "Path to configuration YAML")
	stats    = flag.String("stats", "", "Enable stats retrieving on host:port")
	proxy    = flag.String("proxy", "", "Enable HTTP proxy on host:port")
	egdPath  = flag.String("egd", "", "Optional path to EGD socket")
	syslog   = flag.Bool("syslog", false, "Enable logging to syslog")
	version  = flag.Bool("version", false, "Print version information")
	warranty = flag.Bool("warranty", false, "Print warranty information")
	logLevel = flag.String("loglevel", "warning", "Logging level")
)

func main() {
	var err error
	fields := logrus.Fields{"func": "main"}

	flag.Parse()
	if *warranty {
		fmt.Println(govpn.Warranty)
		return
	}
	if *version {
		fmt.Println(govpn.VersionGet())
		return
	}

	logger, err = govpn.NewLogger(*logLevel, *syslog)
	if err != nil {
		logrus.WithFields(
			fields,
		).WithError(err).Fatal("Can not initialize logging")
	}
	govpn.SetLogger(logger)

	if *egdPath != "" {
		logger.WithField(
			"egd_path", *egdPath,
		).WithFields(
			fields,
		).Debug("Init EGD")
		govpn.EGDInit(*egdPath)
	}

	confInit()

	serverConfig := server.Configuration{
		BindAddress:  *bindAddr,
		ProxyAddress: *proxy,
		Timeout:      govpn.TimeoutDefault,
	}
	if serverConfig.Protocol, err = govpn.NewProtocolFromString(*proto); err != nil {
		logger.WithError(err).WithFields(
			fields,
		).WithField(
			"proto", *proto,
		).Fatal("Invalid protocol")
	}
	if err = serverConfig.Validate(); err != nil {
		logger.WithError(err).WithFields(fields).Fatal("Invalid configuration")
	}

	srv := server.NewServer(
		serverConfig,
		confs,
		idsCache,
		logger,
		govpn.CatchSignalShutdown(),
	)

	if *stats != "" {
		go govpn.StatsProcessor(*stats, srv.KnownPeers())
	}

	go srv.MainCycle()
	if err = <-srv.Error; err != nil {
		logger.WithError(err).Fatal("Fatal error")
	}
}
