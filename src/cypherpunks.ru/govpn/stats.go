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
	"encoding/json"
	"net"
	"time"

	"github.com/Sirupsen/logrus"
)

const rwTimeout = 10 * time.Second

// KnownPeers map of all connected GoVPN peers
type KnownPeers map[string]**Peer

// StatsProcessor is assumed to be run in background. It accepts
// connection on statsPort, reads anything one send to them and show
// information about known peers in serialized JSON format. peers
// argument is a reference to the map with references to the peers as
// values. Map is used here because of ease of adding and removing
// elements in it.
func StatsProcessor(stats string, peers *KnownPeers) {
	var conn net.Conn
	buf := make([]byte, 2<<8)
	fields := logrus.Fields{
		"func":    logFuncPrefix + "StatsProcessor",
		"bufsize": len(buf),
		"port":    stats,
	}

	logger.WithFields(
		fields,
	).WithField(
		"port", stats,
	).Debug("Stats are going to listen")
	statsPort, err := net.Listen("tcp", stats)
	if err != nil {
		logger.WithError(err).WithField(
			"stats", stats,
		).Error("Can not listen stats server")
		return
	}

	for {
		conn, err = statsPort.Accept()
		if err != nil {
			logger.WithFields(fields).WithError(err).Error("Can not accept connection")
			continue
		}
		deadLine := time.Now().Add(rwTimeout)
		if err = conn.SetDeadline(deadLine); err != nil {
			logger.WithFields(
				fields,
			).WithField(
				"deadline",
				deadLine.String(),
			).WithError(err).Error("Can not set deadline")
		} else if _, err = conn.Read(buf); err != nil {
			logger.WithFields(fields).WithError(err).Error("Can not read buffer")
		} else if _, err = conn.Write([]byte("HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n")); err != nil {
			logger.WithFields(fields).WithError(err).Error("Can not write HTTP headers")
		} else {
			var peersList []*Peer
			for _, peer := range *peers {
				peersList = append(peersList, *peer)
			}
			if err = json.NewEncoder(conn).Encode(peersList); err != nil {
				logger.WithFields(
					fields,
				).WithField(
					"peers", len(peersList),
				).WithError(err).Error("Can not encode to JSON")
			}
		}
		if err = conn.Close(); err != nil {
			logger.WithFields(fields).WithError(err).Error("Can not close connection")
		}
	}
}
