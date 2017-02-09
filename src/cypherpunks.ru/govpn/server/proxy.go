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

package server

import (
	"net/http"

	"github.com/Sirupsen/logrus"
)

type proxyHandler struct {
	goVpnServer *Server
}

func (p proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		p.goVpnServer.logger.WithError(err).WithFields(
			logrus.Fields{
				"func":    logFuncPrefix + "proxyHandler.ServeHTTP",
				"address": p.goVpnServer.configuration.BindAddress,
			},
		).Error("Proxy hijack failed")
		return
	}
	conn.Write([]byte("HTTP/1.0 200 OK\n\n"))
	go p.goVpnServer.handleTCP(conn)
}

func (s *Server) proxyStart() {
	fields := logrus.Fields{
		"func":    logFuncPrefix + "Server.proxyStart",
		"address": s.configuration.BindAddress,
		"proxy":   s.configuration.ProxyAddress,
	}
	s.logger.WithFields(fields).Info("Proxy Listen")
	httpServer := &http.Server{
		Addr: s.configuration.ProxyAddress,
		Handler: proxyHandler{
			goVpnServer: s,
		},
	}
	if err := httpServer.ListenAndServe(); err != nil {
		s.logger.WithFields(fields).WithError(err).Error("Proxy failed")
		return
	}
	s.logger.WithFields(fields).Info("Proxy finished")
}
