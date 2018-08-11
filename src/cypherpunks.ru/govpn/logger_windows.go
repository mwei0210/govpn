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
	"os"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
)

// NewLogger returns a logger for specified level. Syslog or Windows
// Events can be turned on.
func NewLogger(level string, syslog bool) (*logrus.Logger, error) {
	var logger *logrus.Logger
	logLevel, err := logrus.ParseLevel(level)
	if err != nil {
		return nil, errors.Wrap(err, "logrus.ParseLevel")
	}

	logger = &logrus.Logger{
		Formatter: &logrus.TextFormatter{
			ForceColors:      false,
			DisableColors:    true,
			DisableTimestamp: false,
			FullTimestamp:    true,
			TimestampFormat:  time.RFC3339Nano,
			DisableSorting:   false,
		},
		Hooks: make(logrus.LevelHooks),
	}
	logger.Out = os.Stderr
	logger.Level = logLevel
	logger.WithFields(logrus.Fields{
		"version": VersionGet(),
		"level":   logLevel.String(),
	}).Info("Initialize logging")
	return logger, nil
}
