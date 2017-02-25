// +build !windows

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
	"bytes"
	"fmt"
	logsyslog "log/syslog"
	"os"
	"sort"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/Sirupsen/logrus/hooks/syslog"
	"github.com/pkg/errors"
)

// syslogFormatter is a syslog friendly formatter
type syslogFormatter struct{}

// Format converts a log entry into a list of bytes
func (sf *syslogFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var buf bytes.Buffer
	var err error
	keys := make([]string, 0, len(entry.Data))
	for k := range entry.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		if _, err = buf.WriteString(fmt.Sprintf("[%s]%+v ", k, entry.Data[k])); err != nil {
			return nil, errors.Wrapf(err, "buf.WriteString %s", k)
		}
	}
	if _, err = buf.WriteString(entry.Message); err != nil {
		return nil, errors.Wrap(err, "buf.WriteString message")
	}
	return buf.Bytes(), nil
}

// NewLogger returns a logger for specified level. Syslog or Windows
// Events can be turned on.
func NewLogger(level string, syslog bool) (*logrus.Logger, error) {
	var logger *logrus.Logger
	logLevel, err := logrus.ParseLevel(level)
	if err != nil {
		return nil, errors.Wrap(err, "logrus.ParseLevel")
	}

	if syslog {
		syslogHook, err := logrus_syslog.NewSyslogHook("", "", logsyslog.LOG_INFO, "GoVPN")
		if err != nil {
			return nil, errors.Wrap(err, "logrus_syslog.NewSyslogHook")
		}
		logger = &logrus.Logger{
			Formatter: &syslogFormatter{},
			Hooks:     make(logrus.LevelHooks),
		}
		logger.Hooks.Add(syslogHook)
	} else {
		logger = &logrus.Logger{
			Formatter: &logrus.TextFormatter{
				ForceColors:      true,
				DisableColors:    false,
				DisableTimestamp: false,
				FullTimestamp:    true,
				TimestampFormat:  time.RFC3339Nano,
				DisableSorting:   false,
			},
			Hooks: make(logrus.LevelHooks),
		}
	}
	logger.Out = os.Stderr
	logger.Level = logLevel
	logger.WithFields(logrus.Fields{
		"version": VersionGet(),
		"level":   logLevel.String(),
	}).Info("Initialize logging")
	return logger, nil
}

// ExtendLogFields adds batch of log Fields to existing fields ones
func ExtendLogFields(input *logrus.Fields, add logrus.Fields) {
	i := *input
	for k, v := range add {
		i[k] = v
	}
}

// MergeLogFields combines multiple log fields into a single one
func MergeLogFields(fields ...logrus.Fields) (output logrus.Fields) {
	output = logrus.Fields{}
	for _, f := range fields {
		ExtendLogFields(&output, f)
	}
	return
}
