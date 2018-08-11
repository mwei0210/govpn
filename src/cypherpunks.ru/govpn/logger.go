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

import "github.com/Sirupsen/logrus"

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
