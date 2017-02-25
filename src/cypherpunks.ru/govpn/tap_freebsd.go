// +build freebsd

/*
GoVPN -- simple secure free software virtual private network daemon
Copyright (C) 2014-2017 Sergey Matveev <stargrave@stargrave.org>
*/

package govpn

import (
	"io"
	"os"
	"path"

	"github.com/pkg/errors"
)

func newTAPer(ifaceName string) (io.ReadWriteCloser, error) {
	output, err := os.OpenFile(path.Join("/dev/", ifaceName), os.O_RDWR, os.ModePerm)
	return output, errors.Wrap(err, "os.OpenFile")
}
