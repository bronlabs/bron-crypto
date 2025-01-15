package internal

import (
	"net"
	"os"
	"runtime"

	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
)

type DeviceProfile struct {
	OS           string
	Architecture string
	CPUs         int
	HostName     string
	Network      []net.Interface

	_ ds.Incomparable
}

func GetDeviceProfile() (*DeviceProfile, error) {
	host, err := os.Hostname()
	if err != nil {
		return nil, errs.WrapFailed(err, "could not get hostname")
	}

	network, err := net.Interfaces()
	if err != nil {
		return nil, errs.WrapFailed(err, "could not get network interfaces")
	}

	return &DeviceProfile{
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
		CPUs:         runtime.NumCPU(),
		HostName:     host,
		Network:      network,
	}, nil
}
