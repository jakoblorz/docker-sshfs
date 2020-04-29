package main

import (
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/docker/go-plugins-helpers/volume"
)

var (
	ErrBindOptionRequired = errors.New("bind option required")
	ErrVolumeNotFound     = errors.New("volume not found")
	ErrNotADirectory      = errors.New("not a directory")
	ErrRemoveUsed         = errors.New("cannot remove volume")
)

type sshfsVolume struct {
	connections int

	Bind       string
	Port       string
	Options    []string
	Mountpoint string
}
type sshfsDriver struct {
	sync.RWMutex

	root      string
	statePath string
	volumes   map[string]*sshfsVolume
}

func (d *sshfsDriver) writeToWriter(w io.Writer) error {
	return json.NewEncoder(w).Encode(d.volumes)
}

func (d *sshfsDriver) readFromReader(r io.Reader) error {
	return json.NewDecoder(r).Decode(&d.volumes)
}

func (d *sshfsDriver) save() (err error) {
	var f *os.File
	f, err = os.OpenFile(d.statePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return
	}
	defer f.Close()

	err = d.writeToWriter(f)
	return
}

func newDriver(root string) (d *sshfsDriver, err error) {
	d = &sshfsDriver{
		root:      filepath.Join(root, "volumes"),
		statePath: filepath.Join(root, "state", "state.json"),
		volumes:   map[string]*sshfsVolume{},
	}

	var f *os.File
	f, err = os.OpenFile(d.statePath, os.O_RDONLY, 0)
	if err != nil {
		log.Printf("%+v\n", err)
		if !os.IsNotExist(err) {
			return
		}
		err = nil
	} else {
		defer f.Close()
		err = d.readFromReader(f)
	}
	return
}

func (d *sshfsDriver) Create(r *volume.CreateRequest) error {
	v := &sshfsVolume{
		Options: []string{
			"-o IdentityFile=/root/.ssh/id_rsa",
			"-o allow_other",
			"-o sshfs_debug",
			"-o debug",
		},
	}

	for key, val := range r.Options {
		switch key {
		case "bind":
			v.Bind = val
			break
		case "port":
			v.Port = val
			break
		default:
			if val != "" {
				v.Options = append(v.Options, fmt.Sprintf("%s=%s", key, val))
			} else {
				v.Options = append(v.Options, key)
			}
		}
	}

	if v.Bind == "" {
		return ErrBindOptionRequired
	}
	v.Mountpoint = filepath.Join(d.root, fmt.Sprintf("%x", md5.Sum([]byte(v.Bind))))

	d.Lock()
	defer d.Unlock()
	d.volumes[r.Name] = v
	return d.save()
}

func (d *sshfsDriver) Remove(r *volume.RemoveRequest) (err error) {
	d.Lock()
	defer d.Unlock()

	v, ok := d.volumes[r.Name]
	if !ok {
		return ErrVolumeNotFound
	}

	if v.connections != 0 {
		return ErrRemoveUsed
	}
	err = os.RemoveAll(v.Mountpoint)
	if err != nil {
		return
	}

	delete(d.volumes, r.Name)
	err = d.save()
	return
}

func (d *sshfsDriver) Path(r *volume.PathRequest) (res *volume.PathResponse, err error) {
	res = &volume.PathResponse{}

	d.RLock()
	defer d.RUnlock()

	v, ok := d.volumes[r.Name]
	if !ok {
		err = ErrVolumeNotFound
		return
	}

	res.Mountpoint = v.Mountpoint
	return
}

func (d *sshfsDriver) Mount(r *volume.MountRequest) (res *volume.MountResponse, err error) {
	res = &volume.MountResponse{}

	d.Lock()
	defer d.Unlock()

	v, ok := d.volumes[r.Name]
	if !ok {
		err = ErrVolumeNotFound
		return
	}

	if v.connections == 0 {
		var fi os.FileInfo
		fi, err = os.Lstat(v.Mountpoint)
		if os.IsNotExist(err) {
			if err2 := os.MkdirAll(v.Mountpoint, 0755); err2 != nil {
				err = err2
				return
			}
		} else if err != nil {
			return
		}

		if fi != nil && !fi.IsDir() {
			err = ErrNotADirectory
			return
		}

		cmd := exec.Command(
			"sshfs",
			"-oStrictHostKeyChecking=no",
			"-oUserKnownHostsFile=/dev/null",
			v.Bind,
			v.Mountpoint,
		)
		if v.Port != "" {
			cmd.Args = append(cmd.Args, "-p", v.Port)
		}
		cmd.Env = append(os.Environ(), "DEBUG=1")
		for _, option := range v.Options {
			cmd.Args = append(cmd.Args, "-o", option)
		}

		var log []byte
		log, err = cmd.CombinedOutput()
		if err != nil {
			err = fmt.Errorf("sshfs %+v: %s", err, log)
			return
		}
	}

	v.connections++
	res.Mountpoint = v.Mountpoint

	return
}

func (d *sshfsDriver) Unmount(r *volume.UnmountRequest) error {
	d.Lock()
	defer d.Unlock()

	v, ok := d.volumes[r.Name]
	if !ok {
		return ErrVolumeNotFound
	}

	v.connections--
	if v.connections <= 0 {
		cmd := exec.Command("sh", "-c", fmt.Sprintf("umount %s", v.Mountpoint))
		log, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("umount %+v: %s", err, log)
		}

		v.connections = 0
	}

	return nil
}

func (d *sshfsDriver) Get(r *volume.GetRequest) (*volume.GetResponse, error) {
	d.RLock()
	defer d.RUnlock()

	v, ok := d.volumes[r.Name]
	if !ok {
		return &volume.GetResponse{}, ErrVolumeNotFound
	}

	return &volume.GetResponse{
		Volume: &volume.Volume{
			Name:       r.Name,
			Mountpoint: v.Mountpoint,
		},
	}, nil
}

func (d *sshfsDriver) List() (*volume.ListResponse, error) {
	d.RLock()
	defer d.RUnlock()

	var vols []*volume.Volume
	for name, v := range d.volumes {
		vols = append(vols, &volume.Volume{
			Name:       name,
			Mountpoint: v.Mountpoint,
		})
	}

	return &volume.ListResponse{
		Volumes: vols,
	}, nil
}

func (d *sshfsDriver) Capabilities() *volume.CapabilitiesResponse {
	return &volume.CapabilitiesResponse{
		Capabilities: volume.Capability{
			Scope: "local",
		},
	}
}

func main() {
	d, err := newDriver("/mnt")
	if err != nil {
		panic(err)
	}

	h := volume.NewHandler(d)

	u, _ := user.Lookup("root")
	gid, _ := strconv.Atoi(u.Gid)
	err = h.ServeUnix("sshfs", gid)
	if err != nil {
		panic(err)
	}
}
