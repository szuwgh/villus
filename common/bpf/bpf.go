package bpf

import "os"

func IsMapPinned(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func UnMapPinned(path string) error {
	return os.Remove(path)
}
