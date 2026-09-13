package wg

import "os"

func readFile(path string) ([]byte, error)         { return os.ReadFile(path) }
func writeFile(path string, b []byte, mode os.FileMode) error {
	return os.WriteFile(path, b, mode)
}
