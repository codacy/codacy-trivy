package openssfdb

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
)

// WriteGzippedJSON persists the provided Output as a gzip-compressed JSON payload.
func WriteGzippedJSON(path string, output *Output) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	gz := gzip.NewWriter(file)
	defer gz.Close()

	encoder := json.NewEncoder(gz)
	encoder.SetEscapeHTML(false)

	return encoder.Encode(output)
}
