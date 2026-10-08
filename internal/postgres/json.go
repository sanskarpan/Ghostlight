package postgres

import (
	"encoding/json"
	"fmt"
)

// jsonMarshal and jsonUnmarshal are indirections so the SQL-facing code reads
// cleanly and the encoding choice is made in one place.
func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

func jsonUnmarshal(b []byte, v any) error {
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("decode json: %w", err)
	}
	return nil
}
