package state

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type State struct {
	// Key format: "<source>::<pkgid>"
	Seen map[string]map[string]bool `json:"seen"`
}

func New() *State {
	return &State{Seen: map[string]map[string]bool{}}
}

func Load(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return New(), nil
		}
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if s.Seen == nil {
		s.Seen = map[string]map[string]bool{}
	}
	return &s, nil
}

func (s *State) MarkSeen(key string, vulnID string) {
	if s.Seen == nil {
		s.Seen = map[string]map[string]bool{}
	}
	if _, ok := s.Seen[key]; !ok {
		s.Seen[key] = map[string]bool{}
	}
	s.Seen[key][vulnID] = true
}

func (s *State) IsSeen(key string, vulnID string) bool {
	if s.Seen == nil {
		return false
	}
	m, ok := s.Seen[key]
	if !ok {
		return false
	}
	return m[vulnID]
}

func Save(path string, s *State) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
