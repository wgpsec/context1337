package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const (
	OriginEnv  = "env"
	OriginFile = "file"
)

type Store struct {
	mu       sync.RWMutex
	byKey    map[string]Principal
	keysFile string
}

type filePrincipal struct {
	ID      string          `json:"id"`
	Key     string          `json:"key"`
	Sources []string        `json:"sources"`
	Access  json.RawMessage `json:"access"`
}

func Load(bootstrapKey, keysFile string) (*Store, error) {
	return Open(bootstrapKey, keysFile, false)
}

func Open(bootstrapKey, keysFile string, optionalFile bool) (*Store, error) {
	store := &Store{byKey: map[string]Principal{}, keysFile: strings.TrimSpace(keysFile)}

	bootstrapKey = strings.TrimSpace(bootstrapKey)
	if bootstrapKey != "" {
		principal := AdminPrincipal(BootstrapID)
		principal.Origin = OriginEnv
		if err := store.addLocked(bootstrapKey, principal); err != nil {
			return nil, err
		}
	}

	if store.keysFile == "" {
		return store, nil
	}

	data, err := os.ReadFile(store.keysFile)
	if err != nil {
		if optionalFile && os.IsNotExist(err) {
			return store, nil
		}
		return nil, fmt.Errorf("read api keys file: %w", err)
	}
	var items []filePrincipal
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("parse api keys file: %w", err)
	}
	for i, item := range items {
		principal, key, err := parseFilePrincipal(item)
		if err != nil {
			return nil, fmt.Errorf("api key[%d]: %w", i, err)
		}
		principal.Origin = OriginFile
		if err := store.addLocked(key, principal); err != nil {
			return nil, fmt.Errorf("api key[%d]: %w", i, err)
		}
	}
	return store, nil
}

func parseFilePrincipal(item filePrincipal) (Principal, string, error) {
	id := strings.TrimSpace(item.ID)
	key := strings.TrimSpace(item.Key)
	if id == "" {
		return Principal{}, "", fmt.Errorf("id is required")
	}
	if key == "" {
		return Principal{}, "", fmt.Errorf("key is required")
	}
	access, err := parseAccess(item.Access)
	if err != nil {
		return Principal{}, "", err
	}
	if len(item.Sources) == 0 {
		return Principal{}, "", fmt.Errorf("sources is required")
	}
	seen := map[string]struct{}{}
	var granted []string
	for _, source := range item.Sources {
		source = strings.TrimSpace(source)
		switch source {
		case SourceBuiltin, SourceTeam, SourceCustom:
			if _, ok := seen[source]; ok {
				return Principal{}, "", fmt.Errorf("duplicate source %q", source)
			}
			seen[source] = struct{}{}
			granted = append(granted, source)
		case SourceNuclei:
			return Principal{}, "", fmt.Errorf("source %q is implied by builtin and cannot be granted directly", source)
		default:
			return Principal{}, "", fmt.Errorf("unknown source %q", source)
		}
	}
	return newPrincipal(id, access, granted), key, nil
}

func (s *Store) addLocked(key string, principal Principal) error {
	if _, ok := s.byKey[key]; ok {
		return fmt.Errorf("duplicate api key")
	}
	for existingKey, existing := range s.byKey {
		if existing.ID == principal.ID {
			return fmt.Errorf("duplicate api key id %q", existing.ID)
		}
		if existing.ID == key {
			return fmt.Errorf("api key collides with id %q", existing.ID)
		}
		if principal.ID == existingKey {
			return fmt.Errorf("api key id %q collides with another key", principal.ID)
		}
	}
	s.byKey[key] = principal
	return nil
}

func (s *Store) Enabled() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byKey) > 0
}

func (s *Store) Lookup(key string) (Principal, bool) {
	if s == nil {
		return Principal{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	principal, ok := s.byKey[key]
	return principal, ok
}

func (s *Store) Count() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byKey)
}

func (s *Store) IDs() []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.byKey))
	for _, principal := range s.byKey {
		ids = append(ids, principal.ID)
	}
	sort.Strings(ids)
	return ids
}

type PublicPrincipal struct {
	ID      string   `json:"id"`
	Access  []string `json:"access"`
	Sources []string `json:"sources"`
	Origin  string   `json:"origin"`
}

func (s *Store) PublicPrincipals() []PublicPrincipal {
	if s == nil {
		return []PublicPrincipal{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]PublicPrincipal, 0, len(s.byKey))
	for _, principal := range s.byKey {
		sources := append([]string(nil), principal.Granted...)
		if len(sources) == 0 {
			sources = append([]string(nil), principal.Sources...)
		}
		out = append(out, PublicPrincipal{
			ID:      principal.ID,
			Access:  principal.Access,
			Sources: sources,
			Origin:  principal.Origin,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func RequireIndependentAdminKey(store *Store, adminKey string) error {
	adminKey = strings.TrimSpace(adminKey)
	if adminKey == "" {
		return nil
	}
	if store != nil {
		if _, ok := store.Lookup(adminKey); ok {
			return fmt.Errorf("ABOUTSECURITY_ADMIN_KEY must be independent of MCP/REST API keys")
		}
	}
	return nil
}

func generateKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func (s *Store) lookupByIDLocked(id string) (string, Principal, bool) {
	for key, principal := range s.byKey {
		if principal.ID == id {
			return key, principal, true
		}
	}
	return "", Principal{}, false
}

func (s *Store) removeLocked(id string) {
	for key, principal := range s.byKey {
		if principal.ID == id {
			delete(s.byKey, key)
			return
		}
	}
}

func (s *Store) persistLocked() error {
	if s.keysFile == "" {
		return fmt.Errorf("api keys file is not configured")
	}
	items := make([]filePrincipal, 0)
	for key, principal := range s.byKey {
		if principal.Origin != OriginFile {
			continue
		}
		accessJSON, err := json.Marshal(principal.Access)
		if err != nil {
			return fmt.Errorf("encode api key access: %w", err)
		}
		items = append(items, filePrincipal{
			ID:      principal.ID,
			Key:     key,
			Sources: append([]string(nil), principal.Granted...),
			Access:  accessJSON,
		})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(s.keysFile), 0o755); err != nil {
		return fmt.Errorf("create api keys directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.keysFile), ".api-keys-*.tmp")
	if err != nil {
		return fmt.Errorf("write api keys file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("write api keys file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write api keys file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write api keys file: %w", err)
	}
	if err := os.Rename(tmpName, s.keysFile); err != nil {
		return fmt.Errorf("write api keys file: %w", err)
	}
	return nil
}

func validateManagedID(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("id is required")
	}
	if strings.ContainsAny(id, "/\\ \t\n\r") {
		return fmt.Errorf("id contains invalid characters")
	}
	switch id {
	case BootstrapID, "console", "anonymous":
		return fmt.Errorf("id %q is reserved", id)
	}
	return nil
}

func rejectAdminCollision(id, key, adminKey string) error {
	adminKey = strings.TrimSpace(adminKey)
	if adminKey == "" {
		return nil
	}
	if key == adminKey || id == adminKey {
		return fmt.Errorf("api key must be independent of ABOUTSECURITY_ADMIN_KEY")
	}
	return nil
}

type KeyInput struct {
	ID      string          `json:"id"`
	Key     string          `json:"key"`
	Access  json.RawMessage `json:"access"`
	Sources []string        `json:"sources"`
}

func (s *Store) Create(input KeyInput, adminKey string) (PublicPrincipal, string, error) {
	if s == nil {
		return PublicPrincipal{}, "", fmt.Errorf("api key store is not configured")
	}
	id := strings.TrimSpace(input.ID)
	if err := validateManagedID(id); err != nil {
		return PublicPrincipal{}, "", err
	}
	key := strings.TrimSpace(input.Key)
	if key == "" {
		generated, err := generateKey()
		if err != nil {
			return PublicPrincipal{}, "", err
		}
		key = generated
	}
	if err := rejectAdminCollision(id, key, adminKey); err != nil {
		return PublicPrincipal{}, "", err
	}
	principal, _, err := parseFilePrincipal(filePrincipal{
		ID:      id,
		Key:     key,
		Sources: input.Sources,
		Access:  input.Access,
	})
	if err != nil {
		return PublicPrincipal{}, "", err
	}
	principal.Origin = OriginFile

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.addLocked(key, principal); err != nil {
		return PublicPrincipal{}, "", err
	}
	if err := s.persistLocked(); err != nil {
		s.removeLocked(id)
		return PublicPrincipal{}, "", err
	}
	return publicPrincipal(principal), key, nil
}

func (s *Store) Update(id string, access json.RawMessage, sources []string) (PublicPrincipal, error) {
	if s == nil {
		return PublicPrincipal{}, fmt.Errorf("api key store is not configured")
	}
	id = strings.TrimSpace(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	key, existing, ok := s.lookupByIDLocked(id)
	if !ok {
		return PublicPrincipal{}, fmt.Errorf("not found")
	}
	if existing.Origin != OriginFile {
		return PublicPrincipal{}, fmt.Errorf("environment-owned key cannot be modified")
	}
	principal, _, err := parseFilePrincipal(filePrincipal{
		ID:      existing.ID,
		Key:     key,
		Sources: sources,
		Access:  access,
	})
	if err != nil {
		return PublicPrincipal{}, err
	}
	principal.Origin = OriginFile
	s.byKey[key] = principal
	if err := s.persistLocked(); err != nil {
		s.byKey[key] = existing
		return PublicPrincipal{}, err
	}
	return publicPrincipal(principal), nil
}

func (s *Store) Rotate(id, adminKey string) (PublicPrincipal, string, error) {
	if s == nil {
		return PublicPrincipal{}, "", fmt.Errorf("api key store is not configured")
	}
	id = strings.TrimSpace(id)
	newKey, err := generateKey()
	if err != nil {
		return PublicPrincipal{}, "", err
	}
	if err := rejectAdminCollision(id, newKey, adminKey); err != nil {
		return PublicPrincipal{}, "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	oldKey, existing, ok := s.lookupByIDLocked(id)
	if !ok {
		return PublicPrincipal{}, "", fmt.Errorf("not found")
	}
	if existing.Origin != OriginFile {
		return PublicPrincipal{}, "", fmt.Errorf("environment-owned key cannot be modified")
	}
	delete(s.byKey, oldKey)
	rotated := existing
	if err := s.addLocked(newKey, rotated); err != nil {
		s.byKey[oldKey] = existing
		return PublicPrincipal{}, "", err
	}
	if err := s.persistLocked(); err != nil {
		delete(s.byKey, newKey)
		s.byKey[oldKey] = existing
		return PublicPrincipal{}, "", err
	}
	return publicPrincipal(rotated), newKey, nil
}

func (s *Store) Delete(id string) error {
	if s == nil {
		return fmt.Errorf("api key store is not configured")
	}
	id = strings.TrimSpace(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	key, existing, ok := s.lookupByIDLocked(id)
	if !ok {
		return fmt.Errorf("not found")
	}
	if existing.Origin != OriginFile {
		return fmt.Errorf("environment-owned key cannot be modified")
	}
	delete(s.byKey, key)
	if err := s.persistLocked(); err != nil {
		s.byKey[key] = existing
		return err
	}
	return nil
}

func publicPrincipal(principal Principal) PublicPrincipal {
	sources := append([]string(nil), principal.Granted...)
	if len(sources) == 0 {
		sources = append([]string(nil), principal.Sources...)
	}
	return PublicPrincipal{
		ID:      principal.ID,
		Access:  principal.Access,
		Sources: sources,
		Origin:  principal.Origin,
	}
}
