package search

import (
	"database/sql"
	"fmt"
	"net/url"
	"strings"
)

const stableIDPrefix = "absec://"

func StableID(r Resource) string {
	return stableIDPrefix + url.PathEscape(r.Source) + "/" + r.Type + "/" + url.PathEscape(r.Name)
}

func ParseStableID(id string) (source, typ, key string, err error) {
	rest, ok := strings.CutPrefix(id, stableIDPrefix)
	if !ok {
		return "", "", "", fmt.Errorf("invalid resource id %q: expected absec://{source}/{type}/{key}", id)
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("invalid resource id %q: expected exactly source/type/key segments", id)
	}
	if parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", fmt.Errorf("invalid resource id %q: source, type, and key must be non-empty", id)
	}

	source, err = url.PathUnescape(parts[0])
	if err != nil {
		return "", "", "", fmt.Errorf("invalid resource id %q: bad source escape: %w", id, err)
	}
	key, err = url.PathUnescape(parts[2])
	if err != nil {
		return "", "", "", fmt.Errorf("invalid resource id %q: bad key escape: %w", id, err)
	}
	typ = parts[1]
	if !validResourceType(typ) {
		return "", "", "", fmt.Errorf("invalid resource id %q: unsupported resource type %q", id, typ)
	}
	if source == "" || key == "" {
		return "", "", "", fmt.Errorf("invalid resource id %q: source and key must be non-empty", id)
	}
	return source, typ, key, nil
}

func GetByStableID(db *sql.DB, id string) (*Resource, error) {
	source, typ, key, err := ParseStableID(id)
	if err != nil {
		return nil, err
	}

	var r Resource
	err = db.QueryRow(`
        SELECT id, type, COALESCE(name,''), COALESCE(source,''), COALESCE(file_path,''),
               COALESCE(category,''), COALESCE(tags,''), COALESCE(mitre,''),
               COALESCE(difficulty,''), COALESCE(description,''), COALESCE(body,''), COALESCE(metadata,'')
        FROM resources WHERE source=? AND type=? AND name=? LIMIT 1`, source, typ, key).Scan(
		&r.ID, &r.Type, &r.Name, &r.Source, &r.FilePath,
		&r.Category, &r.Tags, &r.Mitre, &r.Difficulty,
		&r.Description, &r.Body, &r.Metadata,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func validResourceType(typ string) bool {
	switch typ {
	case "skill", "dict", "payload", "vuln":
		return true
	default:
		return false
	}
}
