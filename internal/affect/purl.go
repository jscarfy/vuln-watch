package affect

import "strings"

// ExtractPURLVersion extracts "@<version>" from a purl string like:
//
//	pkg:golang/github.com/gin-gonic/gin@v1.10.0
//
// If no "@", returns "".
func ExtractPURLVersion(purl string) string {
	s := strings.TrimSpace(purl)
	i := strings.LastIndex(s, "@")
	if i < 0 || i == len(s)-1 {
		return ""
	}
	return strings.TrimSpace(s[i+1:])
}
