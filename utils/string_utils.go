package utils

import (
	"crypto/sha1"
	"encoding/hex"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"math/rand"
	"strings"
	"time"
)

var (
	sha1Hasher = sha1.New()
	randSource = rand.NewSource(time.Now().UnixNano())
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

func GenerateInternalIdFromString(source string) string {
	sha1Hasher.Write([]byte(source))
	return hex.EncodeToString(sha1Hasher.Sum(nil)[:len(primitive.ObjectID{})])
}

func TryGetLastNDigits(source string, digits int) string {
	if len(source) == 0 {
		return "<empty>"
	}

	if len(source) > digits {
		return (source)[len(source)-digits:]
	}
	return source
}

func MasqueradeSensitiveString(source string, showNDigits int) string {
	if len(source) == 0 {
		return "<empty>"
	}

	exposedString := TryGetLastNDigits(source, showNDigits)
	if len(exposedString) == showNDigits {
		return strings.Repeat("*", len(source)-showNDigits) + exposedString
	}
	return exposedString
}

func PointerToEmptyString(source *string) string {
	if source == nil {
		return ""
	}
	return *source
}

func StringToNilPointer(source string) *string {
	if len(source) == 0 {
		return nil
	}
	return &source
}

func SanitizeStringWithValues(command string, toMaskValues ...string) string {
	res := command

	for _, toMask := range toMaskValues {
		if len(toMask) != 0 {
			res = strings.ReplaceAll(command, toMask, "<masked>")
		}
	}
	return res
}
