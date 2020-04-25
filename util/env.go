package util

import (
	"fmt"
	"os"
)

func GetEnvVar(key string) string {
	value := os.Getenv(key)
	if value == "" {
		panic(fmt.Errorf("%s is required env var", key))
	}

	return value
}
