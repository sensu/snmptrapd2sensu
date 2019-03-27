package utils

import (
  "os"
)

func Getenv(key string, fallback string) string {
	value := os.Getenv(key)
	if len(value) == 0 {
		return fallback
	}
	return value
}

func IndexOf(s []string, k string) int {
	// return the []string slice index value of the first occurence of key (k).
	for i, v := range s {
		if v == k {
			return i
		}
	}
	return -1
}
