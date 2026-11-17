package oputils

import "strings"

// EmptyIfEmpty returns an empty slice if the input slice is empty,
// otherwise it returns the input slice.
// Useful for avoiding null marshalling in JSON responses.
func EmptyIfEmpty[E any](slice []E) []E {
	if len(slice) == 0 {
		return []E{}
	}
	return slice
}

// Ref returns a pointer to the input value.
// Useful to take pointer to constants or function return values.
func Ref[E any](e E) *E {
	return &e
}

func NilIfEmpty(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func NilIfEmptyFloat(value float64) *float64 {
	if value == 0 {
		return nil
	}
	return &value
}

func NilIfEmptyInt(value int) *int {
	if value == 0 {
		return nil
	}
	return &value
}

func NilSliceIfStringEmpty(value string) *[]string {
	if value == "" {
		return nil
	}
	slice := strings.Split(value, ",")
	return &slice
}

func NilIfSliceEmpty(slice []string) *[]string {
	if len(slice) == 0 {
		return nil
	}
	return &slice
}
