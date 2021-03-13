package main

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"strings"
)

type AuthUser struct {
	username         string
	token            string
	allowedAddresses []string
}

// Split a string and ignore empty results
// https://stackoverflow.com/a/46798310/119527
func splitstr(s string, sep rune) []string {
	return strings.FieldsFunc(s, func(c rune) bool { return c == sep })
}

func parseLine(line string) *AuthUser {
	parts := strings.Fields(line)

	if len(parts) < 2 || len(parts) > 3 {
		return nil
	}

	user := AuthUser{
		username:         parts[0],
		token:            parts[1],
		allowedAddresses: nil,
	}

	if len(parts) >= 3 {
		user.allowedAddresses = splitstr(parts[2], ',')
	}

	return &user
}

func AuthFetch(username string) (*AuthUser, error) {
	data := os.Getenv("SMTPRELAY_USERS")
	if data == "" {
		return nil, errors.New("SMTPRELAY_USERS is unspecified")
	}

	scanner := bufio.NewScanner(bytes.NewBufferString(data))
	for scanner.Scan() {
		user := parseLine(scanner.Text())
		if user == nil {
			continue
		}

		if strings.ToLower(username) != strings.ToLower(user.username) {
			continue
		}

		return user, nil
	}

	return nil, errors.New("User not found")
}

func AuthCheckPassword(username string, secret string) error {
	user, err := AuthFetch(username)
	if err != nil {
		return err
	}
	if user.token == secret {
		return nil
	}
	return errors.New("Password invalid")
}
