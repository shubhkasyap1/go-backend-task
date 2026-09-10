package auth

import (
	"errors"
	"fmt"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

var ErrInvalidTOTP = errors.New("invalid authentication code")

func GenerateTOTP(username string) (*otp.Key, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Go Backend Task",
		AccountName: username,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	return key, nil
}

func ValidateTOTP(
	code string,
	secret string,
) bool {
	return totp.Validate(code, secret)
}
