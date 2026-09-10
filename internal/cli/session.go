package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type meResponse struct {
	Username         string     `json:"username"`
	MFAEnabled       bool       `json:"mfa_enabled"`
	RegistrationDate string     `json:"registration_date"`
	SessionExpires   string     `json:"session_expires"`
	LastLogin        *string    `json:"last_login"`
}

func (a *App) whoami() {
	if !a.loggedIn || a.sessionID == "" {
		fmt.Println("You are not logged in.")
		return
	}

	req, err := http.NewRequest(
		http.MethodGet,
		a.baseURL+"/api/v1/auth/me",
		nil,
	)
	if err != nil {
		fmt.Println("Failed to create request.")
		return
	}

	req.Header.Set("Authorization", "Bearer "+a.sessionID)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Unable to connect to authentication server.")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		a.clearSession()

		fmt.Println("Your session has expired.")
		fmt.Println("Please login again.")
		return
	}

	if resp.StatusCode != http.StatusOK {
		fmt.Printf(
			"Failed to get user information. HTTP status: %d\n",
			resp.StatusCode,
		)
		return
	}

	var result meResponse

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Println("Invalid server response.")
		return
	}

	fmt.Println()
	fmt.Println("=================================")
	fmt.Println("          Account Info")
	fmt.Println("=================================")

	fmt.Printf("Username: %s\n", result.Username)

	// Format registration date.
	fmt.Printf(
		"Registered: %s\n",
		formatDate(result.RegistrationDate),
	)

	if result.MFAEnabled {
		fmt.Println("2FA: Enabled")
	} else {
		fmt.Println("2FA: Disabled")
	}

	// Session expiration.
	fmt.Printf(
		"Session expires: %s\n",
		formatDate(result.SessionExpires),
	)

	// Last login.
	if result.LastLogin != nil && *result.LastLogin != "" {
		fmt.Printf(
			"Last login: %s\n",
			formatDate(*result.LastLogin),
		)
	} else {
		fmt.Println("Last login: First login")
	}

	fmt.Println("=================================")
}

func formatDate(value string) string {
	if value == "" {
		return "N/A"
	}

	// Try RFC3339/RFC3339Nano first.
	t, err := time.Parse(time.RFC3339Nano, value)
	if err == nil {
		return t.Local().Format("2006-01-02 03:04:05 PM")
	}

	// If the backend returns another format,
	// display the original value rather than losing information.
	return value
}

func (a *App) clearSession() {
	a.sessionID = ""
	a.username = ""
	a.loggedIn = false
}