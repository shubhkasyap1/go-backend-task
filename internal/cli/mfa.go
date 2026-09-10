package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
)

type enableMFAResponse struct {
	Message string `json:"message"`
	Secret  string `json:"secret"`
	URL     string `json:"url"`
}

// enableMFA starts the 2FA setup process.
//
// The backend stores the generated secret as a pending secret.
// MFA is only enabled after the user successfully verifies a TOTP code.
func (a *App) enableMFA() {
	if !a.loggedIn || a.sessionID == "" {
		fmt.Println("You must be logged in.")
		return
	}

	fmt.Println()
	fmt.Println("Setting up 2FA...")
	fmt.Println()

	req, err := http.NewRequest(
		http.MethodPost,
		a.baseURL+"/api/v1/auth/enable-2fa",
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

	// Session expired or invalid.
	if resp.StatusCode == http.StatusUnauthorized {
		a.clearSession()

		fmt.Println("Your session has expired.")
		fmt.Println("Please login again.")
		return
	}

	// Handle backend errors.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var result map[string]interface{}

		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
			if message, ok := result["error"].(string); ok {
				fmt.Printf("Failed to enable 2FA: %s\n", message)
				return
			}
		}

		fmt.Printf(
			"Failed to enable 2FA. HTTP status: %d\n",
			resp.StatusCode,
		)
		return
	}

	// Decode successful response.
	var result enableMFAResponse

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Println("Invalid server response.")
		return
	}

	fmt.Println("Scan this QR code with Google Authenticator:")
	fmt.Println()

	// Generate and display terminal QR code.
	if result.URL == "" {
		fmt.Println("QR code data was not provided by the server.")
	} else {
		qr, err := qrcode.New(result.URL, qrcode.Medium)

		if err != nil {
			fmt.Println("Failed to generate QR code:", err)
		} else {
			fmt.Println(qr.ToSmallString(false))
		}
	}

	// Display secret as a manual setup alternative.
	fmt.Println()
	fmt.Println("Secret:", result.Secret)
	fmt.Println()

	if result.Secret == "" {
		fmt.Println("Warning: MFA secret was not provided by the server.")
		fmt.Println()
	}

	fmt.Println("Enter the 6-digit code from your authenticator:")

	code, ok := a.readTOTPCode()

	if !ok {
		fmt.Println("Invalid 2FA code format.")
		return
	}

	a.verifyMFA(code)
}

// verifyMFA verifies the pending TOTP secret.
//
// MFA becomes fully enabled only after this verification succeeds.
func (a *App) verifyMFA(code string) {
	payload := map[string]string{
		"code": code,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		fmt.Println("Failed to prepare verification request.")
		return
	}

	req, err := http.NewRequest(
		http.MethodPost,
		a.baseURL+"/api/v1/auth/verify-2fa",
		bytes.NewReader(body),
	)
	if err != nil {
		fmt.Println("Failed to create request.")
		return
	}

	req.Header.Set("Authorization", "Bearer "+a.sessionID)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Unable to connect to authentication server.")
		return
	}
	defer resp.Body.Close()

	// Session expired or invalid.
	if resp.StatusCode == http.StatusUnauthorized {
		var result map[string]interface{}

		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
			if message, ok := result["error"].(string); ok {
				fmt.Printf(
					"2FA verification failed: %s\n",
					message,
				)
				return
			}
		}

		fmt.Println("2FA verification failed.")
		return
	}

	// Successful verification.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		fmt.Println()
		fmt.Println("2FA enabled successfully!")
		fmt.Println()
		return
	}

	// Other backend error.
	var result map[string]interface{}

	if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
		if message, ok := result["error"].(string); ok {
			fmt.Printf(
				"2FA verification failed: %s\n",
				message,
			)
			return
		}
	}

	fmt.Printf(
		"2FA verification failed. HTTP status: %d\n",
		resp.StatusCode,
	)
}

// disableMFA disables 2FA for the currently authenticated user.
func (a *App) disableMFA() {
	if !a.loggedIn || a.sessionID == "" {
		fmt.Println("You must be logged in.")
		return
	}

	fmt.Print("Are you sure you want to disable 2FA? (yes/no): ")

	answer := readConfirmation()

	if answer != "yes" {
		fmt.Println("2FA disable cancelled.")
		return
	}

	req, err := http.NewRequest(
		http.MethodPost,
		a.baseURL+"/api/v1/auth/disable-2fa",
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

	// Session expired or invalid.
	if resp.StatusCode == http.StatusUnauthorized {
		a.clearSession()

		fmt.Println("Your session has expired.")
		fmt.Println("Please login again.")
		return
	}

	// Successful disable.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		fmt.Println("2FA disabled successfully.")
		return
	}

	// Backend error.
	var result map[string]interface{}

	if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
		if message, ok := result["error"].(string); ok {
			fmt.Printf(
				"Failed to disable 2FA: %s\n",
				message,
			)
			return
		}
	}

	fmt.Printf(
		"Failed to disable 2FA. HTTP status: %d\n",
		resp.StatusCode,
	)
}

// readConfirmation reads a yes/no confirmation from the terminal.
func readConfirmation() string {
	reader := bufio.NewReader(os.Stdin)

	answer, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}

	return strings.ToLower(strings.TrimSpace(answer))
}