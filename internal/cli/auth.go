package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode"

	"golang.org/x/term"
)

type loginResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`

	UserID string `json:"user_id"`

	Session struct {
		ID        string    `json:"id"`
		ExpiresAt time.Time `json:"expires_at"`
		CreatedAt time.Time `json:"created_at"`
	} `json:"session"`

	User struct {
		ID          string     `json:"id"`
		Username    string     `json:"username"`
		MFAEnabled  bool       `json:"mfa_enabled"`
		CreatedAt   time.Time  `json:"created_at"`
		LastLoginAt *time.Time `json:"last_login_at"`
	} `json:"user"`
}

func readPassword(prompt string) (string, error) {
	fmt.Print(prompt)

	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()

	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(password)), nil
}

func (a *App) login() {
	fmt.Println()
	fmt.Println("============== Login ==============")

	// --------------------------------------------------
	// USERNAME
	// --------------------------------------------------

	username, err := a.readLine("Username: ")
	if err != nil {
		fmt.Println("Failed to read username.")
		return
	}

	username = strings.TrimSpace(username)

	if username == "" {
		fmt.Println("Username cannot be empty.")
		return
	}

	// --------------------------------------------------
	// PASSWORD
	// --------------------------------------------------

	password, err := readPassword("Password: ")
	if err != nil {
		fmt.Println("Failed to read password.")
		return
	}

	if password == "" {
		fmt.Println("Password cannot be empty.")
		return
	}

	// --------------------------------------------------
	// STEP 1: USERNAME + PASSWORD
	// --------------------------------------------------

	payload := map[string]string{
		"username": username,
		"password": password,
	}

	result, statusCode, err := a.loginRequest(payload)

	if err != nil {
		fmt.Println("Unable to connect to authentication server.")
		fmt.Println("Make sure the Go backend is running.")
		return
	}

	// --------------------------------------------------
	// CHECK LOGIN RESULT
	// --------------------------------------------------

	// Normal login failure.
	if statusCode != http.StatusOK {
		handleLoginError(result, statusCode)
		return
	}

	// Check whether backend requires MFA.
	if code, ok := result["code"].(string); ok &&
		code == "MFA_REQUIRED" {

		// Get user ID returned by backend.
		userID, ok := result["user_id"].(string)

		if !ok || userID == "" {
			fmt.Println("Login failed: server did not return user ID.")
			return
		}

		// --------------------------------------------------
		// STEP 2: ASK FOR TOTP
		// --------------------------------------------------

		fmt.Println()
		fmt.Println("Two-factor authentication is enabled.")

		totpCode, ok := a.readTOTPCode()
		if !ok {
			fmt.Println("Invalid 2FA code format.")
			return
		}

		// Send user ID + TOTP to /login/2fa.
		mfaPayload := map[string]string{
			"user_id": userID,
			"code":    totpCode,
		}

		result, statusCode, err = a.loginMFARequest(mfaPayload)

		if err != nil {
			fmt.Println("Unable to connect to authentication server.")
			return
		}

		if statusCode != http.StatusOK {
			handleLoginError(result, statusCode)
			return
		}
	}

	// --------------------------------------------------
	// LOGIN SUCCESS
	// --------------------------------------------------

	raw, err := json.Marshal(result)
	if err != nil {
		fmt.Println("Invalid server response.")
		return
	}

	var response loginResponse

	if err := json.Unmarshal(raw, &response); err != nil {
		fmt.Println("Invalid server response.")
		return
	}

	// Validate session returned by server.
	if response.Session.ID == "" {
		fmt.Println("Login failed: server returned an empty session.")
		return
	}

	if response.User.Username == "" {
		fmt.Println("Login failed: server returned an empty username.")
		return
	}

	// Save local session.
	a.sessionID = response.Session.ID
	a.username = response.User.Username
	a.loggedIn = true

	// --------------------------------------------------
	// DISPLAY LOGIN INFORMATION
	// --------------------------------------------------

	fmt.Println()
	fmt.Println("=================================")
	fmt.Println("         Login Successful")
	fmt.Println("=================================")

	fmt.Printf(
		"Username: %s\n",
		response.User.Username,
	)

	fmt.Printf(
		"Registered: %s\n",
		response.User.CreatedAt.Local().Format("2006-01-02 03:04:05 PM"),
	)

	if response.User.MFAEnabled {
		fmt.Println("2FA: Enabled")
	} else {
		fmt.Println("2FA: Disabled")
	}

	fmt.Printf(
		"Session expires: %s\n",
		response.Session.ExpiresAt.Local().Format("2006-01-02 03:04:05 PM"),
	)

	if response.User.LastLoginAt != nil {
		fmt.Printf(
			"Last login: %s\n",
			response.User.LastLoginAt.Local().Format("2006-01-02 03:04:05 PM"),
		)
	} else {
		fmt.Println("Last login: First login")
	}

	fmt.Println("=================================")
	fmt.Println()
}

// --------------------------------------------------
// FIRST LOGIN REQUEST
// --------------------------------------------------

func (a *App) loginRequest(
	payload map[string]string,
) (map[string]interface{}, int, error) {

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, err
	}

	resp, err := http.Post(
		a.baseURL+"/api/v1/auth/login",
		"application/json",
		bytes.NewReader(body),
	)

	if err != nil {
		return nil, 0, err
	}

	defer resp.Body.Close()

	var result map[string]interface{}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, resp.StatusCode, err
	}

	return result, resp.StatusCode, nil
}

// --------------------------------------------------
// SECOND LOGIN REQUEST - TOTP
// --------------------------------------------------

func (a *App) loginMFARequest(
	payload map[string]string,
) (map[string]interface{}, int, error) {

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, err
	}

	resp, err := http.Post(
		a.baseURL+"/api/v1/auth/login/2fa",
		"application/json",
		bytes.NewReader(body),
	)

	if err != nil {
		return nil, 0, err
	}

	defer resp.Body.Close()

	var result map[string]interface{}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, resp.StatusCode, err
	}

	return result, resp.StatusCode, nil
}

// --------------------------------------------------
// TOTP INPUT
// --------------------------------------------------

func (a *App) readTOTPCode() (string, bool) {
	code, err := a.readLine("2FA Code: ")

	if err != nil {
		return "", false
	}

	code = strings.TrimSpace(code)

	if !isValidTOTPCode(code) {
		return "", false
	}

	return code, true
}

func isValidTOTPCode(code string) bool {
	if len(code) != 6 {
		return false
	}

	for _, r := range code {
		if !unicode.IsDigit(r) {
			return false
		}
	}

	return true
}

// --------------------------------------------------
// LOGIN ERROR HANDLING
// --------------------------------------------------

func handleLoginError(
	result map[string]interface{},
	statusCode int,
) {

	if message, ok := result["error"].(string); ok {

		switch message {

		case "invalid username or password":
			fmt.Println(
				"Login failed: invalid username or password.",
			)

		case "invalid 2FA code":
			fmt.Println(
				"Login failed: invalid 2FA code.",
			)
			fmt.Println(
				"Please check your authenticator and try again.",
			)

		case "account is temporarily locked":
			fmt.Println(
				"Login failed: account is temporarily locked.",
			)

		default:
			fmt.Printf(
				"Login failed: %s\n",
				message,
			)
		}

		return
	}

	fmt.Printf(
		"Login failed. HTTP status: %d\n",
		statusCode,
	)
}