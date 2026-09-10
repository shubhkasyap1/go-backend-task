package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/chzyer/readline"
)

type App struct {
	sessionID string
	username  string
	loggedIn  bool
	baseURL   string
	rl        *readline.Instance
}

type registerResponse struct {
	Message string `json:"message"`
	User    struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	} `json:"user"`
}

func NewApp() (*App, error) {
	return &App{
		baseURL: "http://localhost:8080",
	}, nil
}

func (a *App) Run() error {
	rl, err := readline.NewEx(&readline.Config{
		Prompt:          a.prompt(),
		HistoryFile:     ".cli_history",
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",

		AutoComplete: readline.NewPrefixCompleter(
			readline.PcItem("register"),
			readline.PcItem("login"),
			readline.PcItem("whoami"),
			readline.PcItem("enable-2fa"),
			readline.PcItem("disable-2fa"),
			readline.PcItem("logout"),
			readline.PcItem("help"),
			readline.PcItem("exit"),
		),
	})
	if err != nil {
		return err
	}

	defer rl.Close()

	// Store the readline instance so other CLI commands can
	// safely use the same terminal input mechanism.
	a.rl = rl

	fmt.Println("Type 'help' to see available commands.")
	fmt.Println()

	for {
		line, err := rl.Readline()

		if err != nil {
			// Ctrl+C / Ctrl+D exits the CLI.
			return nil
		}

		command := strings.TrimSpace(line)

		if command == "" {
			continue
		}

		if command == "exit" {
			fmt.Println("Goodbye!")
			return nil
		}

		a.handleCommand(command)

		rl.SetPrompt(a.prompt())
	}
}

// prompt returns the correct CLI prompt depending on
// whether the user is authenticated.
func (a *App) prompt() string {
	if a.loggedIn {
		return fmt.Sprintf("%s> ", a.username)
	}

	return "> "
}

// readLine reads input using the SAME readline instance
// used by the main CLI loop.
//
// This prevents conflicts between readline and multiple
// bufio.Reader instances.
func (a *App) readLine(prompt string) (string, error) {
	if a.rl == nil {
		return "", fmt.Errorf("CLI input is not initialized")
	}

	a.rl.SetPrompt(prompt)

	line, err := a.rl.Readline()

	// Restore the normal application prompt.
	a.rl.SetPrompt(a.prompt())

	return line, err
}

// handleCommand routes the user's command.
func (a *App) handleCommand(command string) {
	switch command {

	case "help":
		a.showHelp()

	case "register":
		if a.loggedIn {
			fmt.Println("You are already logged in.")
			return
		}

		a.register()

	case "login":
		if a.loggedIn {
			fmt.Println("You are already logged in.")
			return
		}

		a.login()

	case "whoami":
		a.whoami()

	case "enable-2fa":
		a.enableMFA()

	case "disable-2fa":
		a.disableMFA()

	case "logout":
		a.logout()

	case "exit":
		fmt.Println("Goodbye!")

	default:
		fmt.Printf("Unknown command: %s\n", command)
		fmt.Println("Type 'help' for available commands.")
	}
}

// register creates a new account through the backend API.
func (a *App) register() {
	fmt.Println()
	fmt.Println("========== Registration ==========")

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

	password, err := readPassword("Password: ")
	if err != nil {
		fmt.Println("Failed to read password.")
		return
	}

	if password == "" {
		fmt.Println("Password cannot be empty.")
		return
	}

	confirmPassword, err := readPassword("Confirm Password: ")
	if err != nil {
		fmt.Println("Failed to read password confirmation.")
		return
	}

	if password != confirmPassword {
		fmt.Println("Passwords do not match.")
		return
	}

	payload := map[string]string{
		"username": username,
		"password": password,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		fmt.Println("Failed to prepare registration request.")
		return
	}

	resp, err := http.Post(
		a.baseURL+"/api/v1/auth/register",
		"application/json",
		strings.NewReader(string(body)),
	)
	if err != nil {
		fmt.Println("Unable to connect to authentication server.")
		fmt.Println("Make sure the Go backend is running.")
		return
	}

	defer resp.Body.Close()

	var result map[string]interface{}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Println("Invalid response from server.")
		return
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		fmt.Println()
		fmt.Println("Registration successful!")
		fmt.Printf("Username: %s\n", username)
		fmt.Println()
		return
	}

	if message, ok := result["error"].(string); ok {
		fmt.Printf("Registration failed: %s\n", message)
		return
	}

	fmt.Printf(
		"Registration failed. HTTP status: %d\n",
		resp.StatusCode,
	)
}

// logout terminates the server-side session.
func (a *App) logout() {
	if !a.loggedIn || a.sessionID == "" {
		fmt.Println("You are not logged in.")
		return
	}

	req, err := http.NewRequest(
		http.MethodPost,
		a.baseURL+"/api/v1/auth/logout",
		nil,
	)
	if err != nil {
		fmt.Println("Failed to create logout request.")
		return
	}

	req.Header.Set(
		"Authorization",
		"Bearer "+a.sessionID,
	)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// Clear local session even if the server is unavailable.
		a.clearSession()

		fmt.Println("Logged out locally.")
		return
	}

	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		a.clearSession()

		fmt.Println("Session already expired.")
		return
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		a.clearSession()

		fmt.Println("Logged out successfully.")
		return
	}

	var result map[string]interface{}

	if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
		if message, ok := result["error"].(string); ok {
			fmt.Printf("Logout failed: %s\n", message)
			return
		}
	}

	fmt.Printf(
		"Logout failed. HTTP status: %d\n",
		resp.StatusCode,
	)
}

// showHelp displays commands available to the current user.
func (a *App) showHelp() {
	fmt.Println()
	fmt.Println("Available commands:")
	fmt.Println()

	if !a.loggedIn {
		fmt.Println("  register     Create a new account")
		fmt.Println("  login        Login to your account")
		fmt.Println("  help         Show available commands")
		fmt.Println("  exit         Exit the application")
	} else {
		fmt.Println("  whoami       Show current user")
		fmt.Println("  enable-2fa   Enable two-factor authentication")
		fmt.Println("  disable-2fa  Disable two-factor authentication")
		fmt.Println("  logout       Logout from your account")
		fmt.Println("  help         Show available commands")
		fmt.Println("  exit         Exit the application")
	}

	fmt.Println()
}