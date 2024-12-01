package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
)

const (
	// ANSI color codes
	colorRed    = "\033[0;31m"
	colorGreen  = "\033[0;32m"
	colorYellow = "\033[1;33m"
	colorNC     = "\033[0m"

	// API constants
	keygenAccountID = "53666519-ebe7-4ca2-9c1a-d026831e4b56"
	keygenBaseURL   = "https://api.keygen.sh/v1/accounts/" + keygenAccountID

	timeFormat    = "2006-01-02-15-04-05"
	logTimeFormat = "2006/01/02 15:04:05"

	// CLI constants
	cliName    = "shapeblock-installer"
	cliVersion = "1.0.0"
)

var logger *log.Logger

func initLogger() error {
	timestamp := time.Now().Format(timeFormat)
	logFile := fmt.Sprintf("install-%s.log", timestamp)

	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return fmt.Errorf("failed to open log file: %v", err)
	}

	logger = log.New(file, "", 0)
	logger.Printf("Installation started at %s", time.Now().Format(logTimeFormat))
	return nil
}

func logMessage(level, msg string) {
	timestamp := time.Now().Format(logTimeFormat)
	logger.Printf("[%s] %s: %s", timestamp, level, msg)
}

type Config struct {
	LicenseKey     string
	AdminUsername  string
	AdminEmail     string
	AdminPassword  string
	DomainName     string
	ConfigureEmail bool
	SMTPHost       string
	SMTPPort       string
	SMTPUsername   string
	SMTPPassword   string
}

func printStatus(msg string) {
	fmt.Printf("%s==>%s %s\n", colorGreen, colorNC, msg)
	logMessage("INFO", msg)
}

func printError(msg string) {
	fmt.Printf("%sError:%s %s\n", colorRed, colorNC, msg)
	logMessage("ERROR", msg)
}

func printWarning(msg string) {
	fmt.Printf("%sWarning:%s %s\n", colorYellow, colorNC, msg)
	logMessage("WARN", msg)
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func checkMemory() error {
	printStatus("Checking system memory...")

	content, err := ioutil.ReadFile("/proc/meminfo")
	if err != nil {
		return fmt.Errorf("failed to read meminfo: %v", err)
	}

	var totalKB int64
	for _, line := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fmt.Sscanf(line, "MemTotal: %d kB", &totalKB)
			break
		}
	}

	totalGB := totalKB / (1024 * 1024)
	if totalGB < 4 {
		return fmt.Errorf("insufficient memory. ShapeBlock requires at least 4GB RAM. Current: %dGB", totalGB)
	}

	return nil
}

func installPrerequisites() error {
	printStatus("Installing prerequisites...")

	// Install jq
	if _, err := exec.LookPath("jq"); err != nil {
		printStatus("Installing jq...")
		if err := runCommand("sudo", "apt-get", "update"); err != nil {
			if err := runCommand("sudo", "yum", "install", "-y", "jq"); err != nil {
				return fmt.Errorf("failed to install jq: %v", err)
			}
		} else {
			if err := runCommand("sudo", "apt-get", "install", "-y", "jq"); err != nil {
				return fmt.Errorf("failed to install jq: %v", err)
			}
		}
	}

	// Install kubectl
	if _, err := exec.LookPath("kubectl"); err != nil {
		printStatus("Installing kubectl...")

		// Get latest stable version
		cmd := exec.Command("curl", "-L", "-s", "https://dl.k8s.io/release/stable.txt")
		version, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("failed to get kubectl version: %v", err)
		}

		// Download kubectl
		downloadURL := fmt.Sprintf("https://dl.k8s.io/release/%s/bin/linux/amd64/kubectl", strings.TrimSpace(string(version)))
		if err := runCommand("curl", "-LO", downloadURL); err != nil {
			return fmt.Errorf("failed to download kubectl: %v", err)
		}

		// Make kubectl executable and move it
		if err := runCommand("chmod", "+x", "kubectl"); err != nil {
			return fmt.Errorf("failed to make kubectl executable: %v", err)
		}
		if err := runCommand("sudo", "mv", "kubectl", "/usr/local/bin/"); err != nil {
			return fmt.Errorf("failed to move kubectl to /usr/local/bin: %v", err)
		}
	}

	// Install helm
	if _, err := exec.LookPath("helm"); err != nil {
		printStatus("Installing helm...")

		// Download helm install script
		if err := runCommand("curl", "-fsSL", "-o", "get_helm.sh",
			"https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3"); err != nil {
			return fmt.Errorf("failed to download helm script: %v", err)
		}

		// Make script executable and run it
		if err := runCommand("chmod", "+x", "get_helm.sh"); err != nil {
			return fmt.Errorf("failed to make helm script executable: %v", err)
		}
		if err := runCommand("./get_helm.sh"); err != nil {
			return fmt.Errorf("failed to install helm: %v", err)
		}

		// Clean up
		if err := os.Remove("get_helm.sh"); err != nil {
			printWarning(fmt.Sprintf("Failed to remove helm installation script: %v", err))
		}
	}

	// Install k3sup
	if _, err := exec.LookPath("k3sup"); err != nil {
		printStatus("Installing k3sup...")

		// Download k3sup
		if err := runCommand("curl", "-sLS", "https://get.k3sup.dev", "-o", "k3sup_install.sh"); err != nil {
			return fmt.Errorf("failed to download k3sup script: %v", err)
		}

		// Make script executable and run it
		if err := runCommand("chmod", "+x", "k3sup_install.sh"); err != nil {
			return fmt.Errorf("failed to make k3sup script executable: %v", err)
		}
		if err := runCommand("./k3sup_install.sh"); err != nil {
			return fmt.Errorf("failed to install k3sup: %v", err)
		}

		// Move k3sup to /usr/local/bin
		if err := runCommand("sudo", "install", "k3sup", "/usr/local/bin/"); err != nil {
			return fmt.Errorf("failed to move k3sup to /usr/local/bin: %v", err)
		}

		// Clean up
		if err := os.Remove("k3sup_install.sh"); err != nil {
			printWarning(fmt.Sprintf("Failed to remove k3sup installation script: %v", err))
		}
		if err := os.Remove("k3sup"); err != nil {
			printWarning(fmt.Sprintf("Failed to remove k3sup binary: %v", err))
		}
	}

	return nil
}

func activateLicense(config *Config) error {
	printStatus("Activating license...")

	// Generate fingerprint from email
	cmd := exec.Command("sh", "-c", fmt.Sprintf("echo -n '%s' | sha256sum | awk '{print $1}'", config.AdminEmail))
	fingerprint, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to generate fingerprint: %v", err)
	}

	// Get license ID
	req, err := http.NewRequest("GET", keygenBaseURL+"/me", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.api+json")
	req.Header.Set("Authorization", "License "+config.LicenseKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var licenseResp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&licenseResp); err != nil {
		return err
	}

	// Activate license
	activationPayload := struct {
		Data struct {
			Type       string `json:"type"`
			Attributes struct {
				Fingerprint string `json:"fingerprint"`
			} `json:"attributes"`
			Relationships struct {
				License struct {
					Data struct {
						Type string `json:"type"`
						ID   string `json:"id"`
					} `json:"data"`
				} `json:"license"`
			} `json:"relationships"`
		} `json:"data"`
	}{}

	activationPayload.Data.Type = "machines"
	activationPayload.Data.Attributes.Fingerprint = string(fingerprint)
	activationPayload.Data.Relationships.License.Data.Type = "licenses"
	activationPayload.Data.Relationships.License.Data.ID = licenseResp.Data.ID

	payloadBytes, err := json.Marshal(activationPayload)
	if err != nil {
		return err
	}

	req, err = http.NewRequest("POST", keygenBaseURL+"/machines", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/vnd.api+json")
	req.Header.Set("Accept", "application/vnd.api+json")
	req.Header.Set("Authorization", "License "+config.LicenseKey)

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("license activation failed with status: %d", resp.StatusCode)
	}

	printStatus("License activated successfully")
	return nil
}

func install(config *Config) error {
	if err := checkMemory(); err != nil {
		return err
	}

	if err := installPrerequisites(); err != nil {
		return err
	}

	if err := activateLicense(config); err != nil {
		return err
	}

	// Add remaining installation steps
	// - install_k3s
	// - install_helm_charts
	// - install_shapeblock
	// - verify_installation

	return nil
}

func collectInput(config *Config) error {
	printStatus("Please provide the following information:")

	// Helper function to read input with validation
	readInput := func(prompt string, required bool, validator func(string) error) (string, error) {
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Printf("%s: ", prompt)
			input, err := reader.ReadString('\n')
			if err != nil {
				return "", err
			}
			input = strings.TrimSpace(input)

			if input == "" && required {
				printError("This field is required")
				continue
			}

			if input != "" && validator != nil {
				if err := validator(input); err != nil {
					printError(err.Error())
					continue
				}
			}

			return input, nil
		}
	}

	// Read password with confirmation
	readPassword := func(prompt string) (string, error) {
		for {
			fmt.Printf("%s: ", prompt)
			password, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				return "", err
			}
			fmt.Println()

			fmt.Print("Confirm password: ")
			confirm, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				return "", err
			}
			fmt.Println()

			if string(password) != string(confirm) {
				printError("Passwords do not match")
				continue
			}

			if len(password) == 0 {
				printError("Password cannot be empty")
				continue
			}

			return string(password), nil
		}
	}

	// Validate email format
	emailValidator := func(email string) error {
		if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
			return fmt.Errorf("invalid email format")
		}
		return nil
	}

	// Collect required inputs if not provided via flags
	var err error

	if config.LicenseKey == "" {
		config.LicenseKey, err = readInput("License key", true, nil)
		if err != nil {
			return err
		}
	}

	if config.AdminUsername == "" {
		config.AdminUsername, err = readInput("Admin username", true, nil)
		if err != nil {
			return err
		}
	}

	if config.AdminEmail == "" {
		config.AdminEmail, err = readInput("Admin email", true, emailValidator)
		if err != nil {
			return err
		}
	}

	if config.AdminPassword == "" {
		config.AdminPassword, err = readPassword("Admin password")
		if err != nil {
			return err
		}
	}

	if config.DomainName == "" {
		config.DomainName, err = readInput("Domain name (optional)", false, nil)
		if err != nil {
			return err
		}
	}

	// Ask about email configuration
	configureEmailStr, err := readInput("Configure email settings? (y/N)", false, nil)
	if err != nil {
		return err
	}

	config.ConfigureEmail = strings.ToLower(configureEmailStr) == "y"

	if config.ConfigureEmail {
		config.SMTPHost, err = readInput("SMTP host", true, nil)
		if err != nil {
			return err
		}

		config.SMTPPort, err = readInput("SMTP port", true, nil)
		if err != nil {
			return err
		}

		config.SMTPUsername, err = readInput("SMTP username", true, nil)
		if err != nil {
			return err
		}

		config.SMTPPassword, err = readPassword("SMTP password")
		if err != nil {
			return err
		}
	}

	// Log collected information (excluding passwords)
	logMessage("INFO", fmt.Sprintf("Admin username: %s", config.AdminUsername))
	logMessage("INFO", fmt.Sprintf("Admin email: %s", config.AdminEmail))
	logMessage("INFO", fmt.Sprintf("Domain name: %s", config.DomainName))
	logMessage("INFO", fmt.Sprintf("Configure email: %v", config.ConfigureEmail))
	if config.ConfigureEmail {
		logMessage("INFO", fmt.Sprintf("SMTP host: %s", config.SMTPHost))
		logMessage("INFO", fmt.Sprintf("SMTP port: %s", config.SMTPPort))
		logMessage("INFO", fmt.Sprintf("SMTP username: %s", config.SMTPUsername))
	}

	return nil
}

// Update main function to use interactive input
func main() {
	if err := initLogger(); err != nil {
		fmt.Printf("%sError:%s Failed to initialize logger: %v\n", colorRed, colorNC, err)
		os.Exit(1)
	}

	var config Config

	// Parse command line flags
	installCmd := flag.NewFlagSet("install", flag.ExitOnError)
	installCmd.StringVar(&config.LicenseKey, "license", "", "License key")
	installCmd.StringVar(&config.AdminUsername, "username", "", "Admin username")
	installCmd.StringVar(&config.AdminEmail, "email", "", "Admin email")
	installCmd.StringVar(&config.AdminPassword, "password", "", "Admin password")
	installCmd.StringVar(&config.DomainName, "domain", "", "Domain name (optional)")

	if len(os.Args) < 2 {
		fmt.Println("expected 'install' subcommand")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "install":
		installCmd.Parse(os.Args[2:])
		if err := collectInput(&config); err != nil {
			printError(fmt.Sprintf("Failed to collect input: %v", err))
			os.Exit(1)
		}
		if err := install(&config); err != nil {
			printError(err.Error())
			logger.Printf("[%s] Installation failed: %v", time.Now().Format(logTimeFormat), err)
			os.Exit(1)
		}
		logger.Printf("[%s] Installation completed successfully", time.Now().Format(logTimeFormat))
	default:
		fmt.Printf("unknown subcommand: %s\n", os.Args[1])
		logger.Printf("[%s] Unknown subcommand: %s", time.Now().Format(logTimeFormat), os.Args[1])
		os.Exit(1)
	}
}
