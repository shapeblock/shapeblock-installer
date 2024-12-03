package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"embed"

	"github.com/manifoldco/promptui"
	"golang.org/x/exp/rand"
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
	//nolint:unused
	cliName = "shapeblock-installer"
	//nolint:unused
	cliVersion = "1.0.0"
)

//go:embed assets/tekton/*
var tektonAssets embed.FS
var logger *log.Logger

//go:embed assets/epinio/*
var epinioAssets embed.FS

func initLogger() error {
	timestamp := time.Now().Format(timeFormat)
	logFile := fmt.Sprintf("install-%s.log", timestamp)

	// Check if log file already exists
	if _, err := os.Stat(logFile); err == nil {
		// File exists, append to it
		file, err := os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0666)
		if err != nil {
			return fmt.Errorf("failed to open existing log file: %v", err)
		}
		logger = log.New(file, "", 0)
		logger.Printf("=== Installation resumed at %s ===", time.Now().Format(logTimeFormat))
		return nil
	}

	// Create new log file
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return fmt.Errorf("failed to create log file: %v", err)
	}

	logger = log.New(file, "", 0)
	logger.Printf("=== Installation started at %s ===", time.Now().Format(logTimeFormat))
	return nil
}

func logMessage(level, msg string) {
	timestamp := time.Now().Format(logTimeFormat)
	logger.Printf("[%s] %s: %s", timestamp, level, msg)
}

type Config struct {
	LicenseKey     string
	AdminEmail     string
	AdminPassword  string
	DomainName     string
	ConfigureEmail bool
	SMTPHost       string
	SMTPPort       string
	SMTPUsername   string
	SMTPPassword   string
}

type BackendConfig struct {
	ServiceAccountToken string
	EpinioUsername      string
	EpinioPassword      string
	PostgresUsername    string
	PostgresPassword    string
	PostgresDatabase    string
	PostgresRootPW      string
	TFStateUsername     string
	TFStatePassword     string
	TFStateDatabase     string
	TFStateRootPW       string
	LicenseKey          string
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

type Spinner struct {
	stopChan chan struct{}
	message  string
}

func NewSpinner(message string) *Spinner {
	return &Spinner{
		stopChan: make(chan struct{}),
		message:  message,
	}
}

func (s *Spinner) Start() {
	go func() {
		frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for i := 0; ; i++ {
			select {
			case <-s.stopChan:
				return
			case <-ticker.C:
				// Clear the line and move cursor to beginning
				fmt.Printf("\r\033[K%s %s", frames[i%len(frames)], s.message)
			}
		}
	}()
}

func (s *Spinner) Stop() {
	s.stopChan <- struct{}{}
	// Clear the line
	fmt.Print("\r\033[K")
}

func runCommand(command string, args ...string) error {
	// Append kubeconfig flag for kubectl and helm commands
	if command == "kubectl" || command == "helm" {
		args = append(args, "--kubeconfig=/etc/rancher/k3s/k3s.yaml")
	}

	// Print the command first
	fmt.Printf("==> Running: %s %s\n", command, strings.Join(args, " "))

	// Start spinner without the command text
	spinner := NewSpinner("Processing...")
	spinner.Start()
	defer spinner.Stop()

	cmd := exec.Command(command, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command \"%s\" failed: %v\nOutput: %s", cmd, err, string(output))
	}
	return nil
}

func checkMemory() error {
	printStatus("Checking system memory...")

	content, err := os.ReadFile("/proc/meminfo")
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

	if totalKB < 4000000 {
		return fmt.Errorf("insufficient memory. ShapeBlock requires at least 4GB RAM. Current: %.1fGB", float64(totalKB)/1024/1024)
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
		// Clean up
		if err := os.Remove("k3sup_install.sh"); err != nil {
			printWarning(fmt.Sprintf("Failed to remove k3sup installation script: %v", err))
		}
	}

	return nil
}

func addHelmRepo(name, url string) error {
	printStatus(fmt.Sprintf("Adding helm repo %s...", name))

	// Check if repo already exists
	output, _ := exec.Command("helm", "repo", "list").Output()
	if strings.Contains(string(output), name) {
		printStatus(fmt.Sprintf("Helm repo %s already exists", name))
		return nil
	}

	if err := runCommand("helm", "repo", "add", name, url); err != nil {
		return fmt.Errorf("failed to add helm repo %s: %v", name, err)
	}
	return nil
}

func resourceExists(kind, name, namespace string) bool {
	if kind == "node" {
		// Nodes do not require a namespace
		return runCommand("kubectl", "get", kind) == nil
	}
	if kind == "clusterissuer" {
		// Cluster issuers do not require a namespace
		return runCommand("kubectl", "get", kind, name) == nil
	}
	return runCommand("kubectl", "get", kind, name, "-n", namespace) == nil
}

func installNginxIngress() error {
	if resourceExists("deployment", "nginx-ingress", "shapeblock") {
		printStatus("Nginx Ingress already installed")
		return nil
	}

	printStatus("Installing Nginx Ingress...")
	if err := addHelmRepo("bitnami", "https://charts.bitnami.com/bitnami"); err != nil {
		return err
	}

	if err := runCommand("helm", "repo", "update"); err != nil {
		printError(fmt.Sprintf("Failed to update helm repos: %v", err))
		return err
	}

	return runCommand("helm", "upgrade", "--install",
		"nginx-ingress", "bitnami/nginx-ingress-controller",
		"--version", "11.3.18",
		"--namespace", "shapeblock",
		"--create-namespace",
		"--timeout", "600s")
}

func installCertManager() error {
	if resourceExists("deployment", "cert-manager", "cert-manager") {
		printStatus("Cert Manager already installed")
		return nil
	}

	printStatus("Installing Cert Manager...")
	if err := addHelmRepo("bitnami", "https://charts.bitnami.com/bitnami"); err != nil {
		return err
	}

	return runCommand("helm", "upgrade", "--install",
		"cert-manager", "bitnami/cert-manager",
		"--version", "1.3.16",
		"--namespace", "cert-manager",
		"--create-namespace",
		"--set", "installCRDs=true",
		"--timeout", "600s")
}

func installClusterIssuer(email string) error {
	if resourceExists("clusterissuer", "letsencrypt-prod", "") {
		printStatus("ClusterIssuer already installed")
		return nil
	}

	printStatus("Installing ClusterIssuer...")

	// Wait for cert-manager to be ready
	printStatus("Waiting 30 seconds for cert-manager to be ready...")
	time.Sleep(30 * time.Second)

	// Create cluster issuer YAML with the provided email
	issuerYAML := fmt.Sprintf(`apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    email: %s
    server: https://acme-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: letsencrypt-secret-prod
    solvers:
    - http01:
        ingress:
          class: nginx`, email)

	// Write YAML to temporary file
	tmpfile, err := os.CreateTemp("", "cluster-issuer-*.yaml")
	if err != nil {
		printError(fmt.Sprintf("Failed to create temp file: %v", err))
		return err
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.WriteString(issuerYAML); err != nil {
		printError(fmt.Sprintf("Failed to write YAML: %v", err))
		return err
	}
	tmpfile.Close()

	// Apply the cluster issuer
	if err := runCommand("kubectl", "apply", "-f", tmpfile.Name()); err != nil {
		printError(fmt.Sprintf("Failed to apply cluster issuer: %v", err))
		return err
	}

	return nil
}

func installTekton() error {
	if resourceExists("deployment", "tekton-pipelines-controller", "tekton-pipelines") {
		printStatus("Tekton already installed")
		return nil
	}

	// Define versions
	tektonVersion := "v0.74.0"
	dashboardVersion := "v0.52.0"

	printStatus(fmt.Sprintf("Installing Tekton %s and Dashboard %s...", tektonVersion, dashboardVersion))

	// Install Tekton Pipelines
	releaseURL := fmt.Sprintf("https://storage.googleapis.com/tekton-releases/operator/previous/%s/release.yaml", tektonVersion)
	if err := runCommand("kubectl", "apply", "-f", releaseURL); err != nil {
		printError(fmt.Sprintf("Failed to install Tekton: %v", err))
		return fmt.Errorf("failed to install Tekton: %v", err)
	}

	// Install Tekton Dashboard
	dashboardURL := fmt.Sprintf("https://storage.googleapis.com/tekton-releases/dashboard/previous/%s/release.yaml", dashboardVersion)
	if err := runCommand("kubectl", "apply", "-f", dashboardURL); err != nil {
		printError(fmt.Sprintf("Failed to install Tekton Dashboard: %v", err))
		return fmt.Errorf("failed to install Tekton Dashboard: %v", err)
	}

	return nil
}

func installTektonResources() error {
	printStatus("Installing/Updating Tekton resources...")

	resources := []string{
		// Tasks
		"assets/tekton/tasks/cluster-artefacts-task.yaml",
		"assets/tekton/tasks/destroy-cluster-task.yaml",
		"assets/tekton/tasks/k3s-remove-node-task.yaml",
		"assets/tekton/tasks/k3sup-task.yaml",
		"assets/tekton/tasks/kubectl-task.yaml",
		"assets/tekton/tasks/terraform-infra-task.yaml",

		// Pipelines
		"assets/tekton/pipelines/create-cluster-pipeline.yaml",
		"assets/tekton/pipelines/scale-down-cluster-pipeline.yaml",
		"assets/tekton/pipelines/scale-up-cluster-pipeline.yaml",
		"assets/tekton/pipelines/ssh-cluster-pipeline.yaml",
	}

	for _, resource := range resources {
		// Read embedded file
		content, err := tektonAssets.ReadFile(resource)
		if err != nil {
			printError(fmt.Sprintf("Failed to read resource %s: %v", resource, err))
			return err
		}

		// Create temporary file
		tmpfile, err := os.CreateTemp("", "tekton-*.yaml")
		if err != nil {
			printError(fmt.Sprintf("Failed to create temp file: %v", err))
			return err
		}
		defer os.Remove(tmpfile.Name())

		// Write content to temp file
		if _, err := tmpfile.Write(content); err != nil {
			printError(fmt.Sprintf("Failed to write to temp file: %v", err))
			return err
		}
		tmpfile.Close()

		// Apply the resource
		if err := runCommand("kubectl", "apply", "-f", tmpfile.Name(), "-n", "shapeblock"); err != nil {
			printError(fmt.Sprintf("Failed to install Tekton resource %s: %v", resource, err))
			return err
		}
	}

	return nil
}

func getServiceAccountToken() (string, error) {
	output, err := exec.Command("kubectl", "get", "secret", "tasks-runner-token", "-n", "shapeblock", "-o", "jsonpath={.data.token}", "--kubeconfig=/etc/rancher/k3s/k3s.yaml").Output()
	if err != nil {
		printError(fmt.Sprintf("Failed to get token: %v", err))
		return "", err
	}

	token, err := base64.StdEncoding.DecodeString(string(output))
	if err != nil {
		printError(fmt.Sprintf("Failed to decode token: %v", err))
		return "", err
	}

	return string(token), nil
}

func createServiceAccount(backendConfig *BackendConfig) error {
	if resourceExists("serviceaccount", "tasks-runner", "shapeblock") {
		printStatus("Service account already exists")
		// Still get the token as we need it
		token, err := getServiceAccountToken()
		if err != nil {
			return err
		}
		backendConfig.ServiceAccountToken = token
		return nil
	}

	printStatus("Creating service account and RBAC resources...")

	// Role YAML
	roleYAML := `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: sb-tasks
rules:
- apiGroups: ["tekton.dev"]
  resources: ["taskruns", "pipelineruns"]
  verbs: ["get", "watch", "list", "create", "update", "patch", "delete"]
- apiGroups: [""]
  resources: ["configmaps", "secrets", "persistentvolumeclaims", "pods", "pods/log"]
  verbs: ["get", "watch", "list"]`

	// Service Account YAML
	saYAML := `apiVersion: v1
kind: ServiceAccount
metadata:
  name: tasks-runner`

	// Token Secret YAML
	tokenYAML := `apiVersion: v1
kind: Secret
metadata:
  name: tasks-runner-token
  annotations:
    kubernetes.io/service-account.name: tasks-runner
type: kubernetes.io/service-account-token`

	// Role Binding YAML
	bindingYAML := `apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: sb-tasks-runner
subjects:
- kind: ServiceAccount
  name: tasks-runner
roleRef:
  kind: Role
  name: sb-tasks
  apiGroup: rbac.authorization.k8s.io`

	// Create temporary files and apply each resource
	for name, content := range map[string]string{
		"role.yaml":    roleYAML,
		"sa.yaml":      saYAML,
		"token.yaml":   tokenYAML,
		"binding.yaml": bindingYAML,
	} {
		tmpfile, err := os.CreateTemp("", name)
		if err != nil {
			printError(fmt.Sprintf("Failed to create temp file: %v", err))
			return err
		}
		defer os.Remove(tmpfile.Name())

		if _, err := tmpfile.WriteString(content); err != nil {
			printError(fmt.Sprintf("Failed to write YAML: %v", err))
			return err
		}
		tmpfile.Close()

		if err := runCommand("kubectl", "apply", "-f", tmpfile.Name(), "-n", "shapeblock", "--kubeconfig=/etc/rancher/k3s/k3s.yaml"); err != nil {
			printError(fmt.Sprintf("Failed to apply %s: %v", name, err))
			return err
		}
	}

	// Get and store the token
	token, err := getServiceAccountToken()
	if err != nil {
		return fmt.Errorf("failed to get service account token: %v", err)
	}
	backendConfig.ServiceAccountToken = token

	printStatus("Service account and RBAC resources created successfully")
	return nil
}

func getNodeIP() (string, error) {
	output, err := exec.Command("hostname", "-I").Output()
	if err != nil {
		return "", fmt.Errorf("failed to get IP: %v", err)
	}
	// Get first IP address
	ip := strings.Fields(string(output))[0]
	return ip, nil
}

func generatePassword() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	length := 16
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func installEpinio(config *Config, backendConfig *BackendConfig) error {
	if resourceExists("deployment", "epinio-server", "epinio") {
		printStatus("Epinio already installed")
		return nil
	}

	printStatus("Installing Epinio...")

	// Add Epinio helm repo
	if err := addHelmRepo("epinio", "https://epinio.github.io/helm-charts"); err != nil {
		return err
	}

	if err := runCommand("helm", "repo", "update"); err != nil {
		printError(fmt.Sprintf("Failed to update helm repos: %v", err))
		return err
	}

	// Determine domain
	var domain string
	if config.DomainName != "" {
		domain = config.DomainName
	} else {
		ip, err := getNodeIP()
		if err != nil {
			return err
		}
		domain = fmt.Sprintf("%s.nip.io", ip)
	}

	// Set Epinio credentials
	backendConfig.EpinioUsername = "shapeblock"
	backendConfig.EpinioPassword = generatePassword()

	printStatus(fmt.Sprintf("Generated Epinio password: %s", backendConfig.EpinioPassword))
	logMessage("INFO", fmt.Sprintf("Epinio credentials - username: %s, password: %s",
		backendConfig.EpinioUsername, backendConfig.EpinioPassword))

	// Create values.yaml
	values := fmt.Sprintf(`
global:
  domain: %s
  tlsIssuer: letsencrypt-prod
  tlsIssuerEmail: %s
  dex:
    enabled: false
ingress:
  ingressClassName: nginx
api:
  users:
    - username: %s
      password: %s
      roles: ["admin"]
epinioUI:
  enabled: false
`, domain, config.AdminEmail, backendConfig.EpinioUsername, backendConfig.EpinioPassword)

	// Write values to temporary file
	tmpfile, err := os.CreateTemp("", "epinio-values-*.yaml")
	if err != nil {
		printError(fmt.Sprintf("Failed to create temp file: %v", err))
		return err
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.WriteString(values); err != nil {
		printError(fmt.Sprintf("Failed to write values: %v", err))
		return err
	}
	tmpfile.Close()

	// Install Epinio
	if err := runCommand("helm", "upgrade", "--install",
		"epinio", "epinio/epinio",
		"--version", "1.11.1",
		"--namespace", "epinio",
		"--create-namespace",
		"--values", tmpfile.Name(),
		"--timeout", "600s"); err != nil {
		printError(fmt.Sprintf("Failed to install Epinio: %v", err))
		return err
	}

	return nil
}

func installPostgres(name, username, database string, backendConfig *BackendConfig) error {
	printStatus(fmt.Sprintf("Installing PostgreSQL instance %s...", name))

	if resourceExists("statefulset", name+"-postgresql", "shapeblock") {
		printStatus(fmt.Sprintf("PostgreSQL instance %s already installed", name))
		return nil
	}

	if err := addHelmRepo("bitnami", "https://charts.bitnami.com/bitnami"); err != nil {
		return err
	}

	// Generate passwords
	password := generatePassword()
	rootPW := generatePassword()

	// Store credentials based on instance name
	switch name {
	case "db":
		backendConfig.PostgresUsername = username
		backendConfig.PostgresDatabase = database
		backendConfig.PostgresPassword = password
		backendConfig.PostgresRootPW = rootPW
	case "tfstate":
		backendConfig.TFStateUsername = username
		backendConfig.TFStateDatabase = database
		backendConfig.TFStatePassword = password
		backendConfig.TFStateRootPW = rootPW
	}

	// Log the credentials for debugging
	logMessage("INFO", fmt.Sprintf("PostgreSQL %s credentials - username: %s, database: %s, password: %s",
		name, username, database, password))

	// Create values.yaml
	values := fmt.Sprintf(`
auth:
  database: %s
  username: %s
  password: %s
  postgresPassword: %s
architecture: standalone
primary:
  persistence:
    size: 2Gi
tls:
  enabled: true
  autoGenerated: true
`, database, username, password, rootPW)

	// Write values to temporary file
	tmpfile, err := os.CreateTemp("", fmt.Sprintf("%s-values-*.yaml", name))
	if err != nil {
		printError(fmt.Sprintf("Failed to create temp file: %v", err))
		return err
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.WriteString(values); err != nil {
		printError(fmt.Sprintf("Failed to write values: %v", err))
		return err
	}
	tmpfile.Close()

	// Install PostgreSQL
	if err := runCommand("helm", "upgrade", "--install",
		name, "bitnami/postgresql",
		"--version", "16.2.3",
		"--namespace", "shapeblock",
		"--values", tmpfile.Name(),
		"--timeout", "600s"); err != nil {
		printError(fmt.Sprintf("Failed to install PostgreSQL %s: %v", name, err))
		return err
	}

	printStatus(fmt.Sprintf("PostgreSQL instance %s installed successfully", name))
	return nil
}

func createTerraformSecret(backendConfig *BackendConfig) error {
	printStatus("Creating Terraform credentials secret...")

	if resourceExists("secret", "terraform-creds", "shapeblock") {
		printStatus("Terraform credentials secret already exists")
		return nil
	}

	// Create connection string
	connStr := fmt.Sprintf("postgres://%s:%s@tfstate-postgresql/%s",
		backendConfig.TFStateUsername,
		backendConfig.TFStatePassword,
		backendConfig.TFStateDatabase)

	// Create secret
	if err := runCommand("kubectl", "create", "secret", "generic",
		"terraform-creds",
		fmt.Sprintf("--from-literal=PG_CONN_STR=%s", connStr),
		"-n", "shapeblock", "--kubeconfig=/etc/rancher/k3s/k3s.yaml"); err != nil {
		printError(fmt.Sprintf("Failed to create Terraform credentials secret: %v", err))
		return err
	}

	printStatus("Terraform credentials secret created successfully")
	return nil
}

func installRedis() error {
	printStatus("Installing Redis...")

	if resourceExists("statefulset", "redis-master", "shapeblock") {
		printStatus("Redis already installed")
		return nil
	}

	if err := addHelmRepo("bitnami", "https://charts.bitnami.com/bitnami"); err != nil {
		return err
	}

	// Create values.yaml
	values := `
architecture: standalone
auth:
  enabled: false
master:
  persistence:
    size: 2Gi`

	// Write values to temporary file
	tmpfile, err := os.CreateTemp("", "redis-values-*.yaml")
	if err != nil {
		printError(fmt.Sprintf("Failed to create temp file: %v", err))
		return err
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.WriteString(values); err != nil {
		printError(fmt.Sprintf("Failed to write values: %v", err))
		return err
	}
	tmpfile.Close()

	// Install Redis
	if err := runCommand("helm", "upgrade", "--install",
		"redis", "bitnami/redis",
		"--version", "18.4.0",
		"--namespace", "shapeblock",
		"--values", tmpfile.Name(),
		"--timeout", "600s"); err != nil {
		printError(fmt.Sprintf("Failed to install Redis: %v", err))
		return err
	}

	printStatus("Redis installed successfully")
	return nil
}

func installEpinioResources() error {
	printStatus("Installing Epinio resources...")

	resources := []string{
		"assets/epinio/mongodb-sb.yaml",
		"assets/epinio/mysql-sb.yaml",
		"assets/epinio/postgresql-sb.yaml",
		"assets/epinio/redis-sb.yaml",
	}

	for _, resource := range resources {
		// Read embedded file
		content, err := epinioAssets.ReadFile(resource)
		if err != nil {
			printError(fmt.Sprintf("Failed to read resource %s: %v", resource, err))
			return err
		}

		// Create temporary file
		tmpfile, err := os.CreateTemp("", "epinio-*.yaml")
		if err != nil {
			printError(fmt.Sprintf("Failed to create temp file: %v", err))
			return err
		}
		defer os.Remove(tmpfile.Name())

		// Write content to temp file
		if _, err := tmpfile.Write(content); err != nil {
			printError(fmt.Sprintf("Failed to write to temp file: %v", err))
			return err
		}
		tmpfile.Close()

		// Apply the resource
		if err := runCommand("kubectl", "apply", "-f", tmpfile.Name(), "--kubeconfig=/etc/rancher/k3s/k3s.yaml", "-n", "epinio"); err != nil {
			printError(fmt.Sprintf("Failed to install Epinio resource %s: %v", resource, err))
			return err
		}
	}

	return nil
}

func install(config *Config, backendConfig *BackendConfig) error {
	// Check if Kubernetes is already installed
	printStatus("Checking if Kubernetes is already installed...")
	if !resourceExists("node", "", "") {
		printStatus("Kubernetes not found. Installing Kubernetes using k3sup...")
		if err := runCommand("k3sup", "install", "--local"); err != nil {
			return fmt.Errorf("failed to install Kubernetes: %v", err)
		}

		// Wait a moment for the cluster to initialize
		printStatus("Waiting for Kubernetes cluster to initialize...")
		time.Sleep(10 * time.Second)
	} else {
		printStatus("Kubernetes is already installed")
	}

	if err := installPrerequisites(); err != nil {
		return err
	}

	if err := installNginxIngress(); err != nil {
		return fmt.Errorf("failed to install nginx ingress: %v", err)
	}

	if err := installCertManager(); err != nil {
		return fmt.Errorf("failed to install cert-manager: %v", err)
	}

	if err := installClusterIssuer(config.AdminEmail); err != nil {
		return fmt.Errorf("failed to install cluster issuer: %v", err)
	}

	if err := installTekton(); err != nil {
		return fmt.Errorf("failed to install Tekton: %v", err)
	}

	if err := installTektonResources(); err != nil {
		return fmt.Errorf("failed to install Tekton resources: %v", err)
	}

	if err := createServiceAccount(backendConfig); err != nil {
		return fmt.Errorf("failed to create service account: %v", err)
	}

	if err := installEpinio(config, backendConfig); err != nil {
		return fmt.Errorf("failed to install Epinio: %v", err)
	}

	// Install main PostgreSQL instance
	if err := installPostgres("db", "shapeblock", "shapeblock", backendConfig); err != nil {
		return fmt.Errorf("failed to install main PostgreSQL: %v", err)
	}

	// Install TFState PostgreSQL instance
	if err := installPostgres("tfstate", "tfstate", "tfstate", backendConfig); err != nil {
		return fmt.Errorf("failed to install TFState PostgreSQL: %v", err)
	}

	// Create Terraform credentials secret
	if err := createTerraformSecret(backendConfig); err != nil {
		return fmt.Errorf("failed to create Terraform credentials secret: %v", err)
	}

	if err := installRedis(); err != nil {
		return fmt.Errorf("failed to install Redis: %v", err)
	}

	if err := installEpinioResources(); err != nil {
		return fmt.Errorf("failed to install Epinio resources: %v", err)
	}

	if err := installBackend(config, backendConfig); err != nil {
		return fmt.Errorf("failed to install shapeblock backend: %v", err)
	}

	return nil
}

func validateRequired(input string) error {
	if len(input) == 0 {
		return errors.New("this field is required")
	}
	return nil
}

func validateEmail(input string) error {
	if err := validateRequired(input); err != nil {
		return err
	}
	if !strings.Contains(input, "@") || !strings.Contains(input, ".") {
		return errors.New("invalid email format")
	}
	return nil
}

func collectInput(config *Config, backendConfig *BackendConfig) error {
	// License Key
	prompt := promptui.Prompt{
		Label:    "License key",
		Validate: validateRequired,
	}
	result, err := prompt.Run()
	if err != nil {
		return fmt.Errorf("prompt failed: %v", err)
	}
	config.LicenseKey = result

	// Admin Email
	prompt = promptui.Prompt{
		Label:    "Admin email",
		Validate: validateEmail,
	}
	result, err = prompt.Run()
	if err != nil {
		return fmt.Errorf("prompt failed: %v", err)
	}
	config.AdminEmail = result

	if err := validateAndActivateLicense(config.AdminEmail, config.LicenseKey); err != nil {
		return fmt.Errorf("license validation failed: %v", err)
	}

	// Admin Password
	prompt = promptui.Prompt{
		Label: "Admin password",
		Mask:  '*',
		Validate: func(input string) error {
			if len(input) == 0 {
				return errors.New("this field is required")
			}
			return nil
		},
	}
	result, err = prompt.Run()
	if err != nil {
		return fmt.Errorf("prompt failed: %v", err)
	}
	config.AdminPassword = result

	// Domain Name
	prompt = promptui.Prompt{
		Label: "Domain name (optional)",
	}
	result, err = prompt.Run()
	if err != nil {
		return fmt.Errorf("prompt failed: %v", err)
	}
	config.DomainName = result

	// Configure Email
	configureEmailPrompt := promptui.Select{
		Label: "Configure email settings?",
		Items: []string{"Yes", "No"},
	}
	_, result, err = configureEmailPrompt.Run()
	if err != nil {
		return fmt.Errorf("prompt failed: %v", err)
	}
	config.ConfigureEmail = result == "Yes"

	if config.ConfigureEmail {
		// SMTP Host
		prompt = promptui.Prompt{
			Label:    "SMTP host",
			Validate: validateRequired,
		}
		result, err = prompt.Run()
		if err != nil {
			return fmt.Errorf("prompt failed: %v", err)
		}
		config.SMTPHost = result

		// SMTP Port
		prompt = promptui.Prompt{
			Label:    "SMTP port",
			Validate: validateRequired,
		}
		result, err = prompt.Run()
		if err != nil {
			return fmt.Errorf("prompt failed: %v", err)
		}
		config.SMTPPort = result

		// SMTP Username
		prompt = promptui.Prompt{
			Label:    "SMTP username",
			Validate: validateRequired,
		}
		result, err = prompt.Run()
		if err != nil {
			return fmt.Errorf("prompt failed: %v", err)
		}
		config.SMTPUsername = result

		// SMTP Password
		prompt = promptui.Prompt{
			Label:    "SMTP password",
			Validate: validateRequired,
			Mask:     '*',
		}
		result, err = prompt.Run()
		if err != nil {
			return fmt.Errorf("prompt failed: %v", err)
		}
		config.SMTPPassword = result
	}

	// Log collected information (excluding passwords)
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

	if len(os.Args) < 2 {
		fmt.Println("expected 'install' subcommand")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "install":
		// Check memory first
		if err := checkMemory(); err != nil {
			printError(err.Error())
			logger.Printf("[%s] Installation failed: %v", time.Now().Format(logTimeFormat), err)
			os.Exit(1)
		}

		// Check prerequisites
		if err := installPrerequisites(); err != nil {
			printError(err.Error())
			logger.Printf("[%s] Installation failed: %v", time.Now().Format(logTimeFormat), err)
			os.Exit(1)
		}

		// Proceed with input collection and installation
		var config Config
		var backendConfig BackendConfig
		if err := collectInput(&config, &backendConfig); err != nil {
			printError(fmt.Sprintf("Failed to collect input: %v", err))
			os.Exit(1)
		}
		if err := install(&config, &backendConfig); err != nil {
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

func validateAndActivateLicense(email, licenseKey string) error {
	// Regex pattern for license key
	licensePattern := `^[A-F0-9]{6}-[A-F0-9]{6}-[A-F0-9]{6}-[A-F0-9]{6}-[A-F0-9]{6}-V3$`
	matched, err := regexp.MatchString(licensePattern, licenseKey)
	if err != nil {
		return fmt.Errorf("failed to compile regex: %v", err)
	}
	if !matched {
		return fmt.Errorf("invalid license format")
	}

	printStatus("Validating license...")

	// Create fingerprint from email
	// Shell equivalent: echo -n "$email" | sha256sum | awk '{print $1}'
	fingerprint := sha256.Sum256([]byte(email))
	fingerprintHex := hex.EncodeToString(fingerprint[:])

	logMessage("INFO", fmt.Sprintf("Fingerprint: %s", fingerprintHex))
	// First validate the license
	validateURL := fmt.Sprintf("%s/licenses/actions/validate-key", keygenBaseURL)
	validatePayload := map[string]interface{}{
		"meta": map[string]interface{}{
			"key": licenseKey,
			"scope": map[string]interface{}{
				"fingerprint": fingerprintHex,
			},
		},
	}

	resp, err := makeRequest("POST", validateURL, validatePayload, licenseKey)
	if err != nil {
		return fmt.Errorf("license validation failed: %v", err)
	}

	meta := resp["meta"].(map[string]interface{})
	if meta["valid"].(bool) {
		printStatus("License is valid and activated")
		return nil
	}

	// Handle invalid license scenario
	detail := meta["detail"].(string)
	printError(fmt.Sprintf("Invalid license: %s", detail))
	logMessage("ERROR", fmt.Sprintf("Invalid license: %s", detail))

	// Check if we need to activate
	if meta["code"] != "NO_MACHINE" {
		return fmt.Errorf("invalid license: %s", detail)
	}

	// Get license ID using the /me endpoint
	meURL := fmt.Sprintf("%s/me", keygenBaseURL)
	licenseInfo, err := makeRequest("GET", meURL, nil, licenseKey)
	if err != nil {
		return fmt.Errorf("failed to get license info: %v", err)
	}

	licenseData := licenseInfo["data"].(map[string]interface{})
	licenseID := licenseData["id"].(string)
	status := licenseData["attributes"].(map[string]interface{})["status"].(string)

	if status != "ACTIVE" {
		return fmt.Errorf("license is not active (status: %s)", status)
	}

	printStatus("Activating license...")
	// Activate the license by creating a machine
	activateURL := fmt.Sprintf("%s/machines", keygenBaseURL)
	activatePayload := map[string]interface{}{
		"data": map[string]interface{}{
			"type": "machines",
			"attributes": map[string]interface{}{
				"fingerprint": fingerprintHex,
			},
			"relationships": map[string]interface{}{
				"license": map[string]interface{}{
					"data": map[string]interface{}{
						"type": "licenses",
						"id":   licenseID,
					},
				},
			},
		},
	}

	_, err = makeRequest("POST", activateURL, activatePayload, licenseKey)
	if err != nil {
		return fmt.Errorf("license activation failed: %v", err)
	}

	printStatus("License activated successfully")

	return nil
}

// Helper function to make HTTP requests
func makeRequest(method, url string, payload interface{}, licenseKey string) (map[string]interface{}, error) {
	var reqBody io.Reader
	if payload != nil {
		jsonData, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %v", err)
		}
		reqBody = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/vnd.api+json")
	req.Header.Set("Accept", "application/vnd.api+json")
	req.Header.Set("Authorization", "License "+licenseKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return result, nil
}

func generateSecretKey() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
	length := 50
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func generateFernetKeys() string {
	// Generate two Fernet keys
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	// Encode them in base64 and join with comma
	return fmt.Sprintf("%s,%s",
		base64.URLEncoding.EncodeToString(key1),
		base64.URLEncoding.EncodeToString(key2))
}

func generateBackendValues(config *Config, backendConfig *BackendConfig) (string, error) {
	// Get domain or use IP if not set
	domain := config.DomainName
	if domain == "" {
		ip, err := getNodeIP()
		if err != nil {
			return "", err
		}
		domain = fmt.Sprintf("%s.nip.io", ip)
	}

	// Log the values being used for debugging
	logMessage("INFO", fmt.Sprintf("Using PostgreSQL credentials - Username: %s, Database: %s",
		backendConfig.PostgresUsername, backendConfig.PostgresDatabase))

	// Create the values template
	valuesTemplate := `
defaultImage: ghcr.io/shapeblock/backend
defaultImageTag: v1.0.6-dec-03.1
defaultImagePullPolicy: Always

deployments:
  shapeblock-backend:
    initContainers:
    - name: migrate
      command: ['python', 'manage.py', 'migrate']
      envConfigmaps:
      - envs
      envSecrets:
      - secret-envs
      resources:
        limits:
          cpu: "500m"
          memory: "512Mi"
        requests:
          cpu: 5m
          memory: 128M

    containers:
    - envConfigmaps:
      - envs
      envSecrets:
      - secret-envs
      name: shapeblock-backend
      command: ['uvicorn', '--host', '0.0.0.0', '--port', '8000', '--workers', '1', 'shapeblock.asgi:application']
      ports:
      - containerPort: 8000
        name: app
      resources:
        limits:
          cpu: "1"
          memory: 2Gi
        requests:
          cpu: 5m
          memory: 128M
    podLabels:
      app: shapeblock
      release: backend
    replicas: 1

  worker:
    containers:
    - envConfigmaps:
      - envs
      envSecrets:
      - secret-envs
      name: worker
      command: ['celery', '-A', 'shapeblock', 'worker', '-l', 'INFO']
      resources:
        limits:
          cpu: "1"
          memory: 2Gi
        requests:
          cpu: 5m
          memory: 128M
    podLabels:
      app: shapeblock
      release: backend
    replicas: 1

envs:
  DEBUG: "False"
  DATABASE_URL: "postgres://%s:%s@db-postgresql/%s"
  POSTGRES_DB: "%s"
  POSTGRES_USER: "%s"
  POSTGRES_PASSWORD: "%s"
  DATABASE_HOST: "db-postgresql"
  REDIS_HOST: "redis-master"
  ADMIN_URL: "admin-sb-4891/"
  SB_TLD: "%s"
  ALLOWED_HOSTS: api.%s
  KUBE_SERVER: https://127.0.0.1:6443
  KUBE_NAMESPACE: shapeblock
  DEFAULT_FROM_EMAIL: %s
  CELERY_BROKER_URL: "redis://redis-master:6379/0"
  CORS_ALLOWED_ORIGINS: "https://console.%s"
  FRONTEND_URL: "https://console.%s"
  CUSTOM_PASSWORD_RESET_DOMAIN: "https://console.%s"
  INVITATIONS_SIGNUP_REDIRECT: "https://console.%s/register"
  DEPLOYMENT_MODE: "single-tenant"

generic:
  labels:
    app: shapeblock
    release: backend
  usePredefinedAffinity: false

releasePrefix: production

secretEnvs:
  SECRET_KEY: "%s"
  KUBE_TOKEN: "%s"
  FERNET_KEYS: "%s"
  LICENSE_KEY: "%s"

services:
  shapeblock-backend:
    extraSelectorLabels:
      app: shapeblock
      release: backend
    ports:
    - port: 8000
    type: ClusterIP

ingresses:
  api.%s:
    annotations:
      nginx.ingress.kubernetes.io/proxy-body-size: 50m
      nginx.ingress.kubernetes.io/ssl-redirect: "true"
      nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
      nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
    certManager:
      originalIssuerName: letsencrypt-prod
      issuerType: cluster-issuer
    hosts:
    - paths:
      - serviceName: shapeblock-backend
        servicePort: 8000
    ingressClassName: nginx
    name: backend
`
	// Format the template with the required values
	values := fmt.Sprintf(valuesTemplate,
		backendConfig.PostgresUsername,
		backendConfig.PostgresPassword,
		backendConfig.PostgresDatabase,
		backendConfig.PostgresDatabase,
		backendConfig.PostgresUsername,
		backendConfig.PostgresPassword,
		domain,
		domain,
		config.AdminEmail,
		domain,
		domain,
		domain,
		domain,
		generateSecretKey(),
		backendConfig.ServiceAccountToken,
		generateFernetKeys(),
		config.LicenseKey,
		domain,
	)

	return values, nil
}

func installBackend(config *Config, backendConfig *BackendConfig) error {
	printStatus("Installing ShapeBlock backend...")

	// Add nixys helm repo
	if err := addHelmRepo("nixys", "https://registry.nixys.ru/chartrepo/public"); err != nil {
		return err
	}

	// Generate values.yaml content
	values, err := generateBackendValues(config, backendConfig)
	if err != nil {
		return fmt.Errorf("failed to generate backend values: %v", err)
	}

	// Log the values file content
	logMessage("INFO", "Backend values.yaml content:")
	logMessage("INFO", values)

	// Write values to temporary file
	tmpfile, err := os.CreateTemp("", "backend-values-*.yaml")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.WriteString(values); err != nil {
		return fmt.Errorf("failed to write values: %v", err)
	}
	tmpfile.Close()

	// Install using helm
	if err := runCommand("helm", "upgrade", "--install",
		"backend", "nixys/universal-chart",
		"--namespace", "shapeblock",
		"--values", tmpfile.Name(),
		"--timeout", "600s"); err != nil {
		return fmt.Errorf("failed to install backend: %v", err)
	}

	return nil
}
