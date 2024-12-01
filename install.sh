#!/usr/bin/env bash
set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Function to print colored output
print_status() {
    echo -e "${GREEN}==>${NC} $1"
}

print_error() {
    echo -e "${RED}Error:${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}Warning:${NC} $1"
}

# Function to check system memory
check_memory() {
    print_status "Checking system memory..."

    # Get total memory in KB and convert to GB
    TOTAL_MEM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    TOTAL_MEM_GB=$((TOTAL_MEM_KB / 1024 / 1024))

    if [ $TOTAL_MEM_GB -lt 4 ]; then
        print_error "Insufficient memory. ShapeBlock requires at least 4GB RAM."
        print_error "Current system memory: ${TOTAL_MEM_GB}GB"
        exit 1
    fi
}

# Install prerequisites
install_prerequisites() {
    print_status "Installing prerequisites..."

    # Install jq if not present
    if ! command -v jq >/dev/null 2>&1; then
        print_status "Installing jq..."
        sudo apt-get update && sudo apt-get install -y jq || {
            sudo yum install -y jq || {
                print_error "Failed to install jq. Please install it manually."
                exit 1
            }
        }
    fi

    # Install kubectl if not present
    if ! command -v kubectl >/dev/null 2>&1; then
        print_status "Installing kubectl..."
        curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
        chmod +x kubectl
        sudo mv kubectl /usr/local/bin/
    fi

    # Install helm if not present
    if ! command -v helm >/dev/null 2>&1; then
        print_status "Installing helm..."
        curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
    fi

    # Install k3sup if not present
    if ! command -v k3sup >/dev/null 2>&1; then
        print_status "Installing k3sup..."
        curl -sLS https://get.k3sup.dev | sh
        sudo install k3sup /usr/local/bin/
    fi
}

# Check if required tools are installed
check_dependencies() {
    print_status "Checking dependencies..."

    local REQUIRED_TOOLS="curl kubectl helm k3sup jq"
    local MISSING_TOOLS=()

    for tool in $REQUIRED_TOOLS; do
        if ! command -v $tool >/dev/null 2>&1; then
            MISSING_TOOLS+=($tool)
        fi
    done

    if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
        print_error "Missing required tools: ${MISSING_TOOLS[*]}"
        print_status "Please install the missing tools and try again"
        exit 1
    fi
}

# Collect user input
collect_input() {
    print_status "Please provide the following information:"

    # License key
    while [ -z "$LICENSE_KEY" ]; do
        read -p "License key: " LICENSE_KEY
    done

    # Admin username
    while [ -z "$ADMIN_USERNAME" ]; do
        read -p "Admin username: " ADMIN_USERNAME
    done

    # Admin email
    while [ -z "$ADMIN_EMAIL" ]; do
        read -p "Admin email: " ADMIN_EMAIL
        if [[ ! "$ADMIN_EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
            print_error "Invalid email format"
            ADMIN_EMAIL=""
        fi
    done

    # Admin password
    while [ -z "$ADMIN_PASSWORD" ]; do
        read -s -p "Admin password: " ADMIN_PASSWORD
        echo
        read -s -p "Confirm password: " ADMIN_PASSWORD_CONFIRM
        echo
        if [ "$ADMIN_PASSWORD" != "$ADMIN_PASSWORD_CONFIRM" ]; then
            print_error "Passwords do not match"
            ADMIN_PASSWORD=""
        fi
    done

    # Optional domain name
    read -p "Domain name (optional): " DOMAIN_NAME

    # Optional email settings
    read -p "Configure email settings? (y/N): " CONFIGURE_EMAIL
    if [[ $CONFIGURE_EMAIL =~ ^[Yy]$ ]]; then
        read -p "SMTP host: " SMTP_HOST
        read -p "SMTP port: " SMTP_PORT
        read -p "SMTP username: " SMTP_USERNAME
        read -s -p "SMTP password: " SMTP_PASSWORD
        echo
    fi
}

# Install K3s using k3sup
install_k3s() {
    print_status "Installing K3s..."

    k3sup install --local --k3s-extra-args '--disable traefik' || {
        print_error "Failed to install K3s"
        exit 1
    }

    # Set KUBECONFIG
    export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
    chmod 644 $KUBECONFIG
}

# Install required Helm charts
install_helm_charts() {
    print_status "Installing Helm charts..."

    # Add required Helm repositories
    helm repo add bitnami https://charts.bitnami.com/bitnami
    helm repo update

    # Install nginx-ingress
    print_status "Installing nginx-ingress..."
    helm install nginx-ingress bitnami/nginx-ingress-controller \
        --version 11.3.18 \
        --timeout 600s || {
        print_error "Failed to install nginx-ingress"
        exit 1
    }

    # Install cert-manager
    print_status "Installing cert-manager..."
    helm install cert-manager bitnami/cert-manager \
        --version 1.3.16 \
        --namespace cert-manager \
        --create-namespace \
        --set installCRDs=true \
        --timeout 600s || {
        print_error "Failed to install cert-manager"
        exit 1
    }

    # Install Epinio
    print_status "Installing Epinio..."
    helm repo add epinio https://epinio.github.io/helm-charts
    helm install epinio epinio/epinio \
        --namespace epinio \
        --create-namespace \
        --set global.domain=$DOMAIN_NAME || {
        print_error "Failed to install Epinio"
        exit 1
    }
}

# Install ShapeBlock
install_shapeblock() {
    print_status "Installing ShapeBlock..."

    # Create values file for ShapeBlock
    cat > sb-values.yaml <<EOF
mode: single-tenant
license:
  key: $LICENSE_KEY

admin:
  username: $ADMIN_USERNAME
  email: $ADMIN_EMAIL
  password: $ADMIN_PASSWORD

domain: $DOMAIN_NAME

email:
  enabled: ${CONFIGURE_EMAIL:-false}
  host: $SMTP_HOST
  port: $SMTP_PORT
  username: $SMTP_USERNAME
  password: $SMTP_PASSWORD
EOF

    # Install ShapeBlock using Helm
    helm repo add shapeblock https://charts.shapeblock.com
    helm install shapeblock shapeblock/shapeblock \
        -f sb-values.yaml \
        --namespace shapeblock \
        --create-namespace || {
        print_error "Failed to install ShapeBlock"
        exit 1
    }
}

# Verify installation
verify_installation() {
    print_status "Verifying installation..."

    # Wait for all pods to be ready
    kubectl wait --for=condition=ready pod \
        --all \
        --namespace shapeblock \
        --timeout=300s || {
        print_error "Not all pods are ready"
        exit 1
    }

    # Get the ShapeBlock URL
    if [ -n "$DOMAIN_NAME" ]; then
        SB_URL="https://app.$DOMAIN_NAME"
    else
        INGRESS_IP=$(kubectl get svc nginx-ingress-controller -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
        SB_URL="http://$INGRESS_IP"
    fi

    print_status "ShapeBlock has been successfully installed!"
    echo "You can access the dashboard at: $SB_URL"
    echo "Username: $ADMIN_USERNAME"
    echo "Password: [your chosen password]"
}

activate_license() {
    print_status "Activating license..."

    # Generate fingerprint from email using sha256sum
    FINGERPRINT=$(echo -n "$ADMIN_EMAIL" | sha256sum | awk '{print $1}')

    # Get license ID
    print_status "Validating license key..."
    LICENSE_RESPONSE=$(curl -s -X GET \
        "https://api.keygen.sh/v1/accounts/53666519-ebe7-4ca2-9c1a-d026831e4b56/me" \
        -H "Accept: application/vnd.api+json" \
        -H "Authorization: License $LICENSE_KEY")

    # Check if the response contains data and extract license ID using jq
    LICENSE_ID=$(echo "$LICENSE_RESPONSE" | jq -r '.data.id')
    if [ "$LICENSE_ID" = "null" ] || [ -z "$LICENSE_ID" ]; then
        print_error "Invalid license key"
        exit 1
    fi

    # Prepare JSON payload for activation
    ACTIVATION_PAYLOAD=$(jq -n \
        --arg fingerprint "$FINGERPRINT" \
        --arg license_id "$LICENSE_ID" \
        '{
            data: {
                type: "machines",
                attributes: {
                    fingerprint: $fingerprint
                },
                relationships: {
                    license: {
                        data: {
                            type: "licenses",
                            id: $license_id
                        }
                    }
                }
            }
        }')

    # Activate license
    print_status "Activating license..."
    ACTIVATION_RESPONSE=$(curl -s -X POST \
        "https://api.keygen.sh/v1/accounts/53666519-ebe7-4ca2-9c1a-d026831e4b56/machines" \
        -H "Content-Type: application/vnd.api+json" \
        -H "Accept: application/vnd.api+json" \
        -H "Authorization: License $LICENSE_KEY" \
        -d "$ACTIVATION_PAYLOAD")

    # Check if activation was successful using jq
    if ! echo "$ACTIVATION_RESPONSE" | jq -e '.data' >/dev/null 2>&1; then
        print_error "License activation failed"
        print_error "Response: $(echo "$ACTIVATION_RESPONSE" | jq -r '.errors[0].detail // "Unknown error"')"
        exit 1
    fi

    print_status "License activated successfully"
}
# Main installation process
main() {
    print_status "Starting ShapeBlock installation..."

    check_memory
    install_prerequisites
    check_dependencies
    collect_input
    activate_license
    install_k3s
    install_helm_charts
    install_shapeblock
    verify_installation
}

main "$@"
