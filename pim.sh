#!/bin/bash
#
# pim.sh - Azure PIM (Privileged Identity Management) CLI Tool
# Manage eligible role assignments and group memberships from the command line
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Configuration
DEFAULT_DURATION_HOURS=1
MAX_DURATION_HOURS=8
CONFIG_DIR="$HOME/.config/pim"
APP_CONFIG_FILE="$CONFIG_DIR/app.json"
TOKEN_CACHE_FILE="$CONFIG_DIR/token.json"
APP_NAME="PIM CLI Tool"

# Required Graph API permissions for PIM groups and directory roles
GRAPH_PERMISSIONS=(
    "User.Read"
    "Group.Read.All"
    "PrivilegedAccess.ReadWrite.AzureADGroup"
    "PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup"
    "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup"
    "RoleManagement.ReadWrite.Directory"
    "RoleEligibilitySchedule.ReadWrite.Directory"
    "RoleAssignmentSchedule.ReadWrite.Directory"
)

# Global variables for caching
ELIGIBLE_ASSIGNMENTS=""
ELIGIBLE_GROUPS=""
CURRENT_USER_ID=""
GRAPH_USER_ID=""
USER_GROUP_IDS=""
GRAPH_TOKEN=""

#------------------------------------------------------------------------------
# Utility Functions
#------------------------------------------------------------------------------

print_error() {
    echo -e "${RED}Error: $1${NC}" >&2
}

print_success() {
    echo -e "${GREEN}$1${NC}"
}

print_info() {
    echo -e "${BLUE}$1${NC}" >&2
}

print_warning() {
    echo -e "${YELLOW}$1${NC}"
}

print_header() {
    echo -e "\n${BOLD}${CYAN}$1${NC}"
    echo -e "${CYAN}$(printf '=%.0s' $(seq 1 ${#1}))${NC}"
}

check_dependencies() {
    if ! command -v jq &> /dev/null; then
        print_error "jq is not installed or not in PATH"
        echo "Please install it: sudo apt-get install jq (Debian/Ubuntu) or brew install jq (macOS)"
        exit 1
    fi

    if ! command -v gum &> /dev/null; then
        print_error "gum is not installed or not in PATH"
        echo "Please install it: https://github.com/charmbracelet/gum#installation"
        exit 1
    fi
}

# Check if Azure CLI is available (only needed for role commands)
check_az() {
    if ! command -v az &> /dev/null; then
        print_error "Azure CLI (az) is not installed or not in PATH"
        echo "Please install it from: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
        exit 1
    fi
}

check_login() {
    if ! az account show &> /dev/null; then
        print_error "Not logged in to Azure CLI"
        echo "Please run: az login"
        exit 1
    fi
}

ensure_config_dir() {
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
}

get_current_user_id() {
    if [[ -z "$CURRENT_USER_ID" ]]; then
        CURRENT_USER_ID=$(az ad signed-in-user show --query id -o tsv 2>/dev/null) || {
            print_error "Failed to get current user ID"
            exit 1
        }
    fi
    echo "$CURRENT_USER_ID"
}

get_tenant_id() {
    az account show --query tenantId -o tsv
}

get_user_group_ids() {
    if [[ -z "$USER_GROUP_IDS" ]]; then
        USER_GROUP_IDS=$(az ad user get-member-groups --id "$(get_current_user_id)" --security-enabled-only \
            2>/dev/null | jq -r '.[].id' | tr '\n' ' ') || {
            print_error "Failed to get user group memberships"
            exit 1
        }
    fi
    echo "$USER_GROUP_IDS"
}

get_subscription_id() {
    az account show --query id -o tsv
}

#------------------------------------------------------------------------------
# App Registration Functions
#------------------------------------------------------------------------------

get_app_config() {
    if [[ -f "$APP_CONFIG_FILE" ]]; then
        cat "$APP_CONFIG_FILE"
    else
        echo ""
    fi
}

save_app_config() {
    local app_id="$1"
    local tenant_id="$2"

    ensure_config_dir
    cat > "$APP_CONFIG_FILE" << EOF
{
    "appId": "$app_id",
    "tenantId": "$tenant_id"
}
EOF
    chmod 600 "$APP_CONFIG_FILE"
}

setup_app_registration() {
    print_header "PIM CLI App Registration Setup"

    check_login

    local tenant_id
    tenant_id=$(get_tenant_id)

    # Check if app already exists
    local existing_app
    existing_app=$(az ad app list --display-name "$APP_NAME" --query '[0].appId' -o tsv 2>/dev/null || echo "")

    if [[ -n "$existing_app" ]]; then
        print_warning "App registration '$APP_NAME' already exists (App ID: $existing_app)"
        read -rp "Do you want to use the existing app? (y/n): " use_existing
        if [[ "$use_existing" == "y" ]] || [[ "$use_existing" == "Y" ]]; then
            save_app_config "$existing_app" "$tenant_id"
            print_success "✓ Configuration saved!"
            echo ""
            echo "Next step: An admin needs to grant consent for the app permissions."
            echo "Run: ${BOLD}pim.sh grant-consent${NC}"
            return 0
        fi
        print_info "Creating a new app registration..."
    fi

    print_info "Creating app registration '$APP_NAME'..."

    # Create the app registration with public client (for device code flow)
    local app_result
    app_result=$(az ad app create \
        --display-name "$APP_NAME" \
        --public-client-redirect-uris "https://login.microsoftonline.com/common/oauth2/nativeclient" \
        --is-fallback-public-client true \
        --sign-in-audience "AzureADMyOrg" \
        2>&1) || {
        print_error "Failed to create app registration: $app_result"
        return 1
    }

    local app_id
    app_id=$(echo "$app_result" | jq -r '.appId')

    print_success "✓ App registration created (App ID: $app_id)"

    # Get Microsoft Graph service principal ID
    local graph_sp_id
    graph_sp_id=$(az ad sp list --filter "appId eq '00000003-0000-0000-c000-000000000000'" --query '[0].id' -o tsv 2>/dev/null)

    # Get the permission IDs for the required scopes
    print_info "Adding API permissions..."

    local graph_permissions_json='[]'
    for perm in "${GRAPH_PERMISSIONS[@]}"; do
        local perm_id
        perm_id=$(az ad sp show --id "00000003-0000-0000-c000-000000000000" \
            --query "oauth2PermissionScopes[?value=='$perm'].id" -o tsv 2>/dev/null || echo "")

        if [[ -n "$perm_id" ]]; then
            graph_permissions_json=$(echo "$graph_permissions_json" | jq ". + [{\"id\": \"$perm_id\", \"type\": \"Scope\"}]")
            print_info "  Added: $perm"
        else
            print_warning "  Permission not found: $perm"
        fi
    done

    # Add User.Read permission (always needed)
    local user_read_id
    user_read_id=$(az ad sp show --id "00000003-0000-0000-c000-000000000000" \
        --query "oauth2PermissionScopes[?value=='User.Read'].id" -o tsv 2>/dev/null)
    graph_permissions_json=$(echo "$graph_permissions_json" | jq ". + [{\"id\": \"$user_read_id\", \"type\": \"Scope\"}]")

    # Update the app with required permissions
    local required_access="[{\"resourceAppId\": \"00000003-0000-0000-c000-000000000000\", \"resourceAccess\": $graph_permissions_json}]"

    az ad app update --id "$app_id" --required-resource-accesses "$required_access" 2>/dev/null || {
        print_warning "Could not add permissions automatically. Please add them manually in Azure Portal."
    }

    # Create service principal for the app
    print_info "Creating service principal..."
    az ad sp create --id "$app_id" 2>/dev/null || true

    # Save configuration
    save_app_config "$app_id" "$tenant_id"

    print_success "✓ App registration setup complete!"
    echo ""
    echo "App ID: ${BOLD}$app_id${NC}"
    echo "Tenant ID: ${BOLD}$tenant_id${NC}"
    echo ""
    print_warning "IMPORTANT: An admin must grant consent for the API permissions."
    echo ""
    echo "Option 1: Run as admin: ${BOLD}pim.sh grant-consent${NC}"
    echo "Option 2: Go to Azure Portal → App registrations → $APP_NAME → API permissions → Grant admin consent"
    echo ""
    echo "After consent is granted, run: ${BOLD}pim.sh login${NC}"
}

grant_admin_consent() {
    print_header "Grant Admin Consent"

    local config
    config=$(get_app_config)

    if [[ -z "$config" ]]; then
        print_error "App not configured. Run 'pim.sh setup' first."
        return 1
    fi

    local app_id
    app_id=$(echo "$config" | jq -r '.appId')

    print_info "Granting admin consent for app: $app_id"
    print_warning "This requires Global Administrator or Privileged Role Administrator permissions."
    echo ""

    # Get the service principal
    local sp_id
    sp_id=$(az ad sp list --filter "appId eq '$app_id'" --query '[0].id' -o tsv 2>/dev/null)

    if [[ -z "$sp_id" ]]; then
        print_error "Service principal not found. Creating..."
        az ad sp create --id "$app_id" 2>/dev/null
        sp_id=$(az ad sp list --filter "appId eq '$app_id'" --query '[0].id' -o tsv 2>/dev/null)
    fi

    # Grant consent using az cli
    local graph_sp_id
    graph_sp_id=$(az ad sp list --filter "appId eq '00000003-0000-0000-c000-000000000000'" --query '[0].id' -o tsv 2>/dev/null)

    # Build the scopes string
    local scopes="User.Read"
    for perm in "${GRAPH_PERMISSIONS[@]}"; do
        scopes="$scopes $perm"
    done

    # Create OAuth2 permission grant
    local grant_result
    grant_result=$(az rest \
        --method POST \
        --url "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" \
        --headers "Content-Type=application/json" \
        --body "{
            \"clientId\": \"$sp_id\",
            \"consentType\": \"AllPrincipals\",
            \"resourceId\": \"$graph_sp_id\",
            \"scope\": \"$scopes\"
        }" 2>&1) || {
        if echo "$grant_result" | grep -q "Permission entry already exists"; then
            print_success "✓ Admin consent already granted!"
        else
            print_error "Failed to grant consent: $grant_result"
            echo ""
            echo "Please grant consent manually in Azure Portal:"
            echo "1. Go to Azure Portal → Azure Active Directory → App registrations"
            echo "2. Find '$APP_NAME'"
            echo "3. Go to API permissions"
            echo "4. Click 'Grant admin consent'"
            return 1
        fi
    }

    if [[ -n "$grant_result" ]] && ! echo "$grant_result" | grep -q "error"; then
        print_success "✓ Admin consent granted successfully!"
    fi

    echo ""
    echo "You can now run: ${BOLD}pim.sh login${NC}"
}

#------------------------------------------------------------------------------
# Token Management
#------------------------------------------------------------------------------

get_cached_token() {
    if [[ -f "$TOKEN_CACHE_FILE" ]]; then
        local token_data
        token_data=$(cat "$TOKEN_CACHE_FILE")

        local expires_on
        expires_on=$(echo "$token_data" | jq -r '.expires_on // 0')
        local now
        now=$(date +%s)

        # Check if token is still valid (with 5 min buffer)
        if [[ "$expires_on" -gt $((now + 300)) ]]; then
            echo "$token_data" | jq -r '.access_token'
            return 0
        fi
    fi
    return 1
}

save_token() {
    local access_token="$1"
    local expires_in="$2"
    local refresh_token="${3:-}"

    ensure_config_dir
    local expires_on
    expires_on=$(($(date +%s) + expires_in))

    # Save access token and expiry to file (short-lived, ok in file)
    cat > "$TOKEN_CACHE_FILE" << EOF
{
    "access_token": "$access_token",
    "expires_on": $expires_on
}
EOF
    chmod 600 "$TOKEN_CACHE_FILE"

    # Save refresh token securely using secret-tool if available
    if [[ -n "$refresh_token" ]] && command -v secret-tool &> /dev/null; then
        echo -n "$refresh_token" | secret-tool store --label="PIM CLI Refresh Token" \
            application pim \
            type refresh_token \
            2>/dev/null || true
    fi
}

# Get refresh token from secure storage
get_refresh_token() {
    if command -v secret-tool &> /dev/null; then
        secret-tool lookup application pim type refresh_token 2>/dev/null || echo ""
    else
        echo ""
    fi
}

# Refresh the access token using the refresh token
refresh_access_token() {
    local config
    config=$(get_app_config)

    if [[ -z "$config" ]]; then
        return 1
    fi

    local refresh_token
    refresh_token=$(get_refresh_token)

    if [[ -z "$refresh_token" ]]; then
        return 1
    fi

    local app_id
    local tenant_id
    app_id=$(echo "$config" | jq -r '.appId')
    tenant_id=$(echo "$config" | jq -r '.tenantId')

    # Build scope string
    local scopes="https://graph.microsoft.com/User.Read"
    for perm in "${GRAPH_PERMISSIONS[@]}"; do
        scopes="$scopes https://graph.microsoft.com/$perm"
    done
    scopes="$scopes offline_access"

    local token_response
    token_response=$(curl -s -X POST \
        "https://login.microsoftonline.com/$tenant_id/oauth2/v2.0/token" \
        -d "client_id=$app_id" \
        -d "grant_type=refresh_token" \
        -d "refresh_token=$refresh_token" \
        -d "scope=$scopes")

    local access_token
    access_token=$(echo "$token_response" | jq -r '.access_token // empty')

    if [[ -n "$access_token" ]]; then
        local expires_in
        local new_refresh_token
        expires_in=$(echo "$token_response" | jq -r '.expires_in // 3600')
        new_refresh_token=$(echo "$token_response" | jq -r '.refresh_token // empty')

        # Use new refresh token if provided, otherwise keep the old one
        if [[ -z "$new_refresh_token" ]]; then
            new_refresh_token="$refresh_token"
        fi

        save_token "$access_token" "$expires_in" "$new_refresh_token"
        return 0
    fi

    return 1
}

do_device_code_login() {
    print_header "Login with PIM Permissions"

    local config
    config=$(get_app_config)

    if [[ -z "$config" ]]; then
        print_error "App not configured. Run 'pim.sh setup' first."
        return 1
    fi

    local app_id
    local tenant_id
    app_id=$(echo "$config" | jq -r '.appId')
    tenant_id=$(echo "$config" | jq -r '.tenantId')

    # Build scope string
    local scopes="https://graph.microsoft.com/User.Read"
    for perm in "${GRAPH_PERMISSIONS[@]}"; do
        scopes="$scopes https://graph.microsoft.com/$perm"
    done
    scopes="$scopes offline_access"

    print_info "Starting device code flow..."

    # Request device code
    local device_code_response
    device_code_response=$(curl -s -X POST \
        "https://login.microsoftonline.com/$tenant_id/oauth2/v2.0/devicecode" \
        -d "client_id=$app_id" \
        -d "scope=$scopes")

    local user_code
    local device_code
    local verification_uri
    local message

    user_code=$(echo "$device_code_response" | jq -r '.user_code // empty')
    device_code=$(echo "$device_code_response" | jq -r '.device_code // empty')
    verification_uri=$(echo "$device_code_response" | jq -r '.verification_uri // empty')
    message=$(echo "$device_code_response" | jq -r '.message // empty')

    if [[ -z "$device_code" ]]; then
        local error
        error=$(echo "$device_code_response" | jq -r '.error_description // .error // "Unknown error"')
        print_error "Failed to get device code: $error"
        return 1
    fi

    echo ""
    echo "$message"
    echo ""
    echo -e "Code: ${BOLD}${GREEN}$user_code${NC}"
    echo ""

    # Poll for token
    local interval
    interval=$(echo "$device_code_response" | jq -r '.interval // 5')

    print_info "Waiting for authentication..."

    while true; do
        sleep "$interval"

        local token_response
        token_response=$(curl -s -X POST \
            "https://login.microsoftonline.com/$tenant_id/oauth2/v2.0/token" \
            -d "client_id=$app_id" \
            -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
            -d "device_code=$device_code")

        local access_token
        access_token=$(echo "$token_response" | jq -r '.access_token // empty')

        if [[ -n "$access_token" ]]; then
            local expires_in
            local refresh_token
            expires_in=$(echo "$token_response" | jq -r '.expires_in // 3600')
            refresh_token=$(echo "$token_response" | jq -r '.refresh_token // empty')
            save_token "$access_token" "$expires_in" "$refresh_token"
            print_success "✓ Logged in successfully!"
            if [[ -n "$refresh_token" ]]; then
                print_info "Refresh token saved - future logins will be automatic."
            fi
            return 0
        fi

        local error
        error=$(echo "$token_response" | jq -r '.error // empty')

        case "$error" in
            "authorization_pending")
                # Still waiting, continue polling
                ;;
            "slow_down")
                interval=$((interval + 5))
                ;;
            "expired_token")
                print_error "Device code expired. Please try again."
                return 1
                ;;
            "access_denied")
                print_error "Access denied by user."
                return 1
                ;;
            *)
                local error_desc
                error_desc=$(echo "$token_response" | jq -r '.error_description // "Unknown error"')
                print_error "Authentication failed: $error_desc"
                return 1
                ;;
        esac
    done
}

get_graph_token() {
    if [[ -n "$GRAPH_TOKEN" ]]; then
        echo "$GRAPH_TOKEN"
        return 0
    fi

    # Try to get cached token
    GRAPH_TOKEN=$(get_cached_token 2>/dev/null) || {
        # Token expired or missing, try to refresh
        if refresh_access_token; then
            GRAPH_TOKEN=$(get_cached_token) || {
                print_error "Not logged in. Please run 'pim.sh login' first."
                return 1
            }
        else
            print_error "Not logged in. Please run 'pim.sh login' first."
            return 1
        fi
    }

    echo "$GRAPH_TOKEN"
}

# Make a Graph API request using the custom app token
graph_request() {
    local method="$1"
    local url="$2"
    local body="${3:-}"

    local token
    token=$(get_graph_token) || return 1

    local curl_args=(
        -s
        -X "$method"
        -H "Authorization: Bearer $token"
        -H "Content-Type: application/json"
    )

    if [[ -n "$body" ]]; then
        curl_args+=(-d "$body")
    fi

    curl "${curl_args[@]}" "$url"
}

# Get current user ID using Graph API (for group operations)
get_graph_user_id() {
    if [[ -n "$GRAPH_USER_ID" ]]; then
        echo "$GRAPH_USER_ID"
        return 0
    fi

    local result
    result=$(graph_request GET "https://graph.microsoft.com/v1.0/me?\$select=id") || {
        print_error "Failed to get user ID from Graph API"
        return 1
    }

    GRAPH_USER_ID=$(echo "$result" | jq -r '.id // empty')

    if [[ -z "$GRAPH_USER_ID" ]]; then
        local error_msg
        error_msg=$(echo "$result" | jq -r '.error.message // "Unknown error"')
        print_error "Failed to get user ID: $error_msg"
        return 1
    fi

    echo "$GRAPH_USER_ID"
}

#------------------------------------------------------------------------------
# PIM Role Functions (Azure Resources)
#------------------------------------------------------------------------------

get_all_eligible_assignments() {
    local subscription_id
    subscription_id=$(get_subscription_id)

    az rest \
        --method GET \
        --url "https://management.azure.com/subscriptions/$subscription_id/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01" \
        2>/dev/null
}

get_directory_eligible_assignments() {
    local user_id
    user_id=$(get_graph_user_id) || return 1

    local url="https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?\$filter=principalId%20eq%20%27${user_id}%27&\$expand=roleDefinition"

    graph_request GET "$url"
}

get_user_eligible_assignments() {
    local user_id
    local group_ids
    user_id=$(get_current_user_id)
    group_ids=$(get_user_group_ids)

    print_info "Fetching eligible role assignments..."

    local all_assignments
    all_assignments=$(get_all_eligible_assignments) || {
        print_error "Failed to fetch eligible assignments"
        return 1
    }

    local principal_ids="$user_id $group_ids"

    local jq_filter='[.value[] | select('
    local first=true
    for pid in $principal_ids; do
        if [[ -n "$pid" ]]; then
            if [[ "$first" == "true" ]]; then
                jq_filter+=".properties.principalId == \"$pid\""
                first=false
            else
                jq_filter+=" or .properties.principalId == \"$pid\""
            fi
        fi
    done
    jq_filter+=')]'

    echo "$all_assignments" | jq "$jq_filter"
}

get_active_assignments() {
    local subscription_id
    subscription_id=$(get_subscription_id)

    local user_id
    local group_ids
    user_id=$(get_current_user_id)
    group_ids=$(get_user_group_ids)

    local all_active
    all_active=$(az rest \
        --method GET \
        --url "https://management.azure.com/subscriptions/$subscription_id/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=2020-10-01" \
        2>/dev/null) || {
        print_error "Failed to fetch active assignments"
        return 1
    }

    local principal_ids="$user_id $group_ids"

    local jq_filter='[.value[] | select((.properties.assignmentType == "Activated") and ('
    local first=true
    for pid in $principal_ids; do
        if [[ -n "$pid" ]]; then
            if [[ "$first" == "true" ]]; then
                jq_filter+=".properties.principalId == \"$pid\""
                first=false
            else
                jq_filter+=" or .properties.principalId == \"$pid\""
            fi
        fi
    done
    jq_filter+='))]'

    echo "$all_active" | jq "$jq_filter"
}

list_eligible_roles() {
    gum style --bold --foreground 212 "Eligible Role Assignments"
    echo ""

    check_az
    check_login

    local user_id group_ids subscription_id
    user_id=$(get_current_user_id)
    group_ids=$(get_user_group_ids)
    subscription_id=$(get_subscription_id)

    # Fetch subscription-level assignments
    local url="https://management.azure.com/subscriptions/$subscription_id/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01"

    local all_assignments
    all_assignments=$(gum spin --spinner dot --title "Fetching subscription-level eligible roles..." -- \
        az rest --method GET --url "$url" 2>/dev/null) || {
        gum style --foreground 196 "Failed to fetch subscription-level eligible assignments"
        return 1
    }

    # Filter to user's assignments
    local principal_ids="$user_id $group_ids"
    local jq_filter='[.value[] | select('
    local first=true
    for pid in $principal_ids; do
        if [[ -n "$pid" ]]; then
            if [[ "$first" == "true" ]]; then
                jq_filter+=".properties.principalId == \"$pid\""
                first=false
            else
                jq_filter+=" or .properties.principalId == \"$pid\""
            fi
        fi
    done
    jq_filter+=')]'

    local assignments
    assignments=$(echo "$all_assignments" | jq "$jq_filter")

    local sub_count
    sub_count=$(echo "$assignments" | jq 'length')

    # Fetch directory-level assignments
    local dir_assignments dir_count=0
    local graph_token graph_user_id
    graph_token=$(get_graph_token 2>/dev/null) || graph_token=""

    if [[ -n "$graph_token" ]]; then
        graph_user_id=$(get_graph_user_id 2>/dev/null) || graph_user_id=""

        if [[ -n "$graph_user_id" ]]; then
            local dir_url="https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?\$filter=principalId%20eq%20%27${graph_user_id}%27&\$expand=roleDefinition"

            dir_assignments=$(gum spin --spinner dot --title "Fetching directory-level eligible roles..." -- \
                curl -s -X GET -H "Authorization: Bearer $graph_token" -H "Content-Type: application/json" "$dir_url") || dir_assignments=""
        fi
    fi

    if [[ -n "$dir_assignments" ]] && ! echo "$dir_assignments" | jq -e '.error' &>/dev/null; then
        dir_count=$(echo "$dir_assignments" | jq '.value | length // 0')
    fi

    local total_count=$((sub_count + dir_count))

    if [[ "$total_count" -eq 0 ]]; then
        gum style --foreground 214 "No eligible role assignments found for your account."
        return 0
    fi

    gum style --foreground 252 "Found $total_count eligible role(s):"
    echo ""

    # Display subscription-level roles
    if [[ "$sub_count" -gt 0 ]]; then
        gum style --foreground 252 --italic "  Azure Resources ($sub_count):"
        while IFS= read -r assignment; do
            local role_name scope_name

            role_name=$(echo "$assignment" | jq -r '.properties.expandedProperties.roleDefinition.displayName // "Unknown Role"')
            scope_name=$(echo "$assignment" | jq -r '.properties.expandedProperties.scope.displayName // "Unknown"')

            gum style --foreground 35 "    • $role_name @ $scope_name"
        done < <(echo "$assignments" | jq -c '.[]')
    fi

    # Display directory-level roles
    if [[ "$dir_count" -gt 0 ]]; then
        echo ""
        gum style --foreground 252 --italic "  Entra ID Directory Roles ($dir_count):"
        while IFS= read -r assignment; do
            local role_name

            role_name=$(echo "$assignment" | jq -r '.roleDefinition.displayName // "Unknown Role"')

            gum style --foreground 35 "    • $role_name"
        done < <(echo "$dir_assignments" | jq -c '.value[]')
    fi

    ELIGIBLE_ASSIGNMENTS="$assignments"
}

list_active_roles() {
    gum style --bold --foreground 212 "Currently Active Role Assignments"
    echo ""

    check_az
    check_login

    local user_id group_ids subscription_id
    user_id=$(get_current_user_id)
    group_ids=$(get_user_group_ids)
    subscription_id=$(get_subscription_id)

    # Fetch subscription-level active roles
    local url="https://management.azure.com/subscriptions/$subscription_id/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=2020-10-01"

    local all_active
    all_active=$(gum spin --spinner dot --title "Fetching subscription-level active roles..." -- \
        az rest --method GET --url "$url" 2>/dev/null) || {
        gum style --foreground 196 "Failed to fetch active assignments"
        return 1
    }

    # Filter to user's activated assignments
    local principal_ids="$user_id $group_ids"
    local jq_filter='[.value[] | select((.properties.assignmentType == "Activated") and ('
    local first=true
    for pid in $principal_ids; do
        if [[ -n "$pid" ]]; then
            if [[ "$first" == "true" ]]; then
                jq_filter+=".properties.principalId == \"$pid\""
                first=false
            else
                jq_filter+=" or .properties.principalId == \"$pid\""
            fi
        fi
    done
    jq_filter+='))]'

    local assignments
    assignments=$(echo "$all_active" | jq "$jq_filter")

    local sub_count
    sub_count=$(echo "$assignments" | jq 'length')

    # Fetch directory-level active roles
    local dir_active dir_count=0
    local graph_token graph_user_id
    graph_token=$(get_graph_token 2>/dev/null) || graph_token=""

    if [[ -n "$graph_token" ]]; then
        graph_user_id=$(get_graph_user_id 2>/dev/null) || graph_user_id=""

        if [[ -n "$graph_user_id" ]]; then
            local dir_url="https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?\$filter=principalId%20eq%20%27${graph_user_id}%27%20and%20assignmentType%20eq%20%27Activated%27&\$expand=roleDefinition"

            dir_active=$(gum spin --spinner dot --title "Fetching directory-level active roles..." -- \
                curl -s -X GET -H "Authorization: Bearer $graph_token" -H "Content-Type: application/json" "$dir_url") || dir_active=""
        fi
    fi

    if [[ -n "$dir_active" ]] && ! echo "$dir_active" | jq -e '.error' &>/dev/null; then
        dir_count=$(echo "$dir_active" | jq '.value | length // 0')
    fi

    local total_count=$((sub_count + dir_count))

    if [[ "$total_count" -eq 0 ]]; then
        gum style --foreground 214 "No currently active PIM role assignments."
        return 0
    fi

    gum style --foreground 252 "Found $total_count active role(s):"
    echo ""

    # Display subscription-level roles
    if [[ "$sub_count" -gt 0 ]]; then
        gum style --foreground 252 --italic "  Azure Resources ($sub_count):"
        while IFS= read -r assignment; do
            local role_name scope_name end_time

            role_name=$(echo "$assignment" | jq -r '.properties.expandedProperties.roleDefinition.displayName // "Unknown Role"')
            scope_name=$(echo "$assignment" | jq -r '.properties.expandedProperties.scope.displayName // "Unknown"')
            end_time=$(echo "$assignment" | jq -r '.properties.endDateTime // "Permanent"')

            gum style --foreground 35 "    ● $role_name @ $scope_name"
            gum style --foreground 245 "      Expires: $end_time"
        done < <(echo "$assignments" | jq -c '.[]')
    fi

    # Display directory-level roles
    if [[ "$dir_count" -gt 0 ]]; then
        echo ""
        gum style --foreground 252 --italic "  Entra ID Directory Roles ($dir_count):"
        while IFS= read -r assignment; do
            local role_name end_time

            role_name=$(echo "$assignment" | jq -r '.roleDefinition.displayName // "Unknown Role"')
            end_time=$(echo "$assignment" | jq -r '.endDateTime // "Permanent"')

            gum style --foreground 35 "    ● $role_name"
            gum style --foreground 245 "      Expires: $end_time"
        done < <(echo "$dir_active" | jq -c '.value[]')
    fi
    echo ""
}

activate_role() {
    local role_index="$1"
    local duration_hours="${2:-$DEFAULT_DURATION_HOURS}"
    local justification="${3:-Activated via PIM CLI tool}"

    if [[ -z "$ELIGIBLE_ASSIGNMENTS" ]]; then
        ELIGIBLE_ASSIGNMENTS=$(get_user_eligible_assignments) || return 1
    fi

    local count
    count=$(echo "$ELIGIBLE_ASSIGNMENTS" | jq 'length')

    if [[ "$role_index" -lt 1 ]] || [[ "$role_index" -gt "$count" ]]; then
        gum style --foreground 196 "Invalid role index. Please choose between 1 and $count"
        return 1
    fi

    local assignment
    assignment=$(echo "$ELIGIBLE_ASSIGNMENTS" | jq -c ".[$((role_index - 1))]")

    local role_def_id scope principal_id role_name schedule_id

    role_def_id=$(echo "$assignment" | jq -r '.properties.roleDefinitionId')
    scope=$(echo "$assignment" | jq -r '.properties.scope')
    principal_id=$(echo "$assignment" | jq -r '.properties.principalId')
    role_name=$(echo "$assignment" | jq -r '.properties.expandedProperties.roleDefinition.displayName // "Unknown Role"')
    schedule_id=$(echo "$assignment" | jq -r '.properties.roleEligibilityScheduleId')

    local request_guid
    request_guid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)

    local request_body
    request_body=$(jq -n \
        --arg principalId "$principal_id" \
        --arg roleDefinitionId "$role_def_id" \
        --arg scheduleId "$schedule_id" \
        --arg justification "$justification" \
        --arg duration "PT${duration_hours}H" \
        '{
            properties: {
                principalId: $principalId,
                roleDefinitionId: $roleDefinitionId,
                requestType: "SelfActivate",
                linkedRoleEligibilityScheduleId: $scheduleId,
                justification: $justification,
                scheduleInfo: {
                    expiration: {
                        type: "AfterDuration",
                        duration: $duration
                    }
                }
            }
        }')

    local api_url="https://management.azure.com${scope}/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/${request_guid}?api-version=2020-10-01"

    local result
    result=$(gum spin --spinner dot --title "Activating $role_name..." -- \
        az rest --method PUT --url "$api_url" --headers "Content-Type=application/json" --body "$request_body" 2>&1) || {
        local error_msg
        error_msg=$(echo "$result" | grep -oP '"message"\s*:\s*"\K[^"]+' | head -1 || echo "$result")
        gum style --foreground 196 "Failed to activate role: $error_msg"
        return 1
    }

    local status
    status=$(echo "$result" | jq -r '.properties.status // "Unknown"')

    if [[ "$status" == "Provisioned" ]] || [[ "$status" == "PendingApproval" ]] || [[ "$status" == "Granted" ]]; then
        gum style --foreground 35 --bold "✓ Role activation request submitted successfully!"
        gum style --foreground 33 "Status: $status"
        if [[ "$status" == "PendingApproval" ]]; then
            gum style --foreground 214 "This role requires approval. Please wait for an approver to approve your request."
        fi
    else
        gum style --foreground 214 "Activation request status: $status"
    fi
}

activate_directory_role() {
    local assignment="$1"
    local duration_hours="${2:-$DEFAULT_DURATION_HOURS}"
    local justification="${3:-Activated via PIM CLI tool}"

    local graph_token
    graph_token=$(get_graph_token) || {
        gum style --foreground 196 "Not logged in. Please run 'pim login' first."
        return 1
    }

    local role_def_id principal_id role_name dir_scope_id
    role_def_id=$(echo "$assignment" | jq -r '.roleDefinition.id // .roleDefinitionId')
    principal_id=$(echo "$assignment" | jq -r '.principalId')
    role_name=$(echo "$assignment" | jq -r '.roleDefinition.displayName // "Unknown Role"')
    dir_scope_id=$(echo "$assignment" | jq -r '.directoryScopeId // "/"')

    local request_body
    request_body=$(jq -n \
        --arg principalId "$principal_id" \
        --arg roleDefinitionId "$role_def_id" \
        --arg directoryScopeId "$dir_scope_id" \
        --arg justification "$justification" \
        --arg duration "PT${duration_hours}H" \
        '{
            action: "selfActivate",
            principalId: $principalId,
            roleDefinitionId: $roleDefinitionId,
            directoryScopeId: $directoryScopeId,
            justification: $justification,
            scheduleInfo: {
                expiration: {
                    type: "AfterDuration",
                    duration: $duration
                }
            }
        }')

    local result
    result=$(gum spin --spinner dot --title "Activating $role_name..." -- \
        curl -s -X POST \
        -H "Authorization: Bearer $graph_token" \
        -H "Content-Type: application/json" \
        -d "$request_body" \
        "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests") || {
        gum style --foreground 196 "Failed to activate directory role"
        return 1
    }

    if echo "$result" | jq -e '.error' &>/dev/null; then
        local error_msg
        error_msg=$(echo "$result" | jq -r '.error.message // "Unknown error"')
        gum style --foreground 196 "Failed to activate role: $error_msg"
        return 1
    fi

    local status
    status=$(echo "$result" | jq -r '.status // "Unknown"')

    if [[ "$status" == "Provisioned" ]] || [[ "$status" == "PendingApproval" ]] || [[ "$status" == "Granted" ]]; then
        gum style --foreground 35 --bold "✓ Role activation request submitted successfully!"
        gum style --foreground 33 "Status: $status"
        if [[ "$status" == "PendingApproval" ]]; then
            gum style --foreground 214 "This role requires approval. Please wait for an approver to approve your request."
        fi
    else
        gum style --foreground 214 "Activation request status: $status"
    fi
}

interactive_activate() {
    gum style --bold --foreground 212 "PIM Role Activation"
    echo ""

    check_az
    check_login

    local user_id group_ids subscription_id
    user_id=$(get_current_user_id)
    group_ids=$(get_user_group_ids)
    subscription_id=$(get_subscription_id)

    # Fetch subscription-level eligible roles
    local url="https://management.azure.com/subscriptions/$subscription_id/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01"

    local all_assignments
    all_assignments=$(gum spin --spinner dot --title "Fetching subscription-level eligible roles..." -- \
        az rest --method GET --url "$url" 2>/dev/null) || {
        gum style --foreground 196 "Failed to fetch eligible assignments"
        return 1
    }

    # Filter to user's assignments
    local principal_ids="$user_id $group_ids"
    local jq_filter='[.value[] | select('
    local first=true
    for pid in $principal_ids; do
        if [[ -n "$pid" ]]; then
            if [[ "$first" == "true" ]]; then
                jq_filter+=".properties.principalId == \"$pid\""
                first=false
            else
                jq_filter+=" or .properties.principalId == \"$pid\""
            fi
        fi
    done
    jq_filter+=')]'

    local assignments
    assignments=$(echo "$all_assignments" | jq "$jq_filter")

    local sub_count
    sub_count=$(echo "$assignments" | jq 'length')

    # Fetch directory-level eligible roles
    local dir_assignments dir_count=0
    local graph_token graph_user_id
    graph_token=$(get_graph_token 2>/dev/null) || graph_token=""

    if [[ -n "$graph_token" ]]; then
        graph_user_id=$(get_graph_user_id 2>/dev/null) || graph_user_id=""

        if [[ -n "$graph_user_id" ]]; then
            local dir_url="https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?\$filter=principalId%20eq%20%27${graph_user_id}%27&\$expand=roleDefinition"

            dir_assignments=$(gum spin --spinner dot --title "Fetching directory-level eligible roles..." -- \
                curl -s -X GET -H "Authorization: Bearer $graph_token" -H "Content-Type: application/json" "$dir_url") || dir_assignments=""
        fi
    fi

    if [[ -n "$dir_assignments" ]] && ! echo "$dir_assignments" | jq -e '.error' &>/dev/null; then
        dir_count=$(echo "$dir_assignments" | jq '.value | length // 0')
    fi

    local total_count=$((sub_count + dir_count))

    if [[ "$total_count" -eq 0 ]]; then
        gum style --foreground 214 "No eligible role assignments found."
        return 0
    fi

    # Build options array for gum choose
    # Track which assignments are directory roles
    local options=()
    local assignment_types=()
    local assignment_data=()
    local i=0

    # Add subscription-level roles
    while IFS= read -r assignment; do
        local role_name scope_name

        role_name=$(echo "$assignment" | jq -r '.properties.expandedProperties.roleDefinition.displayName // "Unknown Role"')
        scope_name=$(echo "$assignment" | jq -r '.properties.expandedProperties.scope.displayName // "Unknown"')

        options+=("$((i + 1)). [Azure] $role_name @ $scope_name")
        assignment_types+=("azure")
        assignment_data+=("$assignment")
        i=$((i + 1))
    done < <(echo "$assignments" | jq -c '.[]')

    # Add directory-level roles
    if [[ "$dir_count" -gt 0 ]]; then
        while IFS= read -r assignment; do
            local role_name

            role_name=$(echo "$assignment" | jq -r '.roleDefinition.displayName // "Unknown Role"')

            options+=("$((i + 1)). [Entra ID] $role_name")
            assignment_types+=("directory")
            assignment_data+=("$assignment")
            i=$((i + 1))
        done < <(echo "$dir_assignments" | jq -c '.value[]')
    fi

    # Use gum choose for selection
    local selection
    selection=$(printf '%s\n' "${options[@]}" | gum choose --header "Select role to activate:")

    if [[ -z "$selection" ]]; then
        gum style --foreground 214 "Cancelled."
        return 0
    fi

    # Extract the index from selection
    local role_index
    role_index=$(echo "$selection" | cut -d'.' -f1)
    local arr_index=$((role_index - 1))

    # Get duration using gum input
    local duration
    duration=$(gum input --placeholder "$DEFAULT_DURATION_HOURS" --header "Duration in hours (1-$MAX_DURATION_HOURS):" --value "$DEFAULT_DURATION_HOURS")

    if [[ -z "$duration" ]]; then
        duration=$DEFAULT_DURATION_HOURS
    fi

    if ! [[ "$duration" =~ ^[0-9]+$ ]] || [[ "$duration" -lt 1 ]] || [[ "$duration" -gt "$MAX_DURATION_HOURS" ]]; then
        gum style --foreground 196 "Invalid duration. Must be between 1 and $MAX_DURATION_HOURS hours."
        return 1
    fi

    # Get justification using gum input
    local justification
    justification=$(gum input --placeholder "Enter justification..." --header "Justification (required):" --width 60)

    if [[ -z "$justification" ]]; then
        gum style --foreground 196 "Justification is required"
        return 1
    fi

    echo ""

    # Activate based on assignment type
    if [[ "${assignment_types[$arr_index]}" == "directory" ]]; then
        activate_directory_role "${assignment_data[$arr_index]}" "$duration" "$justification"
    else
        ELIGIBLE_ASSIGNMENTS="$assignments"
        # Calculate the azure-only index
        local azure_index=0
        for ((j=0; j<arr_index; j++)); do
            if [[ "${assignment_types[$j]}" == "azure" ]]; then
                azure_index=$((azure_index + 1))
            fi
        done
        activate_role "$((azure_index + 1))" "$duration" "$justification"
    fi
}

deactivate_directory_role() {
    local assignment="$1"

    local graph_token
    graph_token=$(get_graph_token) || {
        gum style --foreground 196 "Not logged in. Please run 'pim login' first."
        return 1
    }

    local role_def_id principal_id role_name dir_scope_id
    role_def_id=$(echo "$assignment" | jq -r '.roleDefinition.id // .roleDefinitionId')
    principal_id=$(echo "$assignment" | jq -r '.principalId')
    role_name=$(echo "$assignment" | jq -r '.roleDefinition.displayName // "Unknown Role"')
    dir_scope_id=$(echo "$assignment" | jq -r '.directoryScopeId // "/"')

    local request_body
    request_body=$(jq -n \
        --arg principalId "$principal_id" \
        --arg roleDefinitionId "$role_def_id" \
        --arg directoryScopeId "$dir_scope_id" \
        '{
            action: "selfDeactivate",
            principalId: $principalId,
            roleDefinitionId: $roleDefinitionId,
            directoryScopeId: $directoryScopeId
        }')

    local result
    result=$(gum spin --spinner dot --title "Deactivating $role_name..." -- \
        curl -s -X POST \
        -H "Authorization: Bearer $graph_token" \
        -H "Content-Type: application/json" \
        -d "$request_body" \
        "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests") || {
        gum style --foreground 196 "Failed to deactivate directory role"
        return 1
    }

    if echo "$result" | jq -e '.error' &>/dev/null; then
        local error_msg
        error_msg=$(echo "$result" | jq -r '.error.message // "Unknown error"')
        gum style --foreground 196 "Failed to deactivate role: $error_msg"
        return 1
    fi

    gum style --foreground 35 --bold "✓ Role deactivated successfully!"
}

deactivate_role() {
    gum style --bold --foreground 212 "Deactivate Active Roles"
    echo ""

    check_az
    check_login

    local user_id group_ids subscription_id
    user_id=$(get_current_user_id)
    group_ids=$(get_user_group_ids)
    subscription_id=$(get_subscription_id)

    # Fetch subscription-level active roles
    local url="https://management.azure.com/subscriptions/$subscription_id/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=2020-10-01"

    local all_active
    all_active=$(gum spin --spinner dot --title "Fetching subscription-level active roles..." -- \
        az rest --method GET --url "$url" 2>/dev/null) || {
        gum style --foreground 196 "Failed to fetch active assignments"
        return 1
    }

    # Filter to user's activated assignments
    local principal_ids="$user_id $group_ids"
    local jq_filter='[.value[] | select((.properties.assignmentType == "Activated") and ('
    local first=true
    for pid in $principal_ids; do
        if [[ -n "$pid" ]]; then
            if [[ "$first" == "true" ]]; then
                jq_filter+=".properties.principalId == \"$pid\""
                first=false
            else
                jq_filter+=" or .properties.principalId == \"$pid\""
            fi
        fi
    done
    jq_filter+='))]'

    local active
    active=$(echo "$all_active" | jq "$jq_filter")

    local sub_count
    sub_count=$(echo "$active" | jq 'length')

    # Fetch directory-level active roles
    local dir_active dir_count=0
    local graph_token graph_user_id
    graph_token=$(get_graph_token 2>/dev/null) || graph_token=""

    if [[ -n "$graph_token" ]]; then
        graph_user_id=$(get_graph_user_id 2>/dev/null) || graph_user_id=""

        if [[ -n "$graph_user_id" ]]; then
            local dir_url="https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?\$filter=principalId%20eq%20%27${graph_user_id}%27%20and%20assignmentType%20eq%20%27Activated%27&\$expand=roleDefinition"

            dir_active=$(gum spin --spinner dot --title "Fetching directory-level active roles..." -- \
                curl -s -X GET -H "Authorization: Bearer $graph_token" -H "Content-Type: application/json" "$dir_url") || dir_active=""
        fi
    fi

    if [[ -n "$dir_active" ]] && ! echo "$dir_active" | jq -e '.error' &>/dev/null; then
        dir_count=$(echo "$dir_active" | jq '.value | length // 0')
    fi

    local total_count=$((sub_count + dir_count))

    if [[ "$total_count" -eq 0 ]]; then
        gum style --foreground 214 "No active role assignments to deactivate."
        return 0
    fi

    # Build options array for gum choose
    local options=()
    local assignment_types=()
    local assignment_data=()
    local i=0

    # Add subscription-level roles
    while IFS= read -r assignment; do
        local role_name scope_name

        role_name=$(echo "$assignment" | jq -r '.properties.expandedProperties.roleDefinition.displayName // "Unknown Role"')
        scope_name=$(echo "$assignment" | jq -r '.properties.expandedProperties.scope.displayName // "Unknown"')

        options+=("$((i + 1)). [Azure] $role_name @ $scope_name")
        assignment_types+=("azure")
        assignment_data+=("$assignment")
        i=$((i + 1))
    done < <(echo "$active" | jq -c '.[]')

    # Add directory-level roles
    if [[ "$dir_count" -gt 0 ]]; then
        while IFS= read -r assignment; do
            local role_name

            role_name=$(echo "$assignment" | jq -r '.roleDefinition.displayName // "Unknown Role"')

            options+=("$((i + 1)). [Entra ID] $role_name")
            assignment_types+=("directory")
            assignment_data+=("$assignment")
            i=$((i + 1))
        done < <(echo "$dir_active" | jq -c '.value[]')
    fi

    # Use gum choose for selection
    local selection
    selection=$(printf '%s\n' "${options[@]}" | gum choose --header "Select role to deactivate:")

    if [[ -z "$selection" ]]; then
        gum style --foreground 214 "Cancelled."
        return 0
    fi

    # Extract the index from selection
    local sel_index
    sel_index=$(echo "$selection" | cut -d'.' -f1)
    local arr_index=$((sel_index - 1))

    # Deactivate based on assignment type
    if [[ "${assignment_types[$arr_index]}" == "directory" ]]; then
        deactivate_directory_role "${assignment_data[$arr_index]}"
    else
        local selected_assignment="${assignment_data[$arr_index]}"

        local role_def_id scope principal_id role_name

        role_def_id=$(echo "$selected_assignment" | jq -r '.properties.roleDefinitionId')
        scope=$(echo "$selected_assignment" | jq -r '.properties.scope')
        principal_id=$(echo "$selected_assignment" | jq -r '.properties.principalId')
        role_name=$(echo "$selected_assignment" | jq -r '.properties.expandedProperties.roleDefinition.displayName // "Unknown Role"')

        local request_guid
        request_guid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)

        local request_body
        request_body=$(jq -n \
            --arg principalId "$principal_id" \
            --arg roleDefinitionId "$role_def_id" \
            '{
                properties: {
                    principalId: $principalId,
                    roleDefinitionId: $roleDefinitionId,
                    requestType: "SelfDeactivate"
                }
            }')

        local api_url="https://management.azure.com${scope}/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/${request_guid}?api-version=2020-10-01"

        local result
        result=$(gum spin --spinner dot --title "Deactivating $role_name..." -- \
            az rest --method PUT --url "$api_url" --headers "Content-Type=application/json" --body "$request_body" 2>&1) || {
            gum style --foreground 196 "Failed to deactivate role"
            echo "$result"
            return 1
        }

        gum style --foreground 35 --bold "✓ Role deactivated successfully!"
    fi
}

#------------------------------------------------------------------------------
# PIM Group Functions (Azure AD Groups)
#------------------------------------------------------------------------------

get_eligible_groups() {
    local user_id
    user_id=$(get_graph_user_id) || return 1

    # URL encode the filter parameter
    local url="https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?\$filter=principalId%20eq%20%27${user_id}%27"

    local result
    result=$(graph_request GET "$url") || return 1

    if echo "$result" | jq -e '.error' &>/dev/null; then
        local error_msg
        error_msg=$(echo "$result" | jq -r '.error.message // "Unknown error"')
        echo "Failed to fetch eligible groups: $error_msg" >&2
        return 1
    fi

    echo "$result"
}

get_active_groups() {
    local user_id
    user_id=$(get_graph_user_id) || return 1

    # URL encode the filter parameter
    local url="https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?\$filter=principalId%20eq%20%27${user_id}%27"
    graph_request GET "$url"
}

get_group_name() {
    local group_id="$1"
    local result

    result=$(graph_request GET "https://graph.microsoft.com/v1.0/groups/${group_id}?\$select=displayName" 2>/dev/null)
    local name
    name=$(echo "$result" | jq -r '.displayName // empty' 2>/dev/null)

    if [[ -n "$name" ]]; then
        echo "$name"
    else
        echo "Group ($group_id)"
    fi
}

# Fetch multiple group names in a single batch request
# Usage: get_group_names_batch "id1" "id2" "id3" ...
# Returns JSON object: {"id1": "Name1", "id2": "Name2", ...}
get_group_names_batch() {
    local token
    token=$(get_graph_token) || return 1

    local group_ids=("$@")

    if [[ ${#group_ids[@]} -eq 0 ]]; then
        echo "{}"
        return 0
    fi

    # Build filter: id in ('id1','id2',...)
    local filter="id%20in%20("
    local first=true
    for gid in "${group_ids[@]}"; do
        if [[ "$first" == "true" ]]; then
            filter+="%27${gid}%27"
            first=false
        else
            filter+=",%27${gid}%27"
        fi
    done
    filter+=")"

    local url="https://graph.microsoft.com/v1.0/groups?\$filter=${filter}&\$select=id,displayName"

    local result
    result=$(curl -s -X GET -H "Authorization: Bearer $token" -H "Content-Type: application/json" "$url")

    # Convert to id->name map
    echo "$result" | jq -r '[.value[] | {(.id): .displayName}] | add // {}'
}

list_eligible_groups() {
    local result

    # Get token and user ID first (these are cached, so fast)
    local token user_id
    token=$(get_graph_token) || {
        gum style --foreground 196 "Not logged in. Please run 'pim login' first."
        return 1
    }
    user_id=$(get_graph_user_id) || {
        gum style --foreground 196 "Failed to get user ID"
        return 1
    }

    # Now use gum spin to show spinner while fetching
    local url="https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?\$filter=principalId%20eq%20%27${user_id}%27"

    result=$(gum spin --spinner dot --title "Fetching eligible groups..." -- \
        curl -s -X GET -H "Authorization: Bearer $token" -H "Content-Type: application/json" "$url")

    # Check if result is valid JSON
    if ! echo "$result" | jq -e . >/dev/null 2>&1; then
        gum style --foreground 196 "Invalid response from API"
        return 1
    fi

    # Check for API error
    if echo "$result" | jq -e '.error' >/dev/null 2>&1; then
        local error_msg
        error_msg=$(echo "$result" | jq -r '.error.message // "Unknown error"')
        gum style --foreground 196 "API Error: $error_msg"
        return 1
    fi

    local assignments
    assignments=$(echo "$result" | jq '.value // []')

    local count
    count=$(echo "$assignments" | jq 'length')

    if [[ "$count" -eq 0 ]]; then
        gum style --foreground 214 "No eligible PIM group memberships found."
        return 0
    fi

    # Collect all unique group IDs and fetch names in batch
    local group_ids_str
    group_ids_str=$(echo "$assignments" | jq -r '.[].groupId' | sort -u | while read -r gid; do printf "%%27%s%%27," "$gid"; done | sed 's/,$//')

    local filter="id%20in%20(${group_ids_str})"
    local names_url="https://graph.microsoft.com/v1.0/groups?\$filter=${filter}&\$select=id,displayName"

    local group_names_raw group_names
    group_names_raw=$(gum spin --spinner dot --title "Resolving group names..." -- \
        curl -s -X GET -H "Authorization: Bearer $token" -H "Content-Type: application/json" "$names_url")
    group_names=$(echo "$group_names_raw" | jq -r '[.value[] | {(.id): .displayName}] | add // {}')

    gum style --bold --foreground 212 "Found $count eligible group(s)"
    echo ""

    # Build display list with group names
    while IFS= read -r assignment; do
        local group_id access_id
        group_id=$(echo "$assignment" | jq -r '.groupId')
        access_id=$(echo "$assignment" | jq -r '.accessId')

        local group_name
        group_name=$(echo "$group_names" | jq -r --arg id "$group_id" '.[$id] // "Unknown Group"')

        local access_type="member"
        [[ "$access_id" == "owner" ]] && access_type="owner"

        gum style --foreground 35 "  • $group_name ($access_type)"
    done < <(echo "$assignments" | jq -c '.[]')

    ELIGIBLE_GROUPS="$assignments"
    ELIGIBLE_GROUP_NAMES="$group_names"
}

list_active_groups() {
    local result

    # Get token and user ID first (cached, fast)
    local token user_id
    token=$(get_graph_token) || {
        gum style --foreground 196 "Not logged in. Please run 'pim login' first."
        return 1
    }
    user_id=$(get_graph_user_id) || {
        gum style --foreground 196 "Failed to get user ID"
        return 1
    }

    # Fetch with spinner
    local url="https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?\$filter=principalId%20eq%20%27${user_id}%27"

    result=$(gum spin --spinner dot --title "Fetching active groups..." -- \
        curl -s -X GET -H "Authorization: Bearer $token" -H "Content-Type: application/json" "$url")

    if echo "$result" | jq -e '.error' &>/dev/null; then
        local error_msg
        error_msg=$(echo "$result" | jq -r '.error.message // "Unknown error"')
        gum style --foreground 196 "Failed to fetch active groups: $error_msg"
        return 1
    fi

    local assignments
    assignments=$(echo "$result" | jq '.value // []')

    local count
    count=$(echo "$assignments" | jq 'length')

    if [[ "$count" -eq 0 ]]; then
        gum style --foreground 214 "No currently active PIM group memberships."
        return 0
    fi

    # Batch fetch group names
    local group_ids_str
    group_ids_str=$(echo "$assignments" | jq -r '.[].groupId' | sort -u | while read -r gid; do printf "%%27%s%%27," "$gid"; done | sed 's/,$//')

    local filter="id%20in%20(${group_ids_str})"
    local names_url="https://graph.microsoft.com/v1.0/groups?\$filter=${filter}&\$select=id,displayName"

    local group_names_raw group_names
    group_names_raw=$(gum spin --spinner dot --title "Resolving group names..." -- \
        curl -s -X GET -H "Authorization: Bearer $token" -H "Content-Type: application/json" "$names_url")
    group_names=$(echo "$group_names_raw" | jq -r '[.value[] | {(.id): .displayName}] | add // {}')

    gum style --bold --foreground 212 "Found $count active group(s)"
    echo ""

    while IFS= read -r assignment; do
        local group_id access_id end_time assignment_type

        group_id=$(echo "$assignment" | jq -r '.groupId')
        access_id=$(echo "$assignment" | jq -r '.accessId')
        end_time=$(echo "$assignment" | jq -r '.endDateTime // "Permanent"')
        assignment_type=$(echo "$assignment" | jq -r '.assignmentType // "Unknown"')

        local group_name
        group_name=$(echo "$group_names" | jq -r --arg id "$group_id" '.[$id] // "Unknown Group"')

        local access_type="member"
        [[ "$access_id" == "owner" ]] && access_type="owner"

        gum style --foreground 35 "  ● $group_name ($access_type)"
        gum style --foreground 245 "    Type: $assignment_type | Expires: $end_time"
        echo ""
    done < <(echo "$assignments" | jq -c '.[]')
}

activate_group() {
    local group_index="$1"
    local duration_hours="${2:-$DEFAULT_DURATION_HOURS}"
    local justification="${3:-Activated via PIM CLI tool}"

    if [[ -z "$ELIGIBLE_GROUPS" ]]; then
        local fetch_result
        fetch_result=$(get_eligible_groups) || return 1
        ELIGIBLE_GROUPS=$(echo "$fetch_result" | jq '.value // []')
    fi

    local count
    count=$(echo "$ELIGIBLE_GROUPS" | jq 'length')

    if [[ "$group_index" -lt 1 ]] || [[ "$group_index" -gt "$count" ]]; then
        gum style --foreground 196 "Invalid group index. Please choose between 1 and $count"
        return 1
    fi

    local assignment
    assignment=$(echo "$ELIGIBLE_GROUPS" | jq -c ".[$((group_index - 1))]")

    local group_id access_id user_id token

    group_id=$(echo "$assignment" | jq -r '.groupId')
    access_id=$(echo "$assignment" | jq -r '.accessId')
    token=$(get_graph_token) || return 1
    user_id=$(get_graph_user_id) || return 1

    local group_name
    group_name=$(get_group_name "$group_id")

    local access_type="member"
    if [[ "$access_id" == "owner" ]]; then
        access_type="owner"
    fi

    local start_time
    start_time=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    local request_body
    request_body=$(jq -n \
        --arg action "selfActivate" \
        --arg principalId "$user_id" \
        --arg groupId "$group_id" \
        --arg accessId "$access_id" \
        --arg justification "$justification" \
        --arg startDateTime "$start_time" \
        --arg duration "PT${duration_hours}H" \
        '{
            action: $action,
            principalId: $principalId,
            groupId: $groupId,
            accessId: $accessId,
            justification: $justification,
            scheduleInfo: {
                startDateTime: $startDateTime,
                expiration: {
                    type: "afterDuration",
                    duration: $duration
                }
            }
        }')

    local result
    result=$(gum spin --spinner dot --title "Activating $group_name ($access_type)..." -- \
        curl -s -X POST \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d "$request_body" \
        "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleRequests")

    if echo "$result" | jq -e '.error' &>/dev/null; then
        local error_msg
        error_msg=$(echo "$result" | jq -r '.error.message // "Unknown error"')
        gum style --foreground 196 "Failed to activate group: $error_msg"
        if echo "$error_msg" | grep -q "ExpirationRule"; then
            gum style --foreground 214 "Hint: The requested duration exceeds the policy limit. Try a shorter duration."
        fi
        return 1
    fi

    local status
    status=$(echo "$result" | jq -r '.status // "Unknown"')

    if [[ "$status" == "Provisioned" ]] || [[ "$status" == "PendingApproval" ]] || [[ "$status" == "Granted" ]]; then
        gum style --foreground 35 --bold "✓ Group activation request submitted successfully!"
        gum style --foreground 33 "Status: $status"
        if [[ "$status" == "PendingApproval" ]]; then
            gum style --foreground 214 "This group requires approval. Please wait for an approver to approve your request."
        fi
    else
        gum style --foreground 214 "Activation request status: $status"
    fi
}

interactive_activate_group() {
    gum style --bold --foreground 212 "PIM Group Activation"
    echo ""

    # Get token and user ID first
    local token user_id
    token=$(get_graph_token) || {
        gum style --foreground 196 "Not logged in. Please run 'pim login' first."
        return 1
    }
    user_id=$(get_graph_user_id) || {
        gum style --foreground 196 "Failed to get user ID"
        return 1
    }

    # Fetch eligible groups with spinner
    local url="https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?\$filter=principalId%20eq%20%27${user_id}%27"

    local result
    result=$(gum spin --spinner dot --title "Fetching eligible groups..." -- \
        curl -s -X GET -H "Authorization: Bearer $token" -H "Content-Type: application/json" "$url")

    local assignments
    assignments=$(echo "$result" | jq '.value // []')

    local count
    count=$(echo "$assignments" | jq 'length')

    if [[ "$count" -eq 0 ]]; then
        gum style --foreground 214 "No eligible PIM group memberships found."
        return 0
    fi

    # Batch fetch group names
    local group_ids_str
    group_ids_str=$(echo "$assignments" | jq -r '.[].groupId' | sort -u | while read -r gid; do printf "%%27%s%%27," "$gid"; done | sed 's/,$//')

    local filter="id%20in%20(${group_ids_str})"
    local names_url="https://graph.microsoft.com/v1.0/groups?\$filter=${filter}&\$select=id,displayName"

    local group_names_raw group_names
    group_names_raw=$(gum spin --spinner dot --title "Resolving group names..." -- \
        curl -s -X GET -H "Authorization: Bearer $token" -H "Content-Type: application/json" "$names_url")
    group_names=$(echo "$group_names_raw" | jq -r '[.value[] | {(.id): .displayName}] | add // {}')

    # Build options array for gum choose
    local options=()
    local i=0
    while IFS= read -r assignment; do
        local group_id access_id
        group_id=$(echo "$assignment" | jq -r '.groupId')
        access_id=$(echo "$assignment" | jq -r '.accessId')

        local group_name
        group_name=$(echo "$group_names" | jq -r --arg id "$group_id" '.[$id] // "Unknown Group"')

        local access_type="member"
        [[ "$access_id" == "owner" ]] && access_type="owner"

        options+=("$((i + 1)). $group_name ($access_type)")
        i=$((i + 1))
    done < <(echo "$assignments" | jq -c '.[]')

    # Use gum choose for selection
    local selection
    selection=$(printf '%s\n' "${options[@]}" | gum choose --header "Select group to activate:")

    if [[ -z "$selection" ]]; then
        gum style --foreground 214 "Cancelled."
        return 0
    fi

    # Extract the index from selection
    local group_index
    group_index=$(echo "$selection" | cut -d'.' -f1)

    # Get duration using gum input
    local duration
    duration=$(gum input --placeholder "$DEFAULT_DURATION_HOURS" --header "Duration in hours (1-$MAX_DURATION_HOURS):" --value "$DEFAULT_DURATION_HOURS")

    if [[ -z "$duration" ]]; then
        duration=$DEFAULT_DURATION_HOURS
    fi

    if ! [[ "$duration" =~ ^[0-9]+$ ]] || [[ "$duration" -lt 1 ]] || [[ "$duration" -gt "$MAX_DURATION_HOURS" ]]; then
        gum style --foreground 196 "Invalid duration. Must be between 1 and $MAX_DURATION_HOURS hours."
        return 1
    fi

    # Get justification using gum input
    local justification
    justification=$(gum input --placeholder "Enter justification..." --header "Justification (required):" --width 60)

    if [[ -z "$justification" ]]; then
        gum style --foreground 196 "Justification is required"
        return 1
    fi

    echo ""
    ELIGIBLE_GROUPS="$assignments"
    activate_group "$group_index" "$duration" "$justification"
}

deactivate_group() {
    gum style --bold --foreground 212 "Deactivate Active PIM Groups"
    echo ""

    # Get token and user ID first
    local token user_id
    token=$(get_graph_token) || {
        gum style --foreground 196 "Not logged in. Please run 'pim login' first."
        return 1
    }
    user_id=$(get_graph_user_id) || {
        gum style --foreground 196 "Failed to get user ID"
        return 1
    }

    # Fetch active groups with spinner
    local url="https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?\$filter=principalId%20eq%20%27${user_id}%27"

    local result
    result=$(gum spin --spinner dot --title "Fetching active groups..." -- \
        curl -s -X GET -H "Authorization: Bearer $token" -H "Content-Type: application/json" "$url")

    if echo "$result" | jq -e '.error' &>/dev/null; then
        local error_msg
        error_msg=$(echo "$result" | jq -r '.error.message // "Unknown error"')
        gum style --foreground 196 "Failed to fetch active groups: $error_msg"
        return 1
    fi

    local assignments
    assignments=$(echo "$result" | jq '.value // []')

    local count
    count=$(echo "$assignments" | jq 'length')

    if [[ "$count" -eq 0 ]]; then
        gum style --foreground 214 "No active PIM group memberships to deactivate."
        return 0
    fi

    # Batch fetch all group names
    local group_ids_str
    group_ids_str=$(echo "$assignments" | jq -r '.[].groupId' | sort -u | while read -r gid; do printf "%%27%s%%27," "$gid"; done | sed 's/,$//')

    local filter="id%20in%20(${group_ids_str})"
    local names_url="https://graph.microsoft.com/v1.0/groups?\$filter=${filter}&\$select=id,displayName"

    local group_names_raw group_names
    group_names_raw=$(gum spin --spinner dot --title "Resolving group names..." -- \
        curl -s -X GET -H "Authorization: Bearer $token" -H "Content-Type: application/json" "$names_url")
    group_names=$(echo "$group_names_raw" | jq -r '[.value[] | {(.id): .displayName}] | add // {}')

    # Build options array for gum choose
    local options=()
    local i=0
    while IFS= read -r assignment; do
        local group_id access_id

        group_id=$(echo "$assignment" | jq -r '.groupId')
        access_id=$(echo "$assignment" | jq -r '.accessId')

        local group_name
        group_name=$(echo "$group_names" | jq -r --arg id "$group_id" '.[$id] // "Unknown Group"')

        local access_type="member"
        [[ "$access_id" == "owner" ]] && access_type="owner"

        options+=("$((i + 1)). $group_name ($access_type)")
        i=$((i + 1))
    done < <(echo "$assignments" | jq -c '.[]')

    # Use gum choose for selection
    local selection
    selection=$(printf '%s\n' "${options[@]}" | gum choose --header "Select group to deactivate:")

    if [[ -z "$selection" ]]; then
        gum style --foreground 214 "Cancelled."
        return 0
    fi

    # Extract the index from selection
    local sel_index
    sel_index=$(echo "$selection" | cut -d'.' -f1)

    local selected
    selected=$(echo "$assignments" | jq -c ".[$((sel_index - 1))]")

    local group_id access_id

    group_id=$(echo "$selected" | jq -r '.groupId')
    access_id=$(echo "$selected" | jq -r '.accessId')

    local group_name
    group_name=$(echo "$group_names" | jq -r --arg id "$group_id" '.[$id] // "Unknown Group"')

    local request_body
    request_body=$(jq -n \
        --arg action "selfDeactivate" \
        --arg principalId "$user_id" \
        --arg groupId "$group_id" \
        --arg accessId "$access_id" \
        '{action: $action, principalId: $principalId, groupId: $groupId, accessId: $accessId}')

    local deactivate_result
    deactivate_result=$(gum spin --spinner dot --title "Deactivating $group_name..." -- \
        curl -s -X POST \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d "$request_body" \
        "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleRequests")

    if echo "$deactivate_result" | jq -e '.error' &>/dev/null; then
        local error_msg
        error_msg=$(echo "$deactivate_result" | jq -r '.error.message // "Unknown error"')
        gum style --foreground 196 "Failed to deactivate group: $error_msg"
        return 1
    fi

    gum style --foreground 35 --bold "✓ Group deactivated successfully!"
}

#------------------------------------------------------------------------------
# Installation and Completions
#------------------------------------------------------------------------------

INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
COMPLETIONS_DIR_BASH="${COMPLETIONS_DIR_BASH:-$HOME/.local/share/bash-completion/completions}"
COMPLETIONS_DIR_ZSH="${COMPLETIONS_DIR_ZSH:-$HOME/.local/share/zsh/site-functions}"

generate_bash_completions() {
    cat << 'BASH_COMPLETIONS'
# pim bash completion
_pim() {
    local cur prev commands scopes shorthand
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    commands="list l active activate a deactivate d setup grant-consent login help h install uninstall completions"
    scopes="all tenant t role r group g"
    shorthand="lt lr lg la lat lar lag at ar ag dt dr dg"

    if [[ ${COMP_CWORD} -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${commands} ${shorthand}" -- "${cur}") )
        return 0
    fi

    case "${prev}" in
        list|l|active|activate|a|deactivate|d)
            COMPREPLY=( $(compgen -W "${scopes}" -- "${cur}") )
            return 0
            ;;
        completions)
            COMPREPLY=( $(compgen -W "bash zsh install" -- "${cur}") )
            return 0
            ;;
    esac

    return 0
}

complete -F _pim pim
complete -F _pim pim.sh
BASH_COMPLETIONS
}

generate_zsh_completions() {
    cat << 'ZSH_COMPLETIONS'
#compdef pim pim.sh

_pim() {
    local -a commands scopes
    commands=(
        'list:List eligible assignments'
        'l:List eligible assignments'
        'active:List active assignments'
        'activate:Activate an eligible assignment'
        'a:Activate an eligible assignment'
        'deactivate:Deactivate an active assignment'
        'd:Deactivate an active assignment'
        'setup:Create app registration for PIM permissions'
        'grant-consent:Grant admin consent for the app (requires admin)'
        'login:Authenticate with PIM permissions'
        'help:Show help message'
        'h:Show help message'
        'install:Install pim to ~/.local/bin'
        'uninstall:Remove pim from ~/.local/bin'
        'completions:Manage shell completions'
        'lt:List eligible tenant roles'
        'lr:List eligible Azure roles'
        'lg:List eligible PIM groups'
        'la:List active (all)'
        'lat:List active tenant roles'
        'lar:List active Azure roles'
        'lag:List active PIM groups'
        'at:Activate tenant role'
        'ar:Activate Azure role'
        'ag:Activate group membership'
        'dt:Deactivate tenant role'
        'dr:Deactivate Azure role'
        'dg:Deactivate group membership'
    )

    scopes=(
        'all:All types (tenant, role, group)'
        'tenant:Entra ID directory roles'
        't:Entra ID directory roles'
        'role:Azure subscription roles'
        'r:Azure subscription roles'
        'group:PIM groups'
        'g:PIM groups'
    )

    _arguments -C \
        '1: :->command' \
        '*: :->args'

    case $state in
        command)
            _describe -t commands 'pim commands' commands
            ;;
        args)
            case $words[2] in
                list|l|active|activate|a|deactivate|d)
                    _describe -t scopes 'scope' scopes
                    ;;
                completions)
                    _values 'completion commands' 'bash[Show bash completions]' 'zsh[Show zsh completions]' 'install[Install completions]'
                    ;;
            esac
            ;;
    esac
}

_pim "$@"
ZSH_COMPLETIONS
}

do_install() {
    echo "Installing pim"
    echo ""

    # Check dependencies before install
    local missing=()

    if ! command -v jq &> /dev/null; then
        missing+=("jq")
    fi

    if ! command -v gum &> /dev/null; then
        missing+=("gum")
    fi

    if ! command -v az &> /dev/null; then
        missing+=("az (Azure CLI)")
    fi

    if ! command -v curl &> /dev/null; then
        missing+=("curl")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "ERROR: Missing required dependencies:"
        for dep in "${missing[@]}"; do
            echo "  - $dep"
        done
        echo ""
        echo "Please install the missing dependencies:"
        echo "  jq:   sudo apt-get install jq (Debian/Ubuntu) or brew install jq (macOS)"
        echo "  gum:  https://github.com/charmbracelet/gum#installation"
        echo "  az:   https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
        echo "  curl: sudo apt-get install curl (Debian/Ubuntu) or brew install curl (macOS)"
        exit 1
    fi

    # Optional dependency check
    if ! command -v secret-tool &> /dev/null; then
        echo "Note: secret-tool not found. Refresh tokens will be stored in a file instead of the system keyring."
        echo "      Install libsecret-tools for more secure token storage."
        echo ""
    fi

    gum style --foreground 35 "✓ All required dependencies found"
    echo ""

    gum style --bold --foreground 212 "Installing pim"
    echo ""

    # Create install directory
    if [[ ! -d "$INSTALL_DIR" ]]; then
        gum style --foreground 33 "Creating $INSTALL_DIR..."
        mkdir -p "$INSTALL_DIR"
    fi

    # Get the script's real path
    local script_path
    script_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

    # Copy or symlink to install directory
    local install_path="$INSTALL_DIR/pim"

    if gum confirm "Create symlink (recommended for development) or copy?"; then
        ln -sf "$script_path" "$install_path"
        gum style --foreground 35 "✓ Created symlink: $install_path -> $script_path"
    else
        cp "$script_path" "$install_path"
        chmod +x "$install_path"
        gum style --foreground 35 "✓ Copied to: $install_path"
    fi

    # Check if install dir is in PATH
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        gum style --foreground 214 "Warning: $INSTALL_DIR is not in your PATH"
        echo ""
        echo "Add this to your ~/.bashrc or ~/.zshrc:"
        gum style --foreground 33 "  export PATH=\"\$HOME/.local/bin:\$PATH\""
        echo ""
    fi

    # Offer to install completions
    echo ""
    if gum confirm "Install shell completions?"; then
        install_completions
    fi

    echo ""
    gum style --foreground 35 --bold "✓ Installation complete!"
    echo ""
    echo "You can now run 'pim' from anywhere."
}

do_uninstall() {
    gum style --bold --foreground 212 "Uninstalling pim"
    echo ""

    local install_path="$INSTALL_DIR/pim"
    local bash_completion="$COMPLETIONS_DIR_BASH/pim"
    local zsh_completion="$COMPLETIONS_DIR_ZSH/_pim"

    if [[ -e "$install_path" ]]; then
        rm -f "$install_path"
        gum style --foreground 35 "✓ Removed $install_path"
    else
        gum style --foreground 214 "pim not found in $INSTALL_DIR"
    fi

    if [[ -e "$bash_completion" ]]; then
        rm -f "$bash_completion"
        gum style --foreground 35 "✓ Removed bash completions"
    fi

    if [[ -e "$zsh_completion" ]]; then
        rm -f "$zsh_completion"
        gum style --foreground 35 "✓ Removed zsh completions"
    fi

    # Remove config if requested
    echo ""
    if [[ -d "$CONFIG_DIR" ]]; then
        if gum confirm "Remove configuration and cached tokens from $CONFIG_DIR?"; then
            rm -rf "$CONFIG_DIR"
            gum style --foreground 35 "✓ Removed configuration directory"

            # Also remove refresh token from secret-tool
            if command -v secret-tool &> /dev/null; then
                secret-tool clear application pim type refresh_token 2>/dev/null || true
                gum style --foreground 35 "✓ Removed stored credentials"
            fi
        fi
    fi

    echo ""
    gum style --foreground 35 --bold "✓ Uninstall complete!"
}

install_completions() {
    gum style --foreground 33 "Installing shell completions..."

    # Detect shell
    local current_shell
    current_shell=$(basename "$SHELL")

    # Install bash completions
    if [[ "$current_shell" == "bash" ]] || [[ -d "$COMPLETIONS_DIR_BASH" ]] || gum confirm "Install bash completions?"; then
        mkdir -p "$COMPLETIONS_DIR_BASH"
        generate_bash_completions > "$COMPLETIONS_DIR_BASH/pim"
        gum style --foreground 35 "✓ Bash completions installed to $COMPLETIONS_DIR_BASH/pim"
    fi

    # Install zsh completions
    if [[ "$current_shell" == "zsh" ]] || [[ -d "$COMPLETIONS_DIR_ZSH" ]] || gum confirm "Install zsh completions?"; then
        mkdir -p "$COMPLETIONS_DIR_ZSH"
        generate_zsh_completions > "$COMPLETIONS_DIR_ZSH/_pim"
        gum style --foreground 35 "✓ Zsh completions installed to $COMPLETIONS_DIR_ZSH/_pim"
    fi

    echo ""
    gum style --foreground 214 "Restart your shell or run:"
    case "$current_shell" in
        bash)
            echo "  source $COMPLETIONS_DIR_BASH/pim"
            ;;
        zsh)
            echo "  autoload -Uz compinit && compinit"
            ;;
    esac
}

handle_completions() {
    local subcmd="${1:-}"

    case "$subcmd" in
        bash)
            generate_bash_completions
            ;;
        zsh)
            generate_zsh_completions
            ;;
        install)
            install_completions
            ;;
        *)
            gum style --bold --foreground 212 "Shell Completions"
            echo ""
            echo "Usage: pim completions <command>"
            echo ""
            echo "Commands:"
            echo "  bash     Print bash completion script"
            echo "  zsh      Print zsh completion script"
            echo "  install  Install completions for your shell"
            echo ""
            echo "To manually source completions:"
            gum style --foreground 33 "  Bash: eval \"\$(pim completions bash)\""
            gum style --foreground 33 "  Zsh:  eval \"\$(pim completions zsh)\""
            ;;
    esac
}

#------------------------------------------------------------------------------
# Unified Action Functions (with scope support)
#------------------------------------------------------------------------------

do_list() {
    local scope="$1"

    gum style --bold --foreground 212 "Eligible Assignments"
    echo ""

    local has_results=false

    # Tenant (Entra ID directory roles)
    if [[ "$scope" == "all" || "$scope" == "tenant" ]]; then
        local graph_token graph_user_id dir_assignments dir_count=0
        graph_token=$(get_graph_token 2>/dev/null) || graph_token=""

        if [[ -n "$graph_token" ]]; then
            graph_user_id=$(get_graph_user_id 2>/dev/null) || graph_user_id=""

            if [[ -n "$graph_user_id" ]]; then
                local dir_url="https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?\$filter=principalId%20eq%20%27${graph_user_id}%27&\$expand=roleDefinition"

                dir_assignments=$(gum spin --spinner dot --title "Fetching Entra ID roles..." -- \
                    curl -s -X GET -H "Authorization: Bearer $graph_token" -H "Content-Type: application/json" "$dir_url") || dir_assignments=""

                if [[ -n "$dir_assignments" ]] && ! echo "$dir_assignments" | jq -e '.error' &>/dev/null; then
                    dir_count=$(echo "$dir_assignments" | jq '.value | length // 0')
                fi

                if [[ "$dir_count" -gt 0 ]]; then
                    has_results=true
                    gum style --foreground 252 --italic "  Entra ID Tenant Roles ($dir_count):"
                    while IFS= read -r assignment; do
                        local role_name
                        role_name=$(echo "$assignment" | jq -r '.roleDefinition.displayName // "Unknown Role"')
                        gum style --foreground 35 "    • $role_name"
                    done < <(echo "$dir_assignments" | jq -c '.value[]')
                    echo ""
                fi
            fi
        elif [[ "$scope" == "tenant" ]]; then
            gum style --foreground 214 "Not logged in to Graph API. Run 'pim login' first."
            return 1
        fi
    fi

    # Role (Azure subscription roles)
    if [[ "$scope" == "all" || "$scope" == "role" ]]; then
        check_az
        check_login

        local user_id group_ids subscription_id
        user_id=$(get_current_user_id)
        group_ids=$(get_user_group_ids)
        subscription_id=$(get_subscription_id)

        local url="https://management.azure.com/subscriptions/$subscription_id/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01"

        local all_assignments
        all_assignments=$(gum spin --spinner dot --title "Fetching Azure roles..." -- \
            az rest --method GET --url "$url" 2>/dev/null) || {
            gum style --foreground 196 "Failed to fetch Azure role assignments"
            return 1
        }

        local principal_ids="$user_id $group_ids"
        local jq_filter='[.value[] | select('
        local first=true
        for pid in $principal_ids; do
            if [[ -n "$pid" ]]; then
                if [[ "$first" == "true" ]]; then
                    jq_filter+=".properties.principalId == \"$pid\""
                    first=false
                else
                    jq_filter+=" or .properties.principalId == \"$pid\""
                fi
            fi
        done
        jq_filter+=')]'

        local assignments
        assignments=$(echo "$all_assignments" | jq "$jq_filter")
        local sub_count
        sub_count=$(echo "$assignments" | jq 'length')

        if [[ "$sub_count" -gt 0 ]]; then
            has_results=true
            gum style --foreground 252 --italic "  Azure Subscription Roles ($sub_count):"
            while IFS= read -r assignment; do
                local role_name scope_name
                role_name=$(echo "$assignment" | jq -r '.properties.expandedProperties.roleDefinition.displayName // "Unknown Role"')
                scope_name=$(echo "$assignment" | jq -r '.properties.expandedProperties.scope.displayName // "Unknown"')
                gum style --foreground 35 "    • $role_name @ $scope_name"
            done < <(echo "$assignments" | jq -c '.[]')
            echo ""
        fi
    fi

    # Group (PIM groups)
    if [[ "$scope" == "all" || "$scope" == "group" ]]; then
        local graph_token user_id
        graph_token=$(get_graph_token 2>/dev/null) || graph_token=""

        if [[ -n "$graph_token" ]]; then
            user_id=$(get_graph_user_id 2>/dev/null) || user_id=""

            if [[ -n "$user_id" ]]; then
                local group_url="https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?\$filter=principalId%20eq%20%27${user_id}%27"

                local group_result
                group_result=$(gum spin --spinner dot --title "Fetching PIM groups..." -- \
                    curl -s -X GET -H "Authorization: Bearer $graph_token" -H "Content-Type: application/json" "$group_url") || group_result=""

                if [[ -n "$group_result" ]] && ! echo "$group_result" | jq -e '.error' &>/dev/null; then
                    local group_count
                    group_count=$(echo "$group_result" | jq '.value | length // 0')

                    if [[ "$group_count" -gt 0 ]]; then
                        has_results=true
                        # Get group names
                        local group_ids_list
                        group_ids_list=$(echo "$group_result" | jq -r '.value[].groupId' | sort -u)

                        gum style --foreground 252 --italic "  PIM Groups ($group_count):"
                        while IFS= read -r item; do
                            local group_id access_id group_name
                            group_id=$(echo "$item" | jq -r '.groupId')
                            access_id=$(echo "$item" | jq -r '.accessId')

                            # Fetch group name
                            group_name=$(curl -s -X GET \
                                -H "Authorization: Bearer $graph_token" \
                                -H "Content-Type: application/json" \
                                "https://graph.microsoft.com/v1.0/groups/${group_id}?\$select=displayName" 2>/dev/null | jq -r '.displayName // "Unknown Group"')

                            gum style --foreground 35 "    • $group_name ($access_id)"
                        done < <(echo "$group_result" | jq -c '.value[]')
                        echo ""
                    fi
                fi
            fi
        elif [[ "$scope" == "group" ]]; then
            gum style --foreground 214 "Not logged in to Graph API. Run 'pim login' first."
            return 1
        fi
    fi

    if [[ "$has_results" == "false" ]]; then
        gum style --foreground 214 "No eligible assignments found."
    fi
}

do_list_active() {
    local scope="$1"

    gum style --bold --foreground 212 "Active Assignments"
    echo ""

    local has_results=false

    # Tenant (Entra ID directory roles)
    if [[ "$scope" == "all" || "$scope" == "tenant" ]]; then
        local graph_token graph_user_id dir_active dir_count=0
        graph_token=$(get_graph_token 2>/dev/null) || graph_token=""

        if [[ -n "$graph_token" ]]; then
            graph_user_id=$(get_graph_user_id 2>/dev/null) || graph_user_id=""

            if [[ -n "$graph_user_id" ]]; then
                local dir_url="https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?\$filter=principalId%20eq%20%27${graph_user_id}%27%20and%20assignmentType%20eq%20%27Activated%27&\$expand=roleDefinition"

                dir_active=$(gum spin --spinner dot --title "Fetching active Entra ID roles..." -- \
                    curl -s -X GET -H "Authorization: Bearer $graph_token" -H "Content-Type: application/json" "$dir_url") || dir_active=""

                if [[ -n "$dir_active" ]] && ! echo "$dir_active" | jq -e '.error' &>/dev/null; then
                    dir_count=$(echo "$dir_active" | jq '.value | length // 0')
                fi

                if [[ "$dir_count" -gt 0 ]]; then
                    has_results=true
                    gum style --foreground 252 --italic "  Entra ID Tenant Roles ($dir_count):"
                    while IFS= read -r assignment; do
                        local role_name end_time
                        role_name=$(echo "$assignment" | jq -r '.roleDefinition.displayName // "Unknown Role"')
                        end_time=$(echo "$assignment" | jq -r '.endDateTime // "Permanent"')
                        gum style --foreground 35 "    • $role_name"
                        gum style --foreground 245 "      Expires: $end_time"
                    done < <(echo "$dir_active" | jq -c '.value[]')
                    echo ""
                fi
            fi
        elif [[ "$scope" == "tenant" ]]; then
            gum style --foreground 214 "Not logged in to Graph API. Run 'pim login' first."
            return 1
        fi
    fi

    # Role (Azure subscription roles)
    if [[ "$scope" == "all" || "$scope" == "role" ]]; then
        check_az
        check_login

        local user_id group_ids subscription_id
        user_id=$(get_current_user_id)
        group_ids=$(get_user_group_ids)
        subscription_id=$(get_subscription_id)

        local url="https://management.azure.com/subscriptions/$subscription_id/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=2020-10-01"

        local all_active
        all_active=$(gum spin --spinner dot --title "Fetching active Azure roles..." -- \
            az rest --method GET --url "$url" 2>/dev/null) || {
            gum style --foreground 196 "Failed to fetch active Azure role assignments"
            return 1
        }

        local principal_ids="$user_id $group_ids"
        local jq_filter='[.value[] | select((.properties.assignmentType == "Activated") and ('
        local first=true
        for pid in $principal_ids; do
            if [[ -n "$pid" ]]; then
                if [[ "$first" == "true" ]]; then
                    jq_filter+=".properties.principalId == \"$pid\""
                    first=false
                else
                    jq_filter+=" or .properties.principalId == \"$pid\""
                fi
            fi
        done
        jq_filter+='))]'

        local active
        active=$(echo "$all_active" | jq "$jq_filter")
        local sub_count
        sub_count=$(echo "$active" | jq 'length')

        if [[ "$sub_count" -gt 0 ]]; then
            has_results=true
            gum style --foreground 252 --italic "  Azure Subscription Roles ($sub_count):"
            while IFS= read -r assignment; do
                local role_name scope_name end_time
                role_name=$(echo "$assignment" | jq -r '.properties.expandedProperties.roleDefinition.displayName // "Unknown Role"')
                scope_name=$(echo "$assignment" | jq -r '.properties.expandedProperties.scope.displayName // "Unknown"')
                end_time=$(echo "$assignment" | jq -r '.properties.endDateTime // "Permanent"')
                gum style --foreground 35 "    • $role_name @ $scope_name"
                gum style --foreground 245 "      Expires: $end_time"
            done < <(echo "$active" | jq -c '.[]')
            echo ""
        fi
    fi

    # Group (PIM groups)
    if [[ "$scope" == "all" || "$scope" == "group" ]]; then
        local graph_token user_id
        graph_token=$(get_graph_token 2>/dev/null) || graph_token=""

        if [[ -n "$graph_token" ]]; then
            user_id=$(get_graph_user_id 2>/dev/null) || user_id=""

            if [[ -n "$user_id" ]]; then
                local group_url="https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?\$filter=principalId%20eq%20%27${user_id}%27"

                local group_result
                group_result=$(gum spin --spinner dot --title "Fetching active PIM groups..." -- \
                    curl -s -X GET -H "Authorization: Bearer $graph_token" -H "Content-Type: application/json" "$group_url") || group_result=""

                if [[ -n "$group_result" ]] && ! echo "$group_result" | jq -e '.error' &>/dev/null; then
                    local group_count
                    group_count=$(echo "$group_result" | jq '.value | length // 0')

                    if [[ "$group_count" -gt 0 ]]; then
                        has_results=true

                        gum style --foreground 252 --italic "  PIM Groups ($group_count):"
                        while IFS= read -r item; do
                            local group_id access_id group_name end_time
                            group_id=$(echo "$item" | jq -r '.groupId')
                            access_id=$(echo "$item" | jq -r '.accessId')
                            end_time=$(echo "$item" | jq -r '.endDateTime // "Permanent"')

                            # Fetch group name
                            group_name=$(curl -s -X GET \
                                -H "Authorization: Bearer $graph_token" \
                                -H "Content-Type: application/json" \
                                "https://graph.microsoft.com/v1.0/groups/${group_id}?\$select=displayName" 2>/dev/null | jq -r '.displayName // "Unknown Group"')

                            gum style --foreground 35 "    • $group_name ($access_id)"
                            gum style --foreground 245 "      Expires: $end_time"
                        done < <(echo "$group_result" | jq -c '.value[]')
                        echo ""
                    fi
                fi
            fi
        elif [[ "$scope" == "group" ]]; then
            gum style --foreground 214 "Not logged in to Graph API. Run 'pim login' first."
            return 1
        fi
    fi

    if [[ "$has_results" == "false" ]]; then
        gum style --foreground 214 "No active assignments found."
    fi
}

do_activate() {
    local scope="$1"

    gum style --bold --foreground 212 "Activate Assignment"
    echo ""

    # Collect all eligible assignments based on scope
    local options=()
    local assignment_types=()
    local assignment_data=()
    local i=0

    # Tenant (Entra ID directory roles)
    if [[ "$scope" == "all" || "$scope" == "tenant" ]]; then
        local graph_token graph_user_id dir_assignments
        graph_token=$(get_graph_token 2>/dev/null) || graph_token=""

        if [[ -n "$graph_token" ]]; then
            graph_user_id=$(get_graph_user_id 2>/dev/null) || graph_user_id=""

            if [[ -n "$graph_user_id" ]]; then
                local dir_url="https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?\$filter=principalId%20eq%20%27${graph_user_id}%27&\$expand=roleDefinition"

                dir_assignments=$(gum spin --spinner dot --title "Fetching Entra ID roles..." -- \
                    curl -s -X GET -H "Authorization: Bearer $graph_token" -H "Content-Type: application/json" "$dir_url") || dir_assignments=""

                if [[ -n "$dir_assignments" ]] && ! echo "$dir_assignments" | jq -e '.error' &>/dev/null; then
                    while IFS= read -r assignment; do
                        local role_name
                        role_name=$(echo "$assignment" | jq -r '.roleDefinition.displayName // "Unknown Role"')
                        options+=("$((i + 1)). [Tenant] $role_name")
                        assignment_types+=("tenant")
                        assignment_data+=("$assignment")
                        i=$((i + 1))
                    done < <(echo "$dir_assignments" | jq -c '.value[]')
                fi
            fi
        elif [[ "$scope" == "tenant" ]]; then
            gum style --foreground 214 "Not logged in to Graph API. Run 'pim login' first."
            return 1
        fi
    fi

    # Role (Azure subscription roles)
    if [[ "$scope" == "all" || "$scope" == "role" ]]; then
        check_az
        check_login

        local user_id group_ids subscription_id
        user_id=$(get_current_user_id)
        group_ids=$(get_user_group_ids)
        subscription_id=$(get_subscription_id)

        local url="https://management.azure.com/subscriptions/$subscription_id/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01"

        local all_assignments
        all_assignments=$(gum spin --spinner dot --title "Fetching Azure roles..." -- \
            az rest --method GET --url "$url" 2>/dev/null) || {
            gum style --foreground 196 "Failed to fetch Azure role assignments"
            return 1
        }

        local principal_ids="$user_id $group_ids"
        local jq_filter='[.value[] | select('
        local first=true
        for pid in $principal_ids; do
            if [[ -n "$pid" ]]; then
                if [[ "$first" == "true" ]]; then
                    jq_filter+=".properties.principalId == \"$pid\""
                    first=false
                else
                    jq_filter+=" or .properties.principalId == \"$pid\""
                fi
            fi
        done
        jq_filter+=')]'

        local assignments
        assignments=$(echo "$all_assignments" | jq "$jq_filter")

        while IFS= read -r assignment; do
            local role_name scope_name
            role_name=$(echo "$assignment" | jq -r '.properties.expandedProperties.roleDefinition.displayName // "Unknown Role"')
            scope_name=$(echo "$assignment" | jq -r '.properties.expandedProperties.scope.displayName // "Unknown"')
            options+=("$((i + 1)). [Role] $role_name @ $scope_name")
            assignment_types+=("role")
            assignment_data+=("$assignment")
            i=$((i + 1))
        done < <(echo "$assignments" | jq -c '.[]')
    fi

    # Group (PIM groups)
    if [[ "$scope" == "all" || "$scope" == "group" ]]; then
        local graph_token user_id
        graph_token=$(get_graph_token 2>/dev/null) || graph_token=""

        if [[ -n "$graph_token" ]]; then
            user_id=$(get_graph_user_id 2>/dev/null) || user_id=""

            if [[ -n "$user_id" ]]; then
                local group_url="https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?\$filter=principalId%20eq%20%27${user_id}%27"

                local group_result
                group_result=$(gum spin --spinner dot --title "Fetching PIM groups..." -- \
                    curl -s -X GET -H "Authorization: Bearer $graph_token" -H "Content-Type: application/json" "$group_url") || group_result=""

                if [[ -n "$group_result" ]] && ! echo "$group_result" | jq -e '.error' &>/dev/null; then
                    while IFS= read -r item; do
                        local group_id access_id group_name
                        group_id=$(echo "$item" | jq -r '.groupId')
                        access_id=$(echo "$item" | jq -r '.accessId')

                        group_name=$(curl -s -X GET \
                            -H "Authorization: Bearer $graph_token" \
                            -H "Content-Type: application/json" \
                            "https://graph.microsoft.com/v1.0/groups/${group_id}?\$select=displayName" 2>/dev/null | jq -r '.displayName // "Unknown Group"')

                        options+=("$((i + 1)). [Group] $group_name ($access_id)")
                        assignment_types+=("group")
                        assignment_data+=("$item")
                        i=$((i + 1))
                    done < <(echo "$group_result" | jq -c '.value[]')
                fi
            fi
        elif [[ "$scope" == "group" ]]; then
            gum style --foreground 214 "Not logged in to Graph API. Run 'pim login' first."
            return 1
        fi
    fi

    if [[ ${#options[@]} -eq 0 ]]; then
        gum style --foreground 214 "No eligible assignments found."
        return 0
    fi

    # Use gum choose for selection
    local selection
    selection=$(printf '%s\n' "${options[@]}" | gum choose --header "Select assignment to activate:")

    if [[ -z "$selection" ]]; then
        gum style --foreground 214 "Cancelled."
        return 0
    fi

    local sel_index
    sel_index=$(echo "$selection" | cut -d'.' -f1)
    local arr_index=$((sel_index - 1))

    # Get duration
    local duration
    duration=$(gum input --placeholder "$DEFAULT_DURATION_HOURS" --header "Duration in hours (1-$MAX_DURATION_HOURS):" --value "$DEFAULT_DURATION_HOURS")
    if [[ -z "$duration" ]]; then
        duration=$DEFAULT_DURATION_HOURS
    fi
    if ! [[ "$duration" =~ ^[0-9]+$ ]] || [[ "$duration" -lt 1 ]] || [[ "$duration" -gt "$MAX_DURATION_HOURS" ]]; then
        gum style --foreground 196 "Invalid duration. Must be between 1 and $MAX_DURATION_HOURS hours."
        return 1
    fi

    # Get justification
    local justification
    justification=$(gum input --placeholder "Enter justification..." --header "Justification (required):" --width 60)
    if [[ -z "$justification" ]]; then
        gum style --foreground 196 "Justification is required"
        return 1
    fi

    echo ""

    # Activate based on type
    case "${assignment_types[$arr_index]}" in
        tenant)
            activate_directory_role "${assignment_data[$arr_index]}" "$duration" "$justification"
            ;;
        role)
            local assignment="${assignment_data[$arr_index]}"
            local role_def_id scope principal_id role_name schedule_id

            role_def_id=$(echo "$assignment" | jq -r '.properties.roleDefinitionId')
            scope=$(echo "$assignment" | jq -r '.properties.scope')
            principal_id=$(echo "$assignment" | jq -r '.properties.principalId')
            role_name=$(echo "$assignment" | jq -r '.properties.expandedProperties.roleDefinition.displayName // "Unknown Role"')
            schedule_id=$(echo "$assignment" | jq -r '.properties.roleEligibilityScheduleId')

            local request_guid
            request_guid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)

            local request_body
            request_body=$(jq -n \
                --arg principalId "$principal_id" \
                --arg roleDefinitionId "$role_def_id" \
                --arg scheduleId "$schedule_id" \
                --arg justification "$justification" \
                --arg duration "PT${duration}H" \
                '{
                    properties: {
                        principalId: $principalId,
                        roleDefinitionId: $roleDefinitionId,
                        requestType: "SelfActivate",
                        linkedRoleEligibilityScheduleId: $scheduleId,
                        justification: $justification,
                        scheduleInfo: {
                            expiration: {
                                type: "AfterDuration",
                                duration: $duration
                            }
                        }
                    }
                }')

            local api_url="https://management.azure.com${scope}/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/${request_guid}?api-version=2020-10-01"

            local result
            result=$(gum spin --spinner dot --title "Activating $role_name..." -- \
                az rest --method PUT --url "$api_url" --headers "Content-Type=application/json" --body "$request_body" 2>&1) || {
                local error_msg
                error_msg=$(echo "$result" | grep -oP '"message"\s*:\s*"\K[^"]+' | head -1 || echo "$result")
                gum style --foreground 196 "Failed to activate role: $error_msg"
                return 1
            }

            local status
            status=$(echo "$result" | jq -r '.properties.status // "Unknown"')

            if [[ "$status" == "Provisioned" ]] || [[ "$status" == "PendingApproval" ]] || [[ "$status" == "Granted" ]]; then
                gum style --foreground 35 --bold "✓ Role activation request submitted successfully!"
                gum style --foreground 33 "Status: $status"
                if [[ "$status" == "PendingApproval" ]]; then
                    gum style --foreground 214 "This role requires approval. Please wait for an approver to approve your request."
                fi
            else
                gum style --foreground 214 "Activation request status: $status"
            fi
            ;;
        group)
            local item="${assignment_data[$arr_index]}"
            local graph_token group_id access_id principal_id group_name

            graph_token=$(get_graph_token) || return 1
            group_id=$(echo "$item" | jq -r '.groupId')
            access_id=$(echo "$item" | jq -r '.accessId')
            principal_id=$(echo "$item" | jq -r '.principalId')

            group_name=$(curl -s -X GET \
                -H "Authorization: Bearer $graph_token" \
                -H "Content-Type: application/json" \
                "https://graph.microsoft.com/v1.0/groups/${group_id}?\$select=displayName" 2>/dev/null | jq -r '.displayName // "Unknown Group"')

            local request_body
            request_body=$(jq -n \
                --arg principalId "$principal_id" \
                --arg groupId "$group_id" \
                --arg accessId "$access_id" \
                --arg justification "$justification" \
                --arg duration "PT${duration}H" \
                '{
                    action: "selfActivate",
                    principalId: $principalId,
                    groupId: $groupId,
                    accessId: $accessId,
                    justification: $justification,
                    scheduleInfo: {
                        expiration: {
                            type: "afterDuration",
                            duration: $duration
                        }
                    }
                }')

            local result
            result=$(gum spin --spinner dot --title "Activating $group_name..." -- \
                curl -s -X POST \
                -H "Authorization: Bearer $graph_token" \
                -H "Content-Type: application/json" \
                -d "$request_body" \
                "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleRequests") || {
                gum style --foreground 196 "Failed to activate group membership"
                return 1
            }

            if echo "$result" | jq -e '.error' &>/dev/null; then
                local error_msg
                error_msg=$(echo "$result" | jq -r '.error.message // "Unknown error"')
                gum style --foreground 196 "Failed to activate group: $error_msg"
                return 1
            fi

            local status
            status=$(echo "$result" | jq -r '.status // "Unknown"')

            if [[ "$status" == "Provisioned" ]] || [[ "$status" == "PendingApproval" ]] || [[ "$status" == "Granted" ]]; then
                gum style --foreground 35 --bold "✓ Group activation request submitted successfully!"
                gum style --foreground 33 "Status: $status"
            else
                gum style --foreground 214 "Activation request status: $status"
            fi
            ;;
    esac
}

do_deactivate() {
    local scope="$1"

    gum style --bold --foreground 212 "Deactivate Assignment"
    echo ""

    # Collect all active assignments based on scope
    local options=()
    local assignment_types=()
    local assignment_data=()
    local i=0

    # Tenant (Entra ID directory roles)
    if [[ "$scope" == "all" || "$scope" == "tenant" ]]; then
        local graph_token graph_user_id dir_active
        graph_token=$(get_graph_token 2>/dev/null) || graph_token=""

        if [[ -n "$graph_token" ]]; then
            graph_user_id=$(get_graph_user_id 2>/dev/null) || graph_user_id=""

            if [[ -n "$graph_user_id" ]]; then
                local dir_url="https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?\$filter=principalId%20eq%20%27${graph_user_id}%27%20and%20assignmentType%20eq%20%27Activated%27&\$expand=roleDefinition"

                dir_active=$(gum spin --spinner dot --title "Fetching active Entra ID roles..." -- \
                    curl -s -X GET -H "Authorization: Bearer $graph_token" -H "Content-Type: application/json" "$dir_url") || dir_active=""

                if [[ -n "$dir_active" ]] && ! echo "$dir_active" | jq -e '.error' &>/dev/null; then
                    while IFS= read -r assignment; do
                        local role_name
                        role_name=$(echo "$assignment" | jq -r '.roleDefinition.displayName // "Unknown Role"')
                        options+=("$((i + 1)). [Tenant] $role_name")
                        assignment_types+=("tenant")
                        assignment_data+=("$assignment")
                        i=$((i + 1))
                    done < <(echo "$dir_active" | jq -c '.value[]')
                fi
            fi
        elif [[ "$scope" == "tenant" ]]; then
            gum style --foreground 214 "Not logged in to Graph API. Run 'pim login' first."
            return 1
        fi
    fi

    # Role (Azure subscription roles)
    if [[ "$scope" == "all" || "$scope" == "role" ]]; then
        check_az
        check_login

        local user_id group_ids subscription_id
        user_id=$(get_current_user_id)
        group_ids=$(get_user_group_ids)
        subscription_id=$(get_subscription_id)

        local url="https://management.azure.com/subscriptions/$subscription_id/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=2020-10-01"

        local all_active
        all_active=$(gum spin --spinner dot --title "Fetching active Azure roles..." -- \
            az rest --method GET --url "$url" 2>/dev/null) || {
            gum style --foreground 196 "Failed to fetch active Azure role assignments"
            return 1
        }

        local principal_ids="$user_id $group_ids"
        local jq_filter='[.value[] | select((.properties.assignmentType == "Activated") and ('
        local first=true
        for pid in $principal_ids; do
            if [[ -n "$pid" ]]; then
                if [[ "$first" == "true" ]]; then
                    jq_filter+=".properties.principalId == \"$pid\""
                    first=false
                else
                    jq_filter+=" or .properties.principalId == \"$pid\""
                fi
            fi
        done
        jq_filter+='))]'

        local active
        active=$(echo "$all_active" | jq "$jq_filter")

        while IFS= read -r assignment; do
            local role_name scope_name
            role_name=$(echo "$assignment" | jq -r '.properties.expandedProperties.roleDefinition.displayName // "Unknown Role"')
            scope_name=$(echo "$assignment" | jq -r '.properties.expandedProperties.scope.displayName // "Unknown"')
            options+=("$((i + 1)). [Role] $role_name @ $scope_name")
            assignment_types+=("role")
            assignment_data+=("$assignment")
            i=$((i + 1))
        done < <(echo "$active" | jq -c '.[]')
    fi

    # Group (PIM groups)
    if [[ "$scope" == "all" || "$scope" == "group" ]]; then
        local graph_token user_id
        graph_token=$(get_graph_token 2>/dev/null) || graph_token=""

        if [[ -n "$graph_token" ]]; then
            user_id=$(get_graph_user_id 2>/dev/null) || user_id=""

            if [[ -n "$user_id" ]]; then
                local group_url="https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?\$filter=principalId%20eq%20%27${user_id}%27"

                local group_result
                group_result=$(gum spin --spinner dot --title "Fetching active PIM groups..." -- \
                    curl -s -X GET -H "Authorization: Bearer $graph_token" -H "Content-Type: application/json" "$group_url") || group_result=""

                if [[ -n "$group_result" ]] && ! echo "$group_result" | jq -e '.error' &>/dev/null; then
                    while IFS= read -r item; do
                        local group_id access_id group_name
                        group_id=$(echo "$item" | jq -r '.groupId')
                        access_id=$(echo "$item" | jq -r '.accessId')

                        group_name=$(curl -s -X GET \
                            -H "Authorization: Bearer $graph_token" \
                            -H "Content-Type: application/json" \
                            "https://graph.microsoft.com/v1.0/groups/${group_id}?\$select=displayName" 2>/dev/null | jq -r '.displayName // "Unknown Group"')

                        options+=("$((i + 1)). [Group] $group_name ($access_id)")
                        assignment_types+=("group")
                        assignment_data+=("$item")
                        i=$((i + 1))
                    done < <(echo "$group_result" | jq -c '.value[]')
                fi
            fi
        elif [[ "$scope" == "group" ]]; then
            gum style --foreground 214 "Not logged in to Graph API. Run 'pim login' first."
            return 1
        fi
    fi

    if [[ ${#options[@]} -eq 0 ]]; then
        gum style --foreground 214 "No active assignments to deactivate."
        return 0
    fi

    # Use gum choose for selection
    local selection
    selection=$(printf '%s\n' "${options[@]}" | gum choose --header "Select assignment to deactivate:")

    if [[ -z "$selection" ]]; then
        gum style --foreground 214 "Cancelled."
        return 0
    fi

    local sel_index
    sel_index=$(echo "$selection" | cut -d'.' -f1)
    local arr_index=$((sel_index - 1))

    echo ""

    # Deactivate based on type
    case "${assignment_types[$arr_index]}" in
        tenant)
            deactivate_directory_role "${assignment_data[$arr_index]}"
            ;;
        role)
            local assignment="${assignment_data[$arr_index]}"
            local role_def_id scope principal_id role_name

            role_def_id=$(echo "$assignment" | jq -r '.properties.roleDefinitionId')
            scope=$(echo "$assignment" | jq -r '.properties.scope')
            principal_id=$(echo "$assignment" | jq -r '.properties.principalId')
            role_name=$(echo "$assignment" | jq -r '.properties.expandedProperties.roleDefinition.displayName // "Unknown Role"')

            local request_guid
            request_guid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)

            local request_body
            request_body=$(jq -n \
                --arg principalId "$principal_id" \
                --arg roleDefinitionId "$role_def_id" \
                '{
                    properties: {
                        principalId: $principalId,
                        roleDefinitionId: $roleDefinitionId,
                        requestType: "SelfDeactivate"
                    }
                }')

            local api_url="https://management.azure.com${scope}/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/${request_guid}?api-version=2020-10-01"

            local result
            result=$(gum spin --spinner dot --title "Deactivating $role_name..." -- \
                az rest --method PUT --url "$api_url" --headers "Content-Type=application/json" --body "$request_body" 2>&1) || {
                gum style --foreground 196 "Failed to deactivate role"
                echo "$result"
                return 1
            }

            gum style --foreground 35 --bold "✓ Role deactivated successfully!"
            ;;
        group)
            local item="${assignment_data[$arr_index]}"
            local graph_token group_id access_id principal_id group_name

            graph_token=$(get_graph_token) || return 1
            group_id=$(echo "$item" | jq -r '.groupId')
            access_id=$(echo "$item" | jq -r '.accessId')
            principal_id=$(echo "$item" | jq -r '.principalId')

            group_name=$(curl -s -X GET \
                -H "Authorization: Bearer $graph_token" \
                -H "Content-Type: application/json" \
                "https://graph.microsoft.com/v1.0/groups/${group_id}?\$select=displayName" 2>/dev/null | jq -r '.displayName // "Unknown Group"')

            local request_body
            request_body=$(jq -n \
                --arg principalId "$principal_id" \
                --arg groupId "$group_id" \
                --arg accessId "$access_id" \
                '{
                    action: "selfDeactivate",
                    principalId: $principalId,
                    groupId: $groupId,
                    accessId: $accessId
                }')

            local result
            result=$(gum spin --spinner dot --title "Deactivating $group_name..." -- \
                curl -s -X POST \
                -H "Authorization: Bearer $graph_token" \
                -H "Content-Type: application/json" \
                -d "$request_body" \
                "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleRequests") || {
                gum style --foreground 196 "Failed to deactivate group membership"
                return 1
            }

            if echo "$result" | jq -e '.error' &>/dev/null; then
                local error_msg
                error_msg=$(echo "$result" | jq -r '.error.message // "Unknown error"')
                gum style --foreground 196 "Failed to deactivate group: $error_msg"
                return 1
            fi

            gum style --foreground 35 --bold "✓ Group deactivated successfully!"
            ;;
    esac
}

#------------------------------------------------------------------------------
# Help and Usage
#------------------------------------------------------------------------------

show_help() {
    gum style --foreground 212 --bold '
██████╗ ██╗███╗   ███╗██╗     ███████╗██████╗
██╔══██╗██║████╗ ████║██║     ██╔════╝██╔══██╗
██████╔╝██║██╔████╔██║██║     █████╗  ██████╔╝
██╔═══╝ ██║██║╚██╔╝██║██║     ██╔══╝  ██╔══██╗
██║     ██║██║ ╚═╝ ██║███████╗███████╗██║  ██║
╚═╝     ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝'
    echo ""
    gum style --foreground 252 "Azure PIM (Privileged Identity Management) CLI Tool"
    echo ""
    gum style --bold --foreground 33 "USAGE:"
    echo "    pim <action> [scope]"
    echo ""
    gum style --bold --foreground 33 "ACTIONS:"
    echo "    list, l         List eligible assignments"
    echo "    active          List active assignments"
    echo "    activate, a     Activate an eligible assignment"
    echo "    deactivate, d   Deactivate an active assignment"
    echo ""
    gum style --bold --foreground 33 "SCOPES:"
    echo "    all             All types (default)"
    echo "    tenant, t       Entra ID directory roles"
    echo "    role, r         Azure subscription roles"
    echo "    group, g        PIM groups"
    echo ""
    gum style --bold --foreground 33 "SHORTHAND:"
    echo "    lt, lr, lg      List eligible (tenant/role/group)"
    echo "    la              List active (all)"
    echo "    lat, lar, lag   List active (tenant/role/group)"
    echo "    at, ar, ag      Activate (tenant/role/group)"
    echo "    dt, dr, dg      Deactivate (tenant/role/group)"
    echo ""
    gum style --bold --foreground 33 "SETUP (one-time):"
    echo "    setup           Create app registration for PIM permissions"
    echo "    grant-consent   Grant admin consent for the app (requires admin)"
    echo "    login           Authenticate with PIM permissions"
    echo ""
    gum style --bold --foreground 33 "UTILITY:"
    echo "    install         Install pim to ~/.local/bin"
    echo "    uninstall       Remove pim and optionally config"
    echo "    completions     Manage shell tab completions"
    echo "    help, h         Show this help message"
    echo ""
    gum style --bold --foreground 33 "EXAMPLES:"
    echo "    pim l               # List all eligible assignments"
    echo "    pim lt              # List eligible tenant roles"
    echo "    pim la              # List all active assignments"
    echo "    pim lat             # List active tenant roles"
    echo "    pim a               # Activate any assignment"
    echo "    pim ag              # Activate a group membership"
    echo "    pim dr              # Deactivate an Azure role"
    echo ""
    gum style --bold --foreground 33 "FIRST-TIME SETUP:"
    echo "    1. az login                 # Login to Azure CLI"
    echo "    2. pim setup                # Create app registration"
    echo "    3. pim grant-consent        # Grant permissions (requires admin)"
    echo "    4. pim login                # Authenticate"
}

#------------------------------------------------------------------------------
# Main Entry Point
#------------------------------------------------------------------------------

# Parse scope argument and normalize it
parse_scope() {
    local scope="${1:-all}"
    case "$scope" in
        all|a)      echo "all" ;;
        tenant|t)   echo "tenant" ;;
        role|r)     echo "role" ;;
        group|g)    echo "group" ;;
        *)          echo "unknown" ;;
    esac
}

# Parse combined shorthand commands like "lt", "ag", "dr", "lat", "lar", "lag"
parse_shorthand() {
    local cmd="$1"
    local action="" scope=""

    # Check for 3-char shorthand for list active (e.g., "lat", "lar", "lag")
    if [[ ${#cmd} -eq 3 && "${cmd:0:2}" == "la" ]]; then
        local third="${cmd:2:1}"
        case "$third" in
            t) echo "list_active tenant"; return ;;
            r) echo "list_active role"; return ;;
            g) echo "list_active group"; return ;;
            *) echo "unknown"; return ;;
        esac
    fi

    # Check for 2-char shorthand (e.g., "lt", "ag", "dr", "la")
    if [[ ${#cmd} -eq 2 ]]; then
        local first="${cmd:0:1}"
        local second="${cmd:1:1}"

        # Special case: "la" = list active all
        if [[ "$first" == "l" && "$second" == "a" ]]; then
            echo "list_active all"
            return
        fi

        # Parse action
        case "$first" in
            l) action="list" ;;
            a) action="activate" ;;
            d) action="deactivate" ;;
            *) echo "unknown"; return ;;
        esac

        # Parse scope
        case "$second" in
            t) scope="tenant" ;;
            r) scope="role" ;;
            g) scope="group" ;;
            e)
                # "le" = list eligible (same as list all)
                if [[ "$first" == "l" ]]; then
                    scope="all"
                else
                    echo "unknown"; return
                fi
                ;;
            *) echo "unknown"; return ;;
        esac

        echo "$action $scope"
    else
        echo "unknown"
    fi
}

main() {
    check_dependencies

    local command="${1:-help}"
    shift || true

    # Try to parse as shorthand first (e.g., "lt", "ag", "la", "lat")
    local parsed
    parsed=$(parse_shorthand "$command")
    if [[ "$parsed" != "unknown" ]]; then
        local action scope
        read -r action scope <<< "$parsed"
        case "$action" in
            list)        do_list "$scope" ;;
            list_active) do_list_active "$scope" ;;
            activate)    do_activate "$scope" ;;
            deactivate)  do_deactivate "$scope" ;;
        esac
        return
    fi

    case "$command" in
        # Setup commands
        setup)
            check_login
            setup_app_registration
            ;;
        grant-consent)
            check_login
            grant_admin_consent
            ;;
        login)
            do_device_code_login
            ;;

        # Main commands with scope support
        list|l)
            local scope
            scope=$(parse_scope "${1:-all}")
            if [[ "$scope" == "unknown" ]]; then
                gum style --foreground 196 "Unknown scope: $1"
                echo "Valid scopes: all, tenant, role, group (or a, t, r, g)"
                exit 1
            fi
            do_list "$scope"
            ;;
        active)
            local scope
            scope=$(parse_scope "${1:-all}")
            if [[ "$scope" == "unknown" ]]; then
                gum style --foreground 196 "Unknown scope: $1"
                echo "Valid scopes: all, tenant, role, group (or a, t, r, g)"
                exit 1
            fi
            do_list_active "$scope"
            ;;
        activate|a)
            local scope
            scope=$(parse_scope "${1:-all}")
            if [[ "$scope" == "unknown" ]]; then
                gum style --foreground 196 "Unknown scope: $1"
                echo "Valid scopes: all, tenant, role, group (or a, t, r, g)"
                exit 1
            fi
            do_activate "$scope"
            ;;
        deactivate|d)
            local scope
            scope=$(parse_scope "${1:-all}")
            if [[ "$scope" == "unknown" ]]; then
                gum style --foreground 196 "Unknown scope: $1"
                echo "Valid scopes: all, tenant, role, group (or a, t, r, g)"
                exit 1
            fi
            do_deactivate "$scope"
            ;;

        # Installation commands
        install)
            do_install
            ;;
        uninstall)
            do_uninstall
            ;;
        completions)
            handle_completions "$@"
            ;;

        # Help
        help|h|--help|-h)
            show_help
            ;;
        *)
            gum style --foreground 196 "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
