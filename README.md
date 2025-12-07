# pim

**Stop clicking through the Azure Portal. Activate your PIM roles from the terminal like a civilized engineer.**

```
$ pim activate
? Select role to activate:
> 1. Contributor @ my-subscription
  2. Reader @ my-resource-group

? Duration in hours (1-8): 1
? Justification: Deploying hotfix

✓ Role activation request submitted successfully!
Status: Provisioned
```

pim is a blazingly fast CLI for Azure Privileged Identity Management (PIM). Activate roles, manage group memberships, and get back to actual work in seconds instead of minutes.

## Why?

Because activating a PIM role in the Azure Portal requires:
1. Opening a browser
2. Logging in (again)
3. Navigating to PIM
4. Finding your role
5. Clicking "Activate"
6. Entering a justification
7. Clicking "Activate" again
8. Waiting for the page to reload
9. Wondering if it actually worked

With pim:
```
$ pim a
```

Done.

## Features

- **Role Management** - List, activate, and deactivate Azure resource roles
- **Group Management** - Manage PIM-enabled group memberships
- **Interactive Mode** - Beautiful TUI powered by [gum](https://github.com/charmbracelet/gum)
- **Fast** - Batch API calls, token caching, minimal overhead
- **Secure** - No secrets stored, uses device code auth, tokens in system keyring

## Installation

### Prerequisites

- [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli) (`az`)
- [jq](https://stedolan.github.io/jq/) - JSON processor
- [gum](https://github.com/charmbracelet/gum) - Fancy CLI components
- `curl`

### Install

```bash
# Clone the repo
git clone https://github.com/robert-inviol/pimler.git
cd pimler

# Run the installer
./pim.sh install
```

The installer will:
- Check all dependencies
- Symlink or copy to `~/.local/bin`
- Install shell completions (bash/zsh)

### First-time Setup

```bash
# Login to Azure CLI first
az login

# Setup creates an app registration for PIM access
pim setup

# Grant admin consent (requires admin, or ask your admin)
pim grant-consent

# Authenticate pim
pim login
```

## Usage

### Roles (Azure Resources)

```bash
# List your eligible roles
pim list

# Activate a role (interactive - select role, duration, justification)
pim activate

# List currently active roles
pim active

# Deactivate a role (interactive)
pim deactivate
```

### Groups (Azure AD)

```bash
# List eligible group memberships
pim groups

# Activate group membership (interactive)
pim groups activate

# List active group memberships
pim groups active

# Deactivate group membership (interactive)
pim groups deactivate
```

### Command Reference

| Command | Alias | Description |
|---------|-------|-------------|
| `list` | `ls` | List eligible roles |
| `activate` | `a` | Activate a role (interactive) |
| `active` | | List active roles |
| `deactivate` | `d` | Deactivate a role (interactive) |
| `groups` | | List eligible groups |
| `groups active` | | List active groups |
| `groups activate` | `groups a` | Activate group membership |
| `groups deactivate` | `groups d` | Deactivate group membership |
| `help` | `h` | Show help |

## How It Works

pim uses:
- **Azure CLI** (`az rest`) for Azure Resource Manager PIM APIs
- **Microsoft Graph API** for Azure AD group PIM operations
- **Device code flow** for authentication (no secrets needed)
- **System keyring** (`secret-tool`) for secure token storage when available

## Configuration

Config is stored in `~/.config/pim/`:
- `app.json` - App registration details
- `token.json` - Cached access tokens

## Uninstall

```bash
pim uninstall
```

This removes the binary, completions, and optionally the config directory.

## License

MIT

## Contributing

PRs welcome. Please keep it simple - this is a CLI tool, not a framework.
