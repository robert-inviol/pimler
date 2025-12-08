# pim

**Stop clicking through the Azure Portal. Activate your PIM roles from the terminal like a civilized engineer.**

```
$ pim a
? Select assignment to activate:
> 1. [Tenant] Global Reader
  2. [Role] Contributor @ my-subscription
  3. [Group] Security Admins (member)

? Duration in hours (1-8): 1
? Justification: Deploying hotfix

✓ Role activation request submitted successfully!
Status: Provisioned
```

pim is a blazingly fast CLI for Azure Privileged Identity Management (PIM). Activate Entra ID roles, Azure subscription roles, and group memberships - all from one unified interface.

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

- **Unified Interface** - Manage Entra ID tenant roles, Azure subscription roles, and PIM groups from one command
- **Shorthand Commands** - `pim lt` (list tenant), `pim ag` (activate group), `pim la` (list active)
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

```
pim <action> [scope]
```

### Actions

| Action | Alias | Description |
|--------|-------|-------------|
| `list` | `l` | List eligible assignments |
| `active` | | List active assignments |
| `activate` | `a` | Activate an eligible assignment |
| `deactivate` | `d` | Deactivate an active assignment |

### Scopes

| Scope | Alias | Description |
|-------|-------|-------------|
| `all` | | All types (default) |
| `tenant` | `t` | Entra ID directory roles |
| `role` | `r` | Azure subscription roles |
| `group` | `g` | PIM groups |

### Shorthand

Combine action + scope into 2-3 characters:

| Shorthand | Description |
|-----------|-------------|
| `pim lt` | List eligible tenant roles |
| `pim lr` | List eligible Azure roles |
| `pim lg` | List eligible PIM groups |
| `pim la` | List active (all) |
| `pim lat` | List active tenant roles |
| `pim lar` | List active Azure roles |
| `pim lag` | List active PIM groups |
| `pim at` | Activate tenant role |
| `pim ar` | Activate Azure role |
| `pim ag` | Activate group membership |
| `pim dt` | Deactivate tenant role |
| `pim dr` | Deactivate Azure role |
| `pim dg` | Deactivate group membership |

### Examples

```bash
# List all eligible assignments
pim list
pim l

# List only eligible Entra ID tenant roles
pim list tenant
pim lt

# List all active assignments
pim active
pim la

# List active Azure roles only
pim active role
pim lar

# Activate any assignment (interactive picker)
pim activate
pim a

# Activate only group memberships
pim activate group
pim ag

# Deactivate an Azure subscription role
pim deactivate role
pim dr
```

## How It Works

pim uses:
- **Azure CLI** (`az rest`) for Azure Resource Manager PIM APIs
- **Microsoft Graph API** for Entra ID tenant roles and PIM groups
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
