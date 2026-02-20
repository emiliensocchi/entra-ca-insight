# 📦 Installation

This page summarizes the **installation** of CA Insight.

## Prerequisites

- **Python**: 3.8 or higher
- **Entra ID User**: with the following permissions or higher:

| Permission | Purpose |
|------------|-------|
| `Application.Read.All` | Read service principals and agent identities |
| `Group.Read.All` | Read group memberships |
| `Policy.Read.All` | Read Conditional Access policies |
| `PrivilegedAccess.Read.AzureAD` | Read PIM eligible role assignments (optional) |
| `RoleManagement.Read.All` | Read active role assignments |
| `User.Read.All` | Read user identities and profiles |


## Installation

Clone the repository:
```bash
git clone https://github.com/emiliensocchi/entra-ca-insight.git
```
Create a dedicated Python virtual environment for CA Insight:
```bash
cd entra-ca-insight
python -m venv cainsightenv
.\cainsightenv\Scripts\activate
```

Install dependencies:
```bash
pip install -r requirements.txt
```

Test the CLI interface:
```bash
python -m caInsight -h 
```

Start the WEB interface:
```bash
python .\web\api_server.py
```
