#!/usr/bin/env python3
"""
RedTeamIQ — Step 3: create the Foundry project connection to the KB's MCP endpoint.

Creates a `RemoteTool` connection on the Foundry project that uses the project's
managed identity to reach the knowledge base's MCP endpoint. The backend's MCPTool
references this connection by name (PROJECT_CONNECTION_NAME).

Reads config from environment (source setup.env first). Uses your Azure login
(DefaultAzureCredential) for the Azure Resource Manager call.

Run:  source ./setup.env && python 03_create_connection.py
"""
import os
import sys

import requests
from azure.identity import DefaultAzureCredential, get_bearer_token_provider


def env(name: str, default: str = "") -> str:
    val = os.environ.get(name, default)
    if not val:
        sys.exit(f"✗ Missing required env var: {name} (source setup.env first)")
    return val


PROJECT_RESOURCE_ID = env("PROJECT_RESOURCE_ID")
PROJECT_CONNECTION_NAME = env("PROJECT_CONNECTION_NAME", "redteamiq-kb-mcp")
SEARCH_ENDPOINT = env("SEARCH_ENDPOINT").rstrip("/")
KNOWLEDGE_BASE_NAME = env("KNOWLEDGE_BASE_NAME", "redteamiq-kb")
KB_API_VERSION = env("KB_API_VERSION", "2026-05-01-preview")
ARM_API_VERSION = os.environ.get("ARM_CONNECTION_API_VERSION", "2025-10-01-preview")

mcp_endpoint = f"{SEARCH_ENDPOINT}/knowledgebases/{KNOWLEDGE_BASE_NAME}/mcp?api-version={KB_API_VERSION}"

credential = DefaultAzureCredential()
token = get_bearer_token_provider(credential, "https://management.azure.com/.default")()

url = (
    f"https://management.azure.com{PROJECT_RESOURCE_ID}"
    f"/connections/{PROJECT_CONNECTION_NAME}?api-version={ARM_API_VERSION}"
)
body = {
    "name": PROJECT_CONNECTION_NAME,
    "type": "Microsoft.MachineLearningServices/workspaces/connections",
    "properties": {
        "authType": "ProjectManagedIdentity",
        "category": "RemoteTool",
        "target": mcp_endpoint,
        "isSharedToAll": True,
        "audience": "https://search.azure.com/",
        "metadata": {"ApiType": "Azure"},
    },
}

resp = requests.put(url, headers={"Authorization": f"Bearer {token}"}, json=body)
if resp.status_code not in (200, 201):
    sys.exit(f"✗ Connection create failed [{resp.status_code}]: {resp.text}")

print(f"✓ Project connection '{PROJECT_CONNECTION_NAME}' created/updated.")
print(f"  → backend .env: PROJECT_CONNECTION_NAME={PROJECT_CONNECTION_NAME}")
