# RedTeamIQ — Foundry IQ setup runbook

Run these **once**, on the Azure machine where `az login` is signed in to the
subscription that holds `redteamiq-rg`. They stand up the Azure AI Search knowledge
base that powers Foundry IQ grounding and connect it to the Foundry project.

## ⚠️ Before you start — deploy an embedding model

A blob knowledge source **vectorizes** content during ingestion, so it needs an
**embedding deployment** in your Foundry resource. You currently only have two
`gpt-4.1-mini` chat deployments. Deploy an embedding model first:

```bash
az cognitiveservices account deployment create \
  -g redteamiq-rg -n redteamiq-hub \
  --deployment-name text-embedding-3-small \
  --model-name text-embedding-3-small --model-version "1" \
  --model-format OpenAI --sku-capacity 50 --sku-name Standard
```

(or deploy it from the Foundry portal). Without it, step 2 ingestion fails.

## Prerequisites
- `az login` complete; correct subscription selected.
- Foundry account `redteamiq-hub`, project `redteamiq-project`, and the
  `gpt-4.1-mini` deployments already exist.
- Python deps for the scripts: `pip install -r requirements.txt`
- Azure AI Search **Basic** tier (Free *may* work since we use API keys for the
  model connection, but Basic is the supported path for managed-identity access).

## Steps

```bash
cd backend/setup
cp setup.env.example setup.env      # then fill in SUBSCRIPTION_ID, AOAI_KEY, etc.
pip install -r requirements.txt

# 1) Provision storage + search + RBAC, and upload the 5 KB docs.
source ./setup.env && bash ./01_provision.sh
#    → paste the printed SEARCH_ENDPOINT / SEARCH_ADMIN_KEY / STORAGE_CONN /
#      PROJECT_RESOURCE_ID back into setup.env.

# 2) Create the knowledge source (ingest+vectorize) and the knowledge base.
source ./setup.env && python ./02_create_knowledge_base.py

# 3) Create the project → KB MCP connection.
source ./setup.env && python ./03_create_connection.py
```

## Then wire the backend
Put these in `backend/.env` :

```
PROJECT_ENDPOINT=<http://your-project-endpoint>
MODEL_EXECUTION=<model-name>
MODEL_REASONING=<model-name>
SEARCH_ENDPOINT=<http://your-search-endpoint>
KNOWLEDGE_BASE_NAME=<your-knowledge-base-name>
PROJECT_CONNECTION_NAME=<your-mcp-name>
PROJECT_RESOURCE_ID=<your-resource-ID>
```

When `SEARCH_ENDPOINT` + `KNOWLEDGE_BASE_NAME` + `PROJECT_CONNECTION_NAME` are all
set, the backend attaches the Foundry IQ `knowledge_base_retrieve` MCP tool to the
Attack Generator, Reasoning, and Report agents. If they're absent, it falls back to
injecting the local `/KB` docs in-context, so the pipeline still runs.

## Verify
```bash
cd backend && pip install -r requirements.txt && python main.py
curl localhost:5001/health      # → "foundry_iq": { "enabled": true, ... }
```

## RBAC quick reference (if step 1 warns)
| Identity | Role | Scope |
| --- | --- | --- |
| Search service managed identity | Cognitive Services User | Foundry account |
| **Foundry project** managed identity | Search Index Data Reader | Search service |
| You (operator) | Search Service Contributor | Search service |

## Teardown
Knowledge base + source aren't deleted with the agent/connection — remove them
explicitly: `DELETE {SEARCH_ENDPOINT}/knowledgebases/{knowledgebase-name}` and
`/knowledgesources/redteamiq-blob-ks` (api-version 2026-05-01-preview), then delete
the storage account and search service if no longer needed.
