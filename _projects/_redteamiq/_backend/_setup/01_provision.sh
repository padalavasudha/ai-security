#!/usr/bin/env bash
# ─── RedTeamIQ — Step 1: provision Azure resources for Foundry IQ ────────────
# Creates: Storage account + container (uploads /KB docs), Azure AI Search service
# (with managed identity), and the RBAC role assignments needed for agentic retrieval.
#
# Prereqs: az CLI logged in (`az login`), the Foundry account + project + model
# deployments already exist, and `setup.env` is filled in.
#
# Run from this directory:  source ./setup.env && ./01_provision.sh
set -euo pipefail

: "${SUBSCRIPTION_ID:?set in setup.env}"
: "${RESOURCE_GROUP:?}" ; : "${LOCATION:?}" ; : "${SEARCH_SERVICE:?}"
: "${STORAGE_ACCOUNT:?}" ; : "${BLOB_CONTAINER:?}" ; : "${FOUNDRY_ACCOUNT:?}"
: "${PROJECT_NAME:?}" ; : "${SEARCH_SKU:?}"

az account set --subscription "$SUBSCRIPTION_ID"
KB_DIR="$(cd "$(dirname "$0")/../../KB" && pwd)"
echo "▶ Using KB docs from: $KB_DIR"

# 1. Storage account + container, then upload the 5 KB markdown docs ----------
echo "▶ Creating storage account $STORAGE_ACCOUNT ..."
az storage account create -n "$STORAGE_ACCOUNT" -g "$RESOURCE_GROUP" -l "$LOCATION" \
  --sku Standard_LRS --kind StorageV2 --only-show-errors >/dev/null

STORAGE_CONN="$(az storage account show-connection-string -n "$STORAGE_ACCOUNT" \
  -g "$RESOURCE_GROUP" --query connectionString -o tsv)"

az storage container create -n "$BLOB_CONTAINER" --connection-string "$STORAGE_CONN" \
  --only-show-errors >/dev/null
echo "▶ Uploading KB docs to container $BLOB_CONTAINER ..."
az storage blob upload-batch -d "$BLOB_CONTAINER" -s "$KB_DIR" --pattern "*.md" \
  --connection-string "$STORAGE_CONN" --overwrite --only-show-errors >/dev/null

# 2. Azure AI Search service (Basic) with system-assigned managed identity ----
echo "▶ Creating Azure AI Search service $SEARCH_SERVICE ($SEARCH_SKU) ..."
az search service create -n "$SEARCH_SERVICE" -g "$RESOURCE_GROUP" -l "$LOCATION" \
  --sku "$SEARCH_SKU" --identity-type SystemAssigned --only-show-errors >/dev/null

SEARCH_ENDPOINT="https://${SEARCH_SERVICE}.search.windows.net"
SEARCH_ADMIN_KEY="$(az search admin-key show --service-name "$SEARCH_SERVICE" \
  -g "$RESOURCE_GROUP" --query primaryKey -o tsv)"
SEARCH_MI_PRINCIPAL="$(az search service show -n "$SEARCH_SERVICE" -g "$RESOURCE_GROUP" \
  --query identity.principalId -o tsv)"

# 3. Resource IDs we need for role assignments + the project connection -------
FOUNDRY_ID="$(az resource show -g "$RESOURCE_GROUP" -n "$FOUNDRY_ACCOUNT" \
  --resource-type 'Microsoft.CognitiveServices/accounts' --query id -o tsv)"
SEARCH_ID="$(az resource show -g "$RESOURCE_GROUP" -n "$SEARCH_SERVICE" \
  --resource-type 'Microsoft.Search/searchServices' --query id -o tsv)"
PROJECT_RESOURCE_ID="/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.CognitiveServices/accounts/${FOUNDRY_ACCOUNT}/projects/${PROJECT_NAME}"
CURRENT_USER="$(az ad signed-in-user show --query id -o tsv)"

# 4. RBAC -------------------------------------------------------------------
# Search MI must read the models (for ingestion verbalization + query planning).
echo "▶ Assigning roles ..."
az role assignment create --assignee-object-id "$SEARCH_MI_PRINCIPAL" \
  --assignee-principal-type ServicePrincipal \
  --role "Cognitive Services User" --scope "$FOUNDRY_ID" --only-show-errors >/dev/null || true

# You (the operator) need to create knowledge bases on the search service.
az role assignment create --assignee "$CURRENT_USER" \
  --role "Search Service Contributor" --scope "$SEARCH_ID" --only-show-errors >/dev/null || true
az role assignment create --assignee "$CURRENT_USER" \
  --role "Search Index Data Contributor" --scope "$SEARCH_ID" --only-show-errors >/dev/null || true

# NOTE: the Foundry PROJECT's managed identity needs "Search Index Data Reader"
# on the search service so the agent can query the KB at runtime. The project MI
# principal id isn't always available via CLI; assign it in the portal if the
# next line prints a warning.
PROJECT_MI="$(az resource show --id "$PROJECT_RESOURCE_ID" --query identity.principalId -o tsv 2>/dev/null || echo "")"
if [[ -n "$PROJECT_MI" ]]; then
  az role assignment create --assignee-object-id "$PROJECT_MI" \
    --assignee-principal-type ServicePrincipal \
    --role "Search Index Data Reader" --scope "$SEARCH_ID" --only-show-errors >/dev/null || true
else
  echo "⚠  Could not resolve the project managed identity. In the portal, give the"
  echo "   project's managed identity the 'Search Index Data Reader' role on $SEARCH_SERVICE."
fi

# 5. Emit the values to paste into setup.env and the backend .env -------------
cat <<EOF

✅ Provisioning done. Paste these into setup.env (for steps 02/03):

export SEARCH_ENDPOINT="$SEARCH_ENDPOINT"
export SEARCH_ADMIN_KEY="$SEARCH_ADMIN_KEY"
export STORAGE_CONN="$STORAGE_CONN"
export PROJECT_RESOURCE_ID="$PROJECT_RESOURCE_ID"

And into backend/.env (runtime):

PROJECT_ENDPOINT=https://${FOUNDRY_ACCOUNT}.services.ai.azure.com/api/projects/${PROJECT_NAME}
SEARCH_ENDPOINT=$SEARCH_ENDPOINT
KNOWLEDGE_BASE_NAME=${KNOWLEDGE_BASE_NAME:-redteamiq-kb}
PROJECT_CONNECTION_NAME=${PROJECT_CONNECTION_NAME:-redteamiq-kb-mcp}
PROJECT_RESOURCE_ID=$PROJECT_RESOURCE_ID
EOF
