#!/usr/bin/env python3
"""
RedTeamIQ — Step 2: create the Foundry IQ knowledge source + knowledge base.

Creates an `azureBlob` knowledge source over the container that holds the 5 KB docs
(it auto-chunks + vectorizes using your embedding deployment), then a knowledge base
that references it and uses gpt-4.1-mini for query planning / answer synthesis.

Reads config from environment (source setup.env first). Uses the Search admin key.

Run:  source ./setup.env && python 02_create_knowledge_base.py
"""
import os
import sys

import requests


def env(name: str, required: bool = True, default: str = "") -> str:
    val = os.environ.get(name, default)
    if required and not val:
        sys.exit(f"✗ Missing required env var: {name} (source setup.env first)")
    return val


SEARCH_ENDPOINT = env("SEARCH_ENDPOINT").rstrip("/")
SEARCH_ADMIN_KEY = env("SEARCH_ADMIN_KEY")
STORAGE_CONN = env("STORAGE_CONN")
BLOB_CONTAINER = env("BLOB_CONTAINER")
KNOWLEDGE_SOURCE_NAME = env("KNOWLEDGE_SOURCE_NAME", default="redteamiq-blob-ks")
KNOWLEDGE_BASE_NAME = env("KNOWLEDGE_BASE_NAME", default="redteamiq-kb")
API_VERSION = env("KB_API_VERSION", default="2026-05-01-preview")

AOAI_ENDPOINT = env("AOAI_ENDPOINT").rstrip("/")
AOAI_KEY = env("AOAI_KEY")
CHAT_DEPLOYMENT = env("CHAT_DEPLOYMENT", default="gpt-4.1-mini")
EMBEDDING_DEPLOYMENT = env("EMBEDDING_DEPLOYMENT", default="text-embedding-3-small")
EMBEDDING_MODEL = env("EMBEDDING_MODEL", default="text-embedding-3-small")

HEADERS = {"Content-Type": "application/json", "api-key": SEARCH_ADMIN_KEY}


def aoai_params(deployment: str, model: str) -> dict:
    return {
        "resourceUri": AOAI_ENDPOINT,
        "deploymentId": deployment,
        "modelName": model,
        "apiKey": AOAI_KEY,
    }


def put(path: str, body: dict, label: str) -> None:
    url = f"{SEARCH_ENDPOINT}/{path}?api-version={API_VERSION}"
    resp = requests.put(url, headers=HEADERS, json=body)
    if resp.status_code not in (200, 201):
        sys.exit(f"✗ {label} failed [{resp.status_code}]: {resp.text}")
    print(f"✓ {label} '{body['name']}' created/updated.")


def main() -> None:
    # 1. Blob knowledge source — ingests + vectorizes the KB docs.
    knowledge_source = {
        "name": KNOWLEDGE_SOURCE_NAME,
        "kind": "azureBlob",
        "description": "RedTeamIQ knowledge base: attack patterns, OWASP refs, severity rubric, fixes.",
        "encryptionKey": None,
        "azureBlobParameters": {
            "connectionString": STORAGE_CONN,
            "containerName": BLOB_CONTAINER,
            "folderPath": None,
            "isADLSGen2": False,
            "ingestionParameters": {
                "identity": None,
                "disableImageVerbalization": True,
                "chatCompletionModel": {
                    "kind": "azureOpenAI",
                    "azureOpenAIParameters": aoai_params(CHAT_DEPLOYMENT, CHAT_DEPLOYMENT),
                },
                "embeddingModel": {
                    "kind": "azureOpenAI",
                    "azureOpenAIParameters": aoai_params(EMBEDDING_DEPLOYMENT, EMBEDDING_MODEL),
                },
                "contentExtractionMode": "minimal",
                "ingestionSchedule": None,
            },
        },
    }
    put(f"knowledgesources/{KNOWLEDGE_SOURCE_NAME}", knowledge_source, "Knowledge source")

    # 2. Knowledge base — references the source + an LLM for planning/synthesis.
    knowledge_base = {
        "name": KNOWLEDGE_BASE_NAME,
        "description": "RedTeamIQ agentic-retrieval KB for attack generation, scoring, and reporting.",
        "retrievalInstructions": "Retrieve attack patterns, OWASP references, the severity rubric, "
        "and fix recommendations relevant to the query.",
        "answerInstructions": "Return concise, citation-backed knowledge for the requesting agent.",
        "outputMode": "answerSynthesis",
        "knowledgeSources": [{"name": KNOWLEDGE_SOURCE_NAME}],
        "models": [
            {"kind": "azureOpenAI", "azureOpenAIParameters": aoai_params(CHAT_DEPLOYMENT, CHAT_DEPLOYMENT)}
        ],
        "encryptionKey": None,
        "retrievalReasoningEffort": {"kind": "low"},
    }
    put(f"knowledgebases/{KNOWLEDGE_BASE_NAME}", knowledge_base, "Knowledge base")

    print("\n✅ Foundry IQ knowledge base ready.")
    print(f"   MCP endpoint: {SEARCH_ENDPOINT}/knowledgebases/{KNOWLEDGE_BASE_NAME}/mcp?api-version={API_VERSION}")


if __name__ == "__main__":
    main()
