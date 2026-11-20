"""Regression tests for standalone tool embeddings."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from registry.repositories.documentdb.search_repository import (
    DocumentDBSearchRepository,
    embedding_config,
)


@pytest.fixture
def indexed_documents():
    docs = {}
    collection = MagicMock()

    def find(query):
        existing = [doc for doc in docs.values() if doc.get("server_path") == query["server_path"]]
        cursor = MagicMock()
        cursor.to_list = AsyncMock(return_value=existing)
        return cursor

    async def replace_one(query, doc, *, upsert):
        docs[query["_id"]] = doc

    async def delete_many(query):
        for doc_id in query["_id"]["$in"]:
            docs.pop(doc_id)

    collection.find.side_effect = find
    collection.replace_one = AsyncMock(side_effect=replace_one)
    collection.delete_many = AsyncMock(side_effect=delete_many)
    return docs, collection


@pytest.mark.asyncio
async def test_sync_stores_independent_vectors_and_refreshes_current_schema(indexed_documents):
    docs, collection = indexed_documents
    repo = DocumentDBSearchRepository()
    repo._embed_with_trim_retry = AsyncMock(side_effect=[[1.0, 0.0], [0.0, 1.0]])
    server = {
        "server_name": "HR",
        "tool_list": [
            {"name": "find_staff", "description": "查询员工", "inputSchema": {}},
            {"name": "find_holidays", "description": "查询假期"},
        ],
    }

    await repo._sync_tool_docs(collection, "/hr", server, is_enabled=True)
    assert docs["/hr::find_staff"]["embedding"] == [1.0, 0.0]
    assert docs["/hr::find_holidays"]["embedding"] == [0.0, 1.0]

    staff = server["tool_list"][0]
    staff["inputSchema"] = {"type": "object"}
    server["tool_list"] = [staff]
    await repo._sync_tool_docs(collection, "/hr", server, is_enabled=False)
    assert set(docs) == {"/hr::find_staff"}
    assert docs["/hr::find_staff"]["is_enabled"] is False
    assert docs["/hr::find_staff"]["inputSchema"] == {"type": "object"}
    assert repo._embed_with_trim_retry.await_count == 2


@pytest.mark.asyncio
async def test_client_side_search_finds_tool_independent_of_parent():
    repo = DocumentDBSearchRepository()
    collection = MagicMock()
    collection.find.return_value.to_list = AsyncMock(return_value=[{
        "_id": "/hr::find_staff",
        "path": "/hr::find_staff",
        "server_path": "/hr",
        "server_name": "HR",
        "entity_type": "mcp_tool",
        "name": "find_staff",
        "description": "查询员工",
        "inputSchema": {},
        "embedding": [1.0, 0.0],
        "is_enabled": True,
    }])
    repo._get_collection = AsyncMock(return_value=collection)

    result = await repo._client_side_search("人员信息", [1.0, 0.0], ["mcp_tool"])

    assert result["servers"] == []
    assert len(result["tools"]) == 1
    assert result["tools"][0]["server_path"] == "/hr"
    assert result["tools"][0]["inputSchema"] == {}
    fields = collection.find.call_args.args[1]
    assert all(fields.get(key) == 1 for key in ("server_path", "server_name", "inputSchema"))


@pytest.mark.asyncio
async def test_sync_reembeds_tool_when_model_changes_at_same_dimension(indexed_documents, monkeypatch):
    docs, collection = indexed_documents
    repo = DocumentDBSearchRepository()
    repo._embed_with_trim_retry = AsyncMock(side_effect=[[1.0, 0.0], [0.0, 1.0]])
    server = {"tool_list": [{"name": "lookup", "description": "Lookup an employee"}]}
    old_metadata = embedding_config.get_embedding_metadata()
    new_metadata = {**old_metadata, "model": "different-embedding-model"}

    await repo._sync_tool_docs(collection, "/hr", server, is_enabled=True)
    monkeypatch.setattr(embedding_config, "get_embedding_metadata", lambda: new_metadata)
    await repo._sync_tool_docs(collection, "/hr", server, is_enabled=True)

    entry = docs["/hr::lookup"]
    assert entry["embedding"] == [0.0, 1.0]
    assert entry["embedding_metadata"]["model"] == new_metadata["model"]
    assert repo._embed_with_trim_retry.await_count == 2
