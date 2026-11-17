"""自测:把玩具后端注册进 MongoDB 的 mcp_servers 集合(模拟 UI 注册结果)。"""
import json
from datetime import datetime, timezone

from pymongo import MongoClient

c = MongoClient("mongodb://localhost:27017/?directConnection=true")
col = c["mcp_registry"]["mcp_servers_default"]

doc = {
    "_id": "/toy",
    "path": "/toy",
    "name": "Toy Server",
    "description": "aggregator self-test backend",
    "proxy_pass_url": "http://127.0.0.1:8002/mcp",
    "auth_scheme": "none",
    "is_enabled": True,
    "is_active": True,
    "supported_transports": ["streamable-http"],
    "registered_at": datetime.now(timezone.utc).isoformat(),
    "tool_list": [],
}
col.update_one({"_id": doc["_id"]}, {"$set": doc}, upsert=True)
print(json.dumps(col.find_one({"_id": "/toy"}, {"_id": 1, "is_enabled": 1}), default=str))
