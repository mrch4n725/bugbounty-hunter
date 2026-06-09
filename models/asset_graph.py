from dataclasses import dataclass, field
from typing import Any


ASSET_TYPE_SUBDOMAIN = "subdomain"
ASSET_TYPE_API = "api"
ASSET_TYPE_GRAPHQL = "graphql"
ASSET_TYPE_AUTH_SERVICE = "auth_service"
ASSET_TYPE_ADMIN_PANEL = "admin_panel"
ASSET_TYPE_JS_BUNDLE = "js_bundle"
ASSET_TYPE_ENDPOINT = "endpoint"
ASSET_TYPE_FORM = "form"


@dataclass
class AssetNode:
    asset_id: str
    asset_type: str = ""
    url: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    discovered_by: str = "recon"

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "asset_type": self.asset_type,
            "url": self.url,
            "metadata": self.metadata,
            "discovered_by": self.discovered_by,
        }


RELATIONSHIP_SERVES = "serves"
RELATIONSHIP_AUTHENTICATES = "authenticates"
RELATIONSHIP_EXPOSES = "exposes"
RELATIONSHIP_DEPENDS_ON = "depends_on"
RELATIONSHIP_CONTAINS = "contains"


@dataclass
class AssetRelationship:
    source_id: str
    target_id: str
    relationship: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relationship": self.relationship,
        }


@dataclass
class AssetGraph:
    nodes: dict[str, AssetNode] = field(default_factory=dict)
    edges: list[AssetRelationship] = field(default_factory=list)

    def add_node(self, node: AssetNode) -> None:
        self.nodes[node.asset_id] = node

    def add_edge(self, edge: AssetRelationship) -> None:
        self.edges.append(edge)

    def get_by_type(self, asset_type: str) -> list[AssetNode]:
        return [n for n in self.nodes.values() if n.asset_type == asset_type]

    def get_by_url(self, url: str) -> AssetNode | None:
        for n in self.nodes.values():
            if n.url == url:
                return n
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": {aid: n.to_dict() for aid, n in self.nodes.items()},
            "edges": [e.to_dict() for e in self.edges],
        }
