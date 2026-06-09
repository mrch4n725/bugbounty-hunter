import hashlib
import re
from urllib.parse import urlparse

from models.asset_graph import (
    AssetNode, AssetRelationship, AssetGraph,
    ASSET_TYPE_SUBDOMAIN, ASSET_TYPE_API, ASSET_TYPE_GRAPHQL,
    ASSET_TYPE_AUTH_SERVICE, ASSET_TYPE_ADMIN_PANEL, ASSET_TYPE_JS_BUNDLE,
    ASSET_TYPE_ENDPOINT, ASSET_TYPE_FORM,
)


GRAPHQL_PATHS = re.compile(r'/graphql|/gql|/query|/v1/graphql|/v2/graphql|/api/graphql', re.IGNORECASE)
API_PATHS = re.compile(r'/api/|/rest/|/v\d+/', re.IGNORECASE)
ADMIN_PATHS = re.compile(r'/admin|/dashboard|/manage|/console|/wp-admin|/administrator', re.IGNORECASE)
AUTH_PATHS = re.compile(r'/auth|/login|/oauth|/token|/authorize|/saml|/openid', re.IGNORECASE)
SUBODMAIN_PATTERN = re.compile(r'^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$', re.IGNORECASE)


def _asset_id(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()[:16]


def _classify_url(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path

    if GRAPHQL_PATHS.search(path):
        return ASSET_TYPE_GRAPHQL
    if ADMIN_PATHS.search(path):
        return ASSET_TYPE_ADMIN_PANEL
    if AUTH_PATHS.search(path):
        return ASSET_TYPE_AUTH_SERVICE
    if API_PATHS.search(path):
        return ASSET_TYPE_API
    return ASSET_TYPE_ENDPOINT


def build_asset_graph(
    target: str,
    urls: list[str],
    subdomains: list[str] | None = None,
    forms: list | None = None,
    js_urls: list[str] | None = None,
    api_endpoints: list[str] | None = None,
) -> AssetGraph:
    graph = AssetGraph()

    target_parsed = urlparse(target)
    target_domain = target_parsed.netloc or target_parsed.path

    target_node = AssetNode(
        asset_id=_asset_id(target),
        asset_type=ASSET_TYPE_SUBDOMAIN,
        url=target,
        metadata={"is_target": True, "domain": target_domain},
        discovered_by="target",
    )
    graph.add_node(target_node)

    for sub in (subdomains or []):
        sub_url = f"https://{sub}" if not sub.startswith("http") else sub
        node = AssetNode(
            asset_id=_asset_id(sub_url),
            asset_type=ASSET_TYPE_SUBDOMAIN,
            url=sub_url,
            metadata={"domain": sub},
            discovered_by="recon",
        )
        graph.add_node(node)
        graph.add_edge(AssetRelationship(
            source_id=target_node.asset_id,
            target_id=node.asset_id,
            relationship="contains",
        ))

    for url in urls:
        asset_type = _classify_url(url)
        node = AssetNode(
            asset_id=_asset_id(url),
            asset_type=asset_type,
            url=url,
            discovered_by="recon",
        )
        graph.add_node(node)

        parent = graph.get_by_url(url)
        if not parent:
            graph.add_edge(AssetRelationship(
                source_id=target_node.asset_id,
                target_id=node.asset_id,
                relationship="contains",
            ))

    for form in (forms or []):
        action = form.get("action", "") if isinstance(form, dict) else getattr(form, "action", "")
        if action:
            node = AssetNode(
                asset_id=_asset_id(action),
                asset_type=ASSET_TYPE_FORM,
                url=action,
                metadata={"method": form.get("method", "GET") if isinstance(form, dict) else getattr(form, "method", "GET")},
                discovered_by="recon",
            )
            graph.add_node(node)

    for js_url in (js_urls or []):
        node = AssetNode(
            asset_id=_asset_id(js_url),
            asset_type=ASSET_TYPE_JS_BUNDLE,
            url=js_url,
            discovered_by="js_intel",
        )
        graph.add_node(node)

    for ep in (api_endpoints or []):
        node = AssetNode(
            asset_id=_asset_id(ep),
            asset_type=ASSET_TYPE_API,
            url=ep,
            discovered_by="api_discovery",
        )
        graph.add_node(node)

    return graph
