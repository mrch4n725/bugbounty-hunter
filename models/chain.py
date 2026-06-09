from dataclasses import dataclass, field
from typing import Any


@dataclass
class AttackNode:
    finding_fingerprint: str
    vuln_type: str
    root_cause: str
    confidence: float = 0.0
    evidence_fingerprints: list[str] = field(default_factory=list)
    url: str = ""


@dataclass
class AttackEdge:
    source: str
    target: str
    relationship: str = "leads_to"
    confidence: float = 0.0
    prerequisite: str = ""


@dataclass
class AttackChain:
    nodes: list[AttackNode] = field(default_factory=list)
    edges: list[AttackEdge] = field(default_factory=list)
    entry_point: str = ""
    final_impact: str = ""
    overall_confidence: float = 0.0
    chain_fingerprint: str = ""
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_point": self.entry_point,
            "final_impact": self.final_impact,
            "overall_confidence": round(self.overall_confidence, 1),
            "chain_fingerprint": self.chain_fingerprint,
            "description": self.description,
            "nodes": [
                {
                    "finding_fingerprint": n.finding_fingerprint,
                    "vuln_type": n.vuln_type,
                    "root_cause": n.root_cause,
                    "confidence": round(n.confidence, 1),
                    "url": n.url,
                }
                for n in self.nodes
            ],
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "relationship": e.relationship,
                    "confidence": round(e.confidence, 1),
                }
                for e in self.edges
            ],
        }
