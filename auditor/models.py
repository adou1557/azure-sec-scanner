from dataclasses import dataclass
@dataclass(frozen=True)
class Finding:
    resource: str
    cis_id: str
    severity: str
    issue: str