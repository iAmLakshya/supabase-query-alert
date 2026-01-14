from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Project:
    id: str
    name: str
    ref: str
    organization_id: str
    status: str
    region: str


@dataclass(frozen=True, slots=True)
class Organization:
    id: str
    name: str
    slug: str
