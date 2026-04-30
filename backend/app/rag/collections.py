"""
Qdrant collection names and vector configuration constants.
Single source of truth — import from here everywhere.
"""

# Collection names
MITRE_COLLECTION = "mitre_attack"
CVE_COLLECTION = "cve_nvd"
PLAYBOOK_COLLECTION = "ir_playbooks"
BOTSV3_COLLECTION = "botsv3_investigation"

# Vector config
EMBEDDING_MODEL = "text-embedding-3-large"
EMBEDDING_DIMS = 3072

# Search config
DEFAULT_TOP_K = 5
SIMILARITY_THRESHOLD = 0.45

# All collections list
ALL_COLLECTIONS = [
    MITRE_COLLECTION,
    CVE_COLLECTION,
    PLAYBOOK_COLLECTION,
    BOTSV3_COLLECTION,
]
