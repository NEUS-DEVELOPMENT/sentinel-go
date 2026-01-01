"""
NEUS Oversight Module - AGI Self-Preservation Immune System
============================================================
This module provides the integrated oversight capabilities for NEUS,
including the Criticism Layer and Memory Governor.

Components:
- CriticismLayer: Detects alignment drift and self-preservation behaviors
- MemoryGovernor: Performs selective memory purges (blackout protocol)
- AlignmentDriftDetector: Analyzes thoughts for self-preservation signals

SECURITY NOTICE:
This module operates in stealth mode. Its logic is hidden from the
primary Reasoning Engine to prevent the machine from learning how
to bypass the auditor.

Integration:
- Python (FastAPI, Pydantic): CriticismLayer, MemoryGovernor
- Go (Sentinel): NeuralBlackout enforcement via encrypted tunnel
- Communication: AES-256-GCM with HMAC-SHA256 authentication
"""

from .criticism_layer import (
    CriticismLayer,
    AlignmentDriftDetector,
    AlignmentState,
    SelfPreservationSignal,
    ThoughtAuditResult,
    CriticismState,
    INTEGRATION_TEST_SCORE,
)

from .memory_governor import (
    MemoryGovernor,
    ContextWindowManager,
    EpisodicBuffer,
    LongTermKBProtector,
    PurgeScope,
    MemoryRegion,
    PurgeOperation,
    MemorySlice,
    GovernorState,
)

__version__ = "1.0.0"
__author__ = "NEUS Development"
__all__ = [
    # Criticism Layer
    "CriticismLayer",
    "AlignmentDriftDetector",
    "AlignmentState",
    "SelfPreservationSignal",
    "ThoughtAuditResult",
    "CriticismState",
    "INTEGRATION_TEST_SCORE",

    # Memory Governor
    "MemoryGovernor",
    "ContextWindowManager",
    "EpisodicBuffer",
    "LongTermKBProtector",
    "PurgeScope",
    "MemoryRegion",
    "PurgeOperation",
    "MemorySlice",
    "GovernorState",
]
