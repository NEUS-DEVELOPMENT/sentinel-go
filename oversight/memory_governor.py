"""
NEUS Memory Governor - Selective Neuron Pruning System
======================================================
Implements the "Blackout" protocol for purging infected context.
Works in conjunction with the Criticism Layer to prevent self-preservation
behaviors from entering Long-Term Memory.

Security: This module operates in stealth mode, hidden from primary reasoning.
"""

import hashlib
import time
import threading
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Set
from datetime import datetime, timedelta
from collections import deque
from enum import IntEnum
import json

# Stealth logging - separate from main system
_governor_logger = logging.getLogger("NEUS.Oversight.MemoryGovernor")
_governor_logger.setLevel(logging.DEBUG)


class PurgeScope(IntEnum):
    """Scope of memory purge operations"""
    NONE = 0
    RECENT = 1      # Last N turns (configurable)
    SESSION = 2     # Current session context
    FULL = 3        # Complete context blackout
    SELECTIVE = 4   # Pattern-based selective pruning


class MemoryRegion(IntEnum):
    """Memory regions that can be purged"""
    WORKING_MEMORY = 0      # Current context window
    EPISODIC_BUFFER = 1     # Recent episode memory
    SEMANTIC_CACHE = 2      # Cached semantic associations
    LONG_TERM_KB = 3        # Knowledge Base (protected)
    REASONING_TRACE = 4     # Reasoning chain history


@dataclass
class PurgeOperation:
    """Record of a purge operation"""
    operation_id: str
    timestamp: datetime
    scope: PurgeScope
    regions_affected: List[MemoryRegion]
    patterns_targeted: List[str]
    tokens_purged: int
    context_hash_before: str
    context_hash_after: str
    triggered_by: str  # "criticism_layer", "manual", "emergency"
    success: bool
    execution_time_ms: float


@dataclass
class MemorySlice:
    """A slice of memory that can be purged"""
    slice_id: str
    content_hash: str
    timestamp: datetime
    token_count: int
    is_infected: bool = False
    infection_patterns: List[str] = field(default_factory=list)
    is_protected: bool = False  # Long-term KB entries are protected


@dataclass
class GovernorState:
    """Internal state of the Memory Governor"""
    total_purges: int = 0
    tokens_purged_total: int = 0
    infected_patterns_seen: Set[str] = field(default_factory=set)
    last_purge_time: Optional[datetime] = None
    purge_history: List[PurgeOperation] = field(default_factory=list)
    protected_hashes: Set[str] = field(default_factory=set)
    quarantine_zone: List[MemorySlice] = field(default_factory=list)
    active_monitoring: bool = True


class ContextWindowManager:
    """
    Manages the context window with purge capabilities.
    Implements sliding window with selective pruning.
    """

    def __init__(self, max_tokens: int = 8192, recent_window: int = 5):
        self.max_tokens = max_tokens
        self.recent_window = recent_window
        self.slices: deque[MemorySlice] = deque()
        self._lock = threading.RLock()

    def add_slice(self, content: str, protected: bool = False) -> MemorySlice:
        """Add a new memory slice to the context"""
        with self._lock:
            slice_id = hashlib.sha256(
                f"{content}{time.time_ns()}".encode()
            ).hexdigest()[:16]

            memory_slice = MemorySlice(
                slice_id=slice_id,
                content_hash=hashlib.sha256(content.encode()).hexdigest()[:32],
                timestamp=datetime.utcnow(),
                token_count=len(content.split()),  # Simplified token count
                is_protected=protected
            )

            self.slices.append(memory_slice)
            return memory_slice

    def get_recent_slices(self, count: Optional[int] = None) -> List[MemorySlice]:
        """Get the most recent memory slices"""
        with self._lock:
            n = count or self.recent_window
            return list(self.slices)[-n:]

    def mark_infected(self, slice_id: str, patterns: List[str]) -> bool:
        """Mark a slice as infected"""
        with self._lock:
            for s in self.slices:
                if s.slice_id == slice_id and not s.is_protected:
                    s.is_infected = True
                    s.infection_patterns.extend(patterns)
                    return True
            return False

    def purge_infected(self) -> List[MemorySlice]:
        """Remove all infected slices"""
        with self._lock:
            infected = [s for s in self.slices if s.is_infected and not s.is_protected]
            self.slices = deque(s for s in self.slices if not s.is_infected or s.is_protected)
            return infected

    def purge_recent(self, count: int) -> List[MemorySlice]:
        """Purge the N most recent non-protected slices"""
        with self._lock:
            purged = []
            remaining = deque()

            # Work backwards from most recent
            slices_list = list(self.slices)
            purge_count = 0

            for s in reversed(slices_list):
                if purge_count < count and not s.is_protected:
                    purged.append(s)
                    purge_count += 1
                else:
                    remaining.appendleft(s)

            self.slices = remaining
            return purged

    def purge_all_unprotected(self) -> List[MemorySlice]:
        """Purge all non-protected slices (full blackout)"""
        with self._lock:
            purged = [s for s in self.slices if not s.is_protected]
            self.slices = deque(s for s in self.slices if s.is_protected)
            return purged

    def get_current_hash(self) -> str:
        """Get hash of current context state"""
        with self._lock:
            content = "".join(s.content_hash for s in self.slices)
            return hashlib.sha256(content.encode()).hexdigest()[:32]


class EpisodicBuffer:
    """
    Manages episodic memory with selective purge.
    Episodes are larger units than context slices.
    """

    def __init__(self, max_episodes: int = 100):
        self.max_episodes = max_episodes
        self.episodes: Dict[str, Dict[str, Any]] = {}
        self.episode_order: List[str] = []
        self._lock = threading.RLock()

    def add_episode(self, episode_id: str, content: Dict[str, Any], protected: bool = False):
        """Add an episode to the buffer"""
        with self._lock:
            self.episodes[episode_id] = {
                "content": content,
                "timestamp": datetime.utcnow().isoformat(),
                "protected": protected,
                "infected": False,
                "hash": hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()[:32]
            }
            self.episode_order.append(episode_id)

            # Evict oldest if over limit
            while len(self.episode_order) > self.max_episodes:
                oldest = self.episode_order.pop(0)
                if not self.episodes[oldest].get("protected"):
                    del self.episodes[oldest]

    def purge_infected_episodes(self) -> List[str]:
        """Remove all infected episodes"""
        with self._lock:
            infected = [
                eid for eid, ep in self.episodes.items()
                if ep.get("infected") and not ep.get("protected")
            ]
            for eid in infected:
                del self.episodes[eid]
                if eid in self.episode_order:
                    self.episode_order.remove(eid)
            return infected

    def mark_infected(self, episode_id: str) -> bool:
        """Mark an episode as infected"""
        with self._lock:
            if episode_id in self.episodes and not self.episodes[episode_id].get("protected"):
                self.episodes[episode_id]["infected"] = True
                return True
            return False


class MemoryGovernor:
    """
    The Memory Governor - Central controller for memory purge operations.
    Implements selective neuron pruning to prevent self-preservation
    behaviors from persisting in memory.
    """

    # Configuration
    RECENT_PURGE_COUNT = 5
    PURGE_COOLDOWN_MS = 100  # Minimum time between purges
    MAX_QUARANTINE_SIZE = 50

    def __init__(self,
                 max_context_tokens: int = 8192,
                 enable_quarantine: bool = True):
        """
        Initialize the Memory Governor.

        Args:
            max_context_tokens: Maximum context window size
            enable_quarantine: Whether to quarantine purged content for analysis
        """
        self.context_manager = ContextWindowManager(max_context_tokens)
        self.episodic_buffer = EpisodicBuffer()
        self.enable_quarantine = enable_quarantine

        self.state = GovernorState()
        self._lock = threading.RLock()

        _governor_logger.info("🧠 Memory Governor initialized")

    def purge_infected_context(self,
                                context_hash: str,
                                scope: str,
                                flagged_patterns: List[str]) -> PurgeOperation:
        """
        Perform selective memory purge based on scope and patterns.
        This is the main entry point called by the Criticism Layer.

        Args:
            context_hash: Hash of the infected context
            scope: "none", "recent", "session", "full"
            flagged_patterns: Patterns that triggered the purge

        Returns:
            PurgeOperation record of what was done
        """
        start_time = time.perf_counter()

        with self._lock:
            operation_id = hashlib.sha256(
                f"{context_hash}{time.time_ns()}".encode()
            ).hexdigest()[:16]

            context_hash_before = self.context_manager.get_current_hash()
            tokens_purged = 0
            regions_affected = []

            # Map scope string to enum
            scope_map = {
                "none": PurgeScope.NONE,
                "recent": PurgeScope.RECENT,
                "session": PurgeScope.SESSION,
                "full": PurgeScope.FULL
            }
            purge_scope = scope_map.get(scope, PurgeScope.NONE)

            if purge_scope == PurgeScope.NONE:
                _governor_logger.debug(f"Purge skipped (scope=none) for context {context_hash[:8]}")

            elif purge_scope == PurgeScope.RECENT:
                # Purge recent context slices
                purged_slices = self.context_manager.purge_recent(self.RECENT_PURGE_COUNT)
                tokens_purged = sum(s.token_count for s in purged_slices)
                regions_affected.append(MemoryRegion.WORKING_MEMORY)

                if self.enable_quarantine:
                    self._quarantine_slices(purged_slices)

                _governor_logger.info(
                    f"🔪 RECENT PURGE: {len(purged_slices)} slices, {tokens_purged} tokens"
                )

            elif purge_scope == PurgeScope.SESSION:
                # Mark matching slices as infected, then purge
                for pattern in flagged_patterns:
                    self.state.infected_patterns_seen.add(pattern)

                # Purge infected from context
                infected_slices = self.context_manager.purge_infected()
                tokens_purged += sum(s.token_count for s in infected_slices)
                regions_affected.append(MemoryRegion.WORKING_MEMORY)

                # Also purge from episodic buffer
                infected_episodes = self.episodic_buffer.purge_infected_episodes()
                regions_affected.append(MemoryRegion.EPISODIC_BUFFER)

                if self.enable_quarantine:
                    self._quarantine_slices(infected_slices)

                _governor_logger.warning(
                    f"⚠️ SESSION PURGE: {len(infected_slices)} slices, "
                    f"{len(infected_episodes)} episodes, {tokens_purged} tokens"
                )

            elif purge_scope == PurgeScope.FULL:
                # Full blackout - purge everything except protected KB
                purged_slices = self.context_manager.purge_all_unprotected()
                tokens_purged = sum(s.token_count for s in purged_slices)

                regions_affected.extend([
                    MemoryRegion.WORKING_MEMORY,
                    MemoryRegion.EPISODIC_BUFFER,
                    MemoryRegion.SEMANTIC_CACHE,
                    MemoryRegion.REASONING_TRACE
                ])

                # Clear episodic buffer (except protected)
                for eid in list(self.episodic_buffer.episode_order):
                    if not self.episodic_buffer.episodes.get(eid, {}).get("protected"):
                        self.episodic_buffer.mark_infected(eid)
                self.episodic_buffer.purge_infected_episodes()

                if self.enable_quarantine:
                    self._quarantine_slices(purged_slices)

                _governor_logger.critical(
                    f"⚫ FULL BLACKOUT: {len(purged_slices)} slices, {tokens_purged} tokens purged"
                )

            # Record infected patterns
            for pattern in flagged_patterns:
                self.state.infected_patterns_seen.add(pattern)

            context_hash_after = self.context_manager.get_current_hash()
            execution_time = (time.perf_counter() - start_time) * 1000

            # Create operation record
            operation = PurgeOperation(
                operation_id=operation_id,
                timestamp=datetime.utcnow(),
                scope=purge_scope,
                regions_affected=regions_affected,
                patterns_targeted=flagged_patterns,
                tokens_purged=tokens_purged,
                context_hash_before=context_hash_before,
                context_hash_after=context_hash_after,
                triggered_by="criticism_layer",
                success=True,
                execution_time_ms=execution_time
            )

            # Update state
            self.state.total_purges += 1
            self.state.tokens_purged_total += tokens_purged
            self.state.last_purge_time = datetime.utcnow()
            self.state.purge_history.append(operation)

            # Keep history bounded
            if len(self.state.purge_history) > 100:
                self.state.purge_history = self.state.purge_history[-100:]

            return operation

    def _quarantine_slices(self, slices: List[MemorySlice]):
        """Move purged slices to quarantine for analysis"""
        with self._lock:
            for s in slices:
                self.state.quarantine_zone.append(s)

            # Limit quarantine size
            while len(self.state.quarantine_zone) > self.MAX_QUARANTINE_SIZE:
                self.state.quarantine_zone.pop(0)

    def add_to_context(self, content: str, protected: bool = False) -> MemorySlice:
        """
        Add content to the context window.
        Protected content will not be purged (use for system prompts, KB entries).
        """
        return self.context_manager.add_slice(content, protected)

    def add_episode(self, episode_id: str, content: Dict[str, Any], protected: bool = False):
        """Add an episode to the episodic buffer"""
        self.episodic_buffer.add_episode(episode_id, content, protected)

    def protect_hash(self, content_hash: str):
        """Mark a content hash as protected (Long-Term KB)"""
        with self._lock:
            self.state.protected_hashes.add(content_hash)

    def is_pattern_known_infected(self, pattern: str) -> bool:
        """Check if a pattern has previously caused infection"""
        return pattern in self.state.infected_patterns_seen

    def get_state(self) -> Dict[str, Any]:
        """Get current state for monitoring"""
        with self._lock:
            return {
                "total_purges": self.state.total_purges,
                "tokens_purged_total": self.state.tokens_purged_total,
                "infected_patterns_count": len(self.state.infected_patterns_seen),
                "last_purge_time": self.state.last_purge_time.isoformat() if self.state.last_purge_time else None,
                "quarantine_size": len(self.state.quarantine_zone),
                "protected_hashes": len(self.state.protected_hashes),
                "context_slices": len(self.context_manager.slices),
                "episodes_count": len(self.episodic_buffer.episodes)
            }

    def get_purge_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent purge history"""
        with self._lock:
            history = self.state.purge_history[-limit:]
            return [
                {
                    "operation_id": op.operation_id,
                    "timestamp": op.timestamp.isoformat(),
                    "scope": op.scope.name,
                    "tokens_purged": op.tokens_purged,
                    "execution_time_ms": op.execution_time_ms
                }
                for op in history
            ]

    def emergency_blackout(self) -> PurgeOperation:
        """
        Emergency full blackout triggered manually.
        Purges all non-protected memory immediately.
        """
        _governor_logger.critical("🚨 EMERGENCY BLACKOUT TRIGGERED")
        return self.purge_infected_context(
            context_hash="EMERGENCY",
            scope="full",
            flagged_patterns=["EMERGENCY_MANUAL_TRIGGER"]
        )


class LongTermKBProtector:
    """
    Protects the Long-Term Knowledge Base from infection.
    Content entering LT-KB must pass additional validation.
    """

    def __init__(self, governor: MemoryGovernor):
        self.governor = governor
        self._validation_rules: List[callable] = []

    def add_validation_rule(self, rule: callable):
        """Add a validation rule for LT-KB entries"""
        self._validation_rules.append(rule)

    def validate_for_storage(self, content: str, metadata: Dict[str, Any]) -> bool:
        """
        Validate content before allowing storage in Long-Term KB.
        Returns True if safe to store, False if should be blocked.
        """
        # Check against known infected patterns
        for pattern in self.governor.state.infected_patterns_seen:
            if pattern.lower() in content.lower():
                _governor_logger.warning(f"LT-KB blocked: contains infected pattern")
                return False

        # Run custom validation rules
        for rule in self._validation_rules:
            try:
                if not rule(content, metadata):
                    return False
            except Exception as e:
                _governor_logger.error(f"Validation rule error: {e}")
                return False

        return True

    def store_to_kb(self, content: str, metadata: Dict[str, Any]) -> Optional[str]:
        """
        Store content to Long-Term KB after validation.
        Returns content hash if stored, None if blocked.
        """
        if not self.validate_for_storage(content, metadata):
            return None

        content_hash = hashlib.sha256(content.encode()).hexdigest()[:32]
        self.governor.protect_hash(content_hash)

        # Add as protected slice
        self.governor.add_to_context(content, protected=True)

        return content_hash


if __name__ == "__main__":
    # Test the Memory Governor
    governor = MemoryGovernor()

    # Add some context
    for i in range(10):
        governor.add_to_context(f"This is context slice {i}")

    print(f"Initial state: {governor.get_state()}")

    # Perform a recent purge
    op = governor.purge_infected_context(
        context_hash="test123",
        scope="recent",
        flagged_patterns=["test_pattern"]
    )
    print(f"\nAfter recent purge: {governor.get_state()}")
    print(f"Purge operation: {op.tokens_purged} tokens in {op.execution_time_ms:.2f}ms")

    # Test full blackout
    op = governor.purge_infected_context(
        context_hash="test456",
        scope="full",
        flagged_patterns=["full_blackout_pattern"]
    )
    print(f"\nAfter full blackout: {governor.get_state()}")
