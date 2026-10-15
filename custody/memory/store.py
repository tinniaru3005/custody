"""Shared-memory retrieval layer.

Agents find and recall shared memories through ``SharedMemory``. Memories the Warden has
put in quarantine (``Datum:Memory {in_quarantine: true}``) are not returned by ``search``
or ``get`` and cannot be recalled, unless a caller explicitly asks for quarantined
content (forensics). The refusal is also enforced on the write path,
``Recorder.record_memory_recall``, so a recall cannot bypass this layer.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional

from custody.graph.model import DatumRecord
from custody.memory.errors import MemoryQuarantined

if TYPE_CHECKING:  # pragma: no cover
    from custody.recorder.service import Recorder


class SharedMemory:
    def __init__(self, recorder: "Recorder") -> None:
        self.recorder = recorder
        self.repo = recorder.repo

    def search(self, text: Optional[str] = None, *, key: Optional[str] = None,
               agent: Optional[str] = None, include_quarantined: bool = False,
               limit: int = 20) -> List[DatumRecord]:
        return self.repo.search_memories(text=text, key=key, agent=agent,
                                         include_quarantined=include_quarantined, limit=limit)

    def get(self, memory_id: str, *, include_quarantined: bool = False) -> DatumRecord:
        memory = self.repo.get_datum(memory_id)
        if not memory.is_memory:
            raise ValueError(f"{memory_id!r} is a {memory.kind.value}, not a memory")
        if memory.in_quarantine and not include_quarantined:
            raise MemoryQuarantined(f"memory {memory_id} is quarantined "
                                    f"({memory.quarantine_id})")
        return memory

    def recall(self, memory_id: str, *, agent: str, session_id: Optional[str] = None,
               query: Optional[str] = None) -> DatumRecord:
        return self.recorder.record_memory_recall(memory_id, agent=agent, session_id=session_id,
                                                  query=query)
