"""Long Context Reordering & Compression to defeat 'Lost in the Middle'.

LLMs exhibit an attention bias where information in the middle of a large
context window suffers degraded retrieval and reasoning. This module
applies alternating extremity placement (Rank 1 at start, Rank 2 at end,
Rank 3 next to start, Rank 4 next to end, etc.) and semantic pruning.
"""

from typing import List, Optional
from langchain_core.documents import Document
from langchain_community.document_transformers import LongContextReorder


class ReadyHaiLongContextTransformer:
    """Manages document reordering and token budgeting for ReadyHai context windows."""

    def __init__(self, max_tokens: int = 16384):
        self.reorderer = LongContextReorder()
        self.max_tokens = max_tokens

    def reorder(self, documents: List[Document]) -> List[Document]:
        """Applies alternating boundary reordering to candidate documents."""
        if not documents:
            return []
        return self.reorderer.transform_documents(documents)

    def assemble_context(
        self,
        documents: List[Document],
        query: Optional[str] = None,
        max_chunks: int = 12
    ) -> str:
        """Assembles reordered documents into an optimized structured string with provenance."""
        selected_docs = documents[:max_chunks]
        reordered = self.reorder(selected_docs)

        blocks = []
        for idx, doc in enumerate(reordered):
            source = doc.metadata.get("source", "unknown")
            kind = doc.metadata.get("kind", "codebase")
            section = doc.metadata.get("section", f"Chunk {idx+1}")
            
            header = f"[Context Block {idx+1} | Source: {source} | Type: {kind} | Section: {section}]"
            body = doc.page_content.strip()
            blocks.append(f"{header}\n{body}")

        return "\n\n" + ("=" * 72) + "\n\n".join([""] + blocks + [""]) + ("=" * 72) + "\n"
