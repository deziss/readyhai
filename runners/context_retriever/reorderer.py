"""Long Context Reordering & Compression to defeat 'Lost in the Middle'.

LLMs exhibit an attention bias where information in the middle of a large context window suffers
degraded retrieval and reasoning. This module applies alternating extremity placement (Rank 1 at
start, Rank 2 at end, ...) and a size budget. Every retrieved chunk is untrusted: its body is
redacted and fenced as <data>, and its provenance label is sanitised.
"""

from typing import List, Optional

from .safety import clean_label, fence

CHARS_PER_TOKEN = 3  # conservative: keeps the budget a hard upper bound for code-heavy text


class ReadyHaiLongContextTransformer:
    """Manages document reordering and token budgeting for ReadyHai context windows."""

    def __init__(self, max_tokens: int = 16384):
        from langchain_community.document_transformers import LongContextReorder

        self.reorderer = LongContextReorder()
        self.max_tokens = max_tokens

    def reorder(self, documents: List) -> List:
        """Applies alternating boundary reordering to candidate documents."""
        if not documents:
            return []
        return self.reorderer.transform_documents(documents)

    def assemble_context(self, documents: List, query: Optional[str] = None, max_chunks: int = 12) -> str:
        """Reordered, fenced, budgeted context with provenance headers."""
        budget = self.max_tokens * CHARS_PER_TOKEN
        reordered = self.reorder(documents[:max_chunks])

        blocks: List[str] = []
        used = 0
        for idx, doc in enumerate(reordered):
            source = clean_label(doc.metadata.get("source", "unknown"))
            kind = clean_label(doc.metadata.get("kind", "codebase"), 40)
            header = f"[Context Block {idx + 1} | Source: {source} | Type: {kind}]"
            room = budget - used - len(header)
            if room <= 200:
                break
            body = fence(doc.page_content.strip(), max_chars=room)
            blocks.append(f"{header}\n{body}")
            used += len(header) + len(body)
        return "\n\n" + "=" * 72 + "\n\n".join([""] + blocks + [""]) + "=" * 72 + "\n"
