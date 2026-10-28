"""LangGraph Query Context Retriever for ReadyHai Long-Context Codebases & Audits.

Architecture:
1. analyze_query: Extracts target entities, HTTP endpoints, CVEs, or component names.
2. retrieve_bge_m3: Employs BGE-M3 (8,192 token capacity) for dense + lexical retrieval.
3. reorder_and_compress: Applies `LongContextReorder` to shift most critical evidence
   to the start and end of prompt context, overcoming LLM 'Lost in the Middle'.
4. synthesize_evidence: Formats context into structured ReadyHai Evidence Ledger.
"""

from typing import Annotated, Dict, Any, List, Optional, TypedDict
from langchain_core.documents import Document
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.language_models.chat_models import BaseChatModel
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages

from .embeddings import get_bge_m3_embeddings
from .reorderer import ReadyHaiLongContextTransformer


# ==========================================================
# 1. State Definition
# ==========================================================
class ReadyHaiRetrieverState(TypedDict):
    """LangGraph State for ReadyHai Query Context Retrieval."""
    query: str
    target_path: Optional[str]
    retrieved_docs: List[Document]
    reordered_docs: List[Document]
    assembled_context: str
    evidence_blocks: List[Dict[str, Any]]
    final_synthesis: Optional[str]


# ==========================================================
# 2. Graph Node Implementations
# ==========================================================
class ReadyHaiContextRetrieverGraph:
    def __init__(
        self,
        vectorstore,
        llm: Optional[BaseChatModel] = None,
        max_chunks: int = 10,
        max_tokens: int = 16384,
    ):
        self.vectorstore = vectorstore
        self.llm = llm
        self.max_chunks = max_chunks
        self.transformer = ReadyHaiLongContextTransformer(max_tokens=max_tokens)
        self.graph = self._build_graph()

    def analyze_query_node(self, state: ReadyHaiRetrieverState) -> Dict[str, Any]:
        """Validates query and prepares retrieval filters."""
        query = state.get("query", "").strip()
        if not query:
            return {"query": "security vulnerabilities and test surface"}
        return {"query": query}

    def retrieve_bge_m3_node(self, state: ReadyHaiRetrieverState) -> Dict[str, Any]:
        """Retrieves candidates using BGE-M3 embeddings."""
        query = state["query"]
        # Use MMR (Maximal Marginal Relevance) for high coverage across disparate files
        retriever = self.vectorstore.as_retriever(
            search_type="mmr",
            search_kwargs={
                "k": self.max_chunks,
                "fetch_k": self.max_chunks * 3,
                "lambda_mult": 0.65
            }
        )
        docs: List[Document] = retriever.invoke(query)
        return {"retrieved_docs": docs}

    def reorder_and_compress_node(self, state: ReadyHaiRetrieverState) -> Dict[str, Any]:
        """Applies LongContextReorder to fight LLM 'Lost in the Middle' attention degradation."""
        docs = state.get("retrieved_docs", [])
        reordered = self.transformer.reorder(docs)
        assembled = self.transformer.assemble_context(
            documents=docs,
            query=state["query"],
            max_chunks=self.max_chunks
        )

        evidence = []
        for d in reordered:
            evidence.append({
                "source": d.metadata.get("source", "unknown"),
                "kind": d.metadata.get("kind", "codebase"),
                "summary": d.page_content[:200].replace("\n", " ") + "...",
            })

        return {
            "reordered_docs": reordered,
            "assembled_context": assembled,
            "evidence_blocks": evidence,
        }

    def synthesize_evidence_node(self, state: ReadyHaiRetrieverState) -> Dict[str, Any]:
        """If an LLM is configured, synthesizes a structured ReadyHai Evidence Ledger."""
        if not self.llm:
            return {
                "final_synthesis": (
                    f"Retrieved and reordered {len(state.get('reordered_docs', []))} context blocks "
                    "ready for injection into ReadyHai Agent Studio."
                )
            }

        prompt = ChatPromptTemplate.from_messages([
            ("system",
             "You are the ReadyHai Autonomous QA & Security Intelligence Agent. "
             "Analyze the retrieved long context (codebase files, OpenAPI specs, SAST findings). "
             "Synthesize a 4-Pillar Evidence report:\n"
             "1. Surface & Attack Vectors\n"
             "2. Broken Assumptions / Vulnerabilities\n"
             "3. Reproducible cURL or Test Spec Proposal\n"
             "4. Evidence Ledger (Source files and exact code references)\n\n"
             "Context:\n{context}"),
            ("human", "{query}")
        ])

        chain = prompt | self.llm
        result = chain.invoke({
            "context": state["assembled_context"],
            "query": state["query"]
        })

        return {"final_synthesis": getattr(result, "content", str(result))}

    def _build_graph(self) -> StateGraph:
        builder = StateGraph(ReadyHaiRetrieverState)

        builder.add_node("analyze_query", self.analyze_query_node)
        builder.add_node("retrieve_bge_m3", self.retrieve_bge_m3_node)
        builder.add_node("reorder_and_compress", self.reorder_and_compress_node)
        builder.add_node("synthesize_evidence", self.synthesize_evidence_node)

        builder.add_edge(START, "analyze_query")
        builder.add_edge("analyze_query", "retrieve_bge_m3")
        builder.add_edge("retrieve_bge_m3", "reorder_and_compress")
        builder.add_edge("reorder_and_compress", "synthesize_evidence")
        builder.add_edge("synthesize_evidence", END)

        return builder.compile()

    def run(self, query: str, target_path: Optional[str] = None) -> Dict[str, Any]:
        initial_state: ReadyHaiRetrieverState = {
            "query": query,
            "target_path": target_path,
            "retrieved_docs": [],
            "reordered_docs": [],
            "assembled_context": "",
            "evidence_blocks": [],
            "final_synthesis": None
        }
        return self.graph.invoke(initial_state)
