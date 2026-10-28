"""CLI and execution entrypoint for ReadyHai LangGraph BGE-M3 Context Retriever."""

import argparse
import os
import sys
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .embeddings import get_bge_m3_embeddings
from .ingest import build_bge_m3_index
from .graph import ReadyHaiContextRetrieverGraph

console = Console()


def get_default_llm():
    """Returns local vLLM or Ollama instance if available, otherwise None."""
    vllm_url = os.environ.get("READYHAI_VLLM_URL", "http://10.10.110.42:13320/v1")
    model = os.environ.get("READYHAI_LLM_MODEL", "qwen3.8-flash-next")
    
    try:
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            base_url=vllm_url,
            model=model,
            api_key=os.environ.get("OPENAI_API_KEY", "EMPTY"),
            temperature=0.1,
            max_tokens=4096
        )
    except Exception:
        return None


def cmd_index(args):
    """Indexes a target codebase or OpenAPI spec directory."""
    console.print(f"[bold cyan]ReadyHai BGE-M3 Indexer[/bold cyan] indexing: [green]{args.target}[/green]")
    build_bge_m3_index(
        target_dir=args.target,
        index_output_dir=args.index_dir,
        chunk_size=args.chunk_size,
        chunk_overlap=args.chunk_overlap,
        backend=args.backend
    )
    console.print(f"[bold green]✔ Done![/bold green] Vector index stored in [cyan]{args.index_dir}[/cyan]")


def cmd_query(args):
    """Executes the LangGraph Long Context Retriever."""
    from langchain_community.vectorstores import FAISS

    if not Path(args.index_dir).exists():
        console.print(f"[bold red]Index directory {args.index_dir} not found. Run index first.[/bold red]")
        sys.exit(1)

    console.print("[dim]Loading BGE-M3 vector store...[/dim]")
    embeddings = get_bge_m3_embeddings(backend=args.backend)
    vectorstore = FAISS.load_local(args.index_dir, embeddings, allow_dangerous_deserialization=True)

    llm = get_default_llm() if not args.no_llm else None
    retriever_graph = ReadyHaiContextRetrieverGraph(
        vectorstore=vectorstore,
        llm=llm,
        max_chunks=args.max_chunks,
        max_tokens=args.max_tokens
    )

    console.print(f"[bold cyan]Running LangGraph Retrieval for:[/bold cyan] '{args.query}'")
    result = retriever_graph.run(query=args.query, target_path=args.target)

    # Display evidence table
    table = Table(title="ReadyHai Reordered Evidence Ledger (Extremities Weighted)")
    table.add_column("Rank", style="cyan", width=6)
    table.add_column("Source", style="green", width=32)
    table.add_column("Type", style="magenta", width=14)
    table.add_column("Snippet Preview", style="white")

    for idx, blk in enumerate(result.get("evidence_blocks", [])):
        table.add_row(str(idx + 1), blk["source"], blk["kind"], blk["summary"])

    console.print(table)

    if result.get("final_synthesis"):
        console.print(Panel(result["final_synthesis"], title="[bold green]ReadyHai Agent Synthesis[/bold green]"))


def main():
    parser = argparse.ArgumentParser(description="ReadyHai LangGraph BGE-M3 Long Context Retriever")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: index
    p_idx = subparsers.add_parser("index", help="Index a target codebase or OpenAPI spec")
    p_idx.add_argument("--target", "-t", required=True, help="Path to repo or directory")
    p_idx.add_argument("--index-dir", "-o", default="./data/bge_m3_index", help="Output directory for index")
    p_idx.add_argument("--chunk-size", type=int, default=2500, help="Chunk size (chars, BGE-M3 supports 8192 tokens)")
    p_idx.add_argument("--chunk-overlap", type=int, default=300, help="Chunk overlap")
    p_idx.add_argument("--backend", default=None, choices=["ollama", "huggingface", "openai_compatible"])

    # Subcommand: query
    p_qry = subparsers.add_parser("query", help="Query the indexed codebase using LangGraph")
    p_qry.add_argument("--query", "-q", required=True, help="Security, QA, or architecture query")
    p_qry.add_argument("--index-dir", "-i", default="./data/bge_m3_index", help="Directory where index is stored")
    p_qry.add_argument("--target", default=None, help="Target context identifier")
    p_qry.add_argument("--max-chunks", type=int, default=10, help="Number of chunks to retrieve and reorder")
    p_qry.add_argument("--max-tokens", type=int, default=16384, help="Context token budget")
    p_qry.add_argument("--no-llm", action="store_true", help="Do not invoke LLM synthesis, only output context")
    p_qry.add_argument("--backend", default=None, choices=["ollama", "huggingface", "openai_compatible"])

    args = parser.parse_args()
    if args.command == "index":
        cmd_index(args)
    elif args.command == "query":
        cmd_query(args)


if __name__ == "__main__":
    main()
