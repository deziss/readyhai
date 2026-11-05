"""CLI and execution entrypoint for ReadyHai LangGraph BGE-M3 Context Retriever."""

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from .config import ConfigError, api_key_for, llm_models, openai_compatible_base_url
from .embeddings import embedding_model_name, get_bge_m3_embeddings
from .ingest import build_bge_m3_index
from .output import dumps, evidence_payload
from .store import IndexError_, load_index

console = Console()


def get_default_llm():
    """OpenAI-compatible chat model for synthesis, or None (with a printed reason) when not configured.

    The endpoint comes from READYHAI_LLM_URL (deprecated alias READYHAI_VLLM_URL; no built-in address).
    READYHAI_LLM_MODEL may list several models: the first is used and the others are tried, in order,
    when a call fails. OPENAI_API_KEY is only sent to api.openai.com; any other endpoint needs
    READYHAI_LLM_API_KEY, otherwise it gets "EMPTY". The key is never printed.
    """
    base = openai_compatible_base_url(required=False)
    if not base:
        console.print("[yellow]LLM synthesis skipped: READYHAI_LLM_URL is not set.[/yellow]")
        return None
    try:
        from langchain_openai import ChatOpenAI

        api_key = api_key_for(base, "READYHAI_LLM_API_KEY")
        clients = [
            ChatOpenAI(
                base_url=base,
                model=model,
                api_key=api_key,
                temperature=0.1,
                max_tokens=4096,
                timeout=60,
                max_retries=2,
            )
            for model in llm_models()
        ]
        return clients[0].with_fallbacks(clients[1:]) if len(clients) > 1 else clients[0]
    except Exception as e:
        console.print(f"[yellow]LLM synthesis skipped: could not create the client ({escape(type(e).__name__)}).[/yellow]")
        return None


def cmd_index(args):
    """Indexes a target codebase or OpenAPI spec directory."""
    console.print(f"[bold cyan]ReadyHai BGE-M3 Indexer[/bold cyan] indexing: [green]{escape(args.target)}[/green]")
    build_bge_m3_index(
        target_dir=args.target,
        index_output_dir=args.index_dir,
        chunk_size=args.chunk_size,
        chunk_overlap=args.chunk_overlap,
        backend=args.backend,
    )
    console.print(f"[bold green]Done.[/bold green] Vector index stored in [cyan]{escape(args.index_dir)}[/cyan]")


def cmd_query(args):
    """Executes the LangGraph Long Context Retriever."""
    from .graph import ReadyHaiContextRetrieverGraph

    if args.json:
        console.quiet = True  # stdout carries exactly one JSON object

    def fail(message: str, code: int):
        if args.json:
            print(dumps({"error": message[:300]}))
        else:
            console.print(f"[bold red]{escape(message)}[/bold red]")
        sys.exit(code)

    if not Path(args.index_dir).exists():
        fail(f"Index directory {args.index_dir} not found. Run index first.", 1)

    console.print("[dim]Rebuilding the vector store from the index files (no pickle is loaded)...[/dim]")
    try:
        embeddings = get_bge_m3_embeddings(backend=args.backend)
        vectorstore = load_index(args.index_dir, embeddings, expect_model=embedding_model_name(args.backend))
    except (IndexError_, ConfigError) as e:
        fail(str(e), 1)

    llm = get_default_llm() if not args.no_llm else None
    retriever_graph = ReadyHaiContextRetrieverGraph(
        vectorstore=vectorstore,
        llm=llm,
        max_chunks=args.max_chunks,
        max_tokens=args.max_tokens,
    )

    console.print(f"[bold cyan]Running LangGraph Retrieval for:[/bold cyan] '{escape(args.query)}'")
    try:
        result = retriever_graph.run(query=args.query, target_path=args.target)
    except Exception as e:  # e.g. the embedding backend is down while embedding the query
        fail(f"Retrieval failed: {type(e).__name__}: {str(e)[:300]}", 2)

    if args.json:
        print(dumps(evidence_payload(result)))
        return

    table = Table(title="ReadyHai Reordered Evidence Ledger (Extremities Weighted)")
    table.add_column("Rank", style="cyan", width=6)
    table.add_column("Source", style="green", width=32)
    table.add_column("Type", style="magenta", width=14)
    table.add_column("Snippet Preview", style="white")
    # every cell is target-derived text: escape it so file content cannot inject rich markup
    for idx, blk in enumerate(result.get("evidence_blocks", [])):
        table.add_row(str(idx + 1), escape(blk["source"]), escape(blk["kind"]), escape(blk["summary"]))
    console.print(table)

    if result.get("llm_error"):
        console.print(f"[bold yellow]LLM synthesis failed:[/bold yellow] {escape(result['llm_error'])} (retrieval results above are still valid)")
    if result.get("final_synthesis"):
        title = "[bold green]ReadyHai Agent Synthesis (AI-generated, advisory)[/bold green]" if llm else "[bold green]ReadyHai Retrieval[/bold green]"
        console.print(Panel(escape(result["final_synthesis"]), title=title))


def main():
    parser = argparse.ArgumentParser(description="ReadyHai LangGraph BGE-M3 Long Context Retriever")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_idx = subparsers.add_parser("index", help="Index a target codebase or OpenAPI spec")
    p_idx.add_argument("--target", "-t", required=True, help="Path to repo or directory (symlinks inside it are never followed)")
    p_idx.add_argument("--index-dir", "-o", default="./data/bge_m3_index", help="Output directory for index")
    p_idx.add_argument("--chunk-size", type=int, default=2500, help="Chunk size (chars, BGE-M3 supports 8192 tokens)")
    p_idx.add_argument("--chunk-overlap", type=int, default=300, help="Chunk overlap")
    p_idx.add_argument("--backend", default=None, choices=["ollama", "huggingface", "openai_compatible"])

    p_qry = subparsers.add_parser("query", help="Query the indexed codebase using LangGraph")
    p_qry.add_argument("--query", "-q", required=True, help="Security, QA, or architecture query")
    p_qry.add_argument("--index-dir", "-i", default="./data/bge_m3_index", help="Directory where index is stored")
    p_qry.add_argument("--target", default=None, help="Target context identifier")
    p_qry.add_argument("--max-chunks", type=int, default=10, help="Number of chunks to retrieve and reorder")
    p_qry.add_argument("--max-tokens", type=int, default=16384, help="Context token budget")
    p_qry.add_argument("--no-llm", action="store_true", help="Do not invoke LLM synthesis, only output context")
    p_qry.add_argument("--json", action="store_true", help="Print one machine-readable JSON object (for ReadyHai's agent) instead of tables")
    p_qry.add_argument("--backend", default=None, choices=["ollama", "huggingface", "openai_compatible"])

    args = parser.parse_args()
    try:
        if args.command == "index":
            cmd_index(args)
        elif args.command == "query":
            cmd_query(args)
    except (ConfigError, FileNotFoundError, ValueError) as e:
        console.print(f"[bold red]{escape(str(e))}[/bold red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
