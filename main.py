#!/usr/bin/env python3

import argparse
import os
import sys
from src.soc_copilot import SOCCoPilot

# Default directory for all generated reports.
REPORTS_DIR = 'reports'


def resolve_output_path(output: str) -> str:
    """Route a bare filename into the reports/ directory.

    A bare name like 'report.html' becomes 'reports/report.html'.
    An explicit path (containing a directory) is respected as-is.
    The target directory is created if needed.
    """
    if os.path.dirname(output):          # caller gave an explicit path
        target = output
    else:                                # bare filename -> reports/
        target = os.path.join(REPORTS_DIR, output)

    parent = os.path.dirname(target)
    if parent:
        os.makedirs(parent, exist_ok=True)
    return target


def main():
    parser = argparse.ArgumentParser(
        description='AI SOC CoPilot - Intelligent Security Incident Analysis'
    )
    parser.add_argument('--log-dir', default='./logs', help='Log directory (default: ./logs)')
    parser.add_argument('--model', default='llama2', help='Ollama model (default: llama2)')
    parser.add_argument('--output', help='Output file (JSON, TXT, or use --format both)')
    parser.add_argument('--format', choices=['json', 'txt', 'html', 'both'], default='txt', help='Output format (default: txt)')
    parser.add_argument('--ollama-url', default='http://localhost:11434', help='Ollama URL')
    parser.add_argument('--explain', action='store_true', help='Show detailed reasoning')

    args = parser.parse_args()

    # Initialize CoPilot
    copilot = SOCCoPilot(ollama_url=args.ollama_url, model=args.model)

    # Hard pre-flight check: this tool is AI-assisted only and requires a
    # working local model. Fail loudly here rather than crashing mid-analysis.
    ok, message = copilot.llm_client.preflight_check()
    if not ok:
        print(f"ERROR: {message}")
        sys.exit(1)

    # Run analysis
    try:
        results = copilot.analyze_logs(log_dir=args.log_dir)

        if not results:
            print("No analysis results")
            sys.exit(1)

        # Output report
        report = results['report']

        if args.output:
            output_path = resolve_output_path(args.output)
            if args.format == 'both':
                report.save_both(output_path)
            elif args.format == 'html' or output_path.endswith('.html'):
                report.save_html(output_path)
            elif args.format == 'json' or output_path.endswith('.json'):
                report.save_json(output_path)
            else:  # txt
                report.save_txt(output_path)
        else:
            # Print summary to stdout (truncated)
            print("\n" + report.to_markdown(full=False))

            if args.explain:
                analysis = results['analysis']
                print("\n" + "=" * 80)
                print("DETAILED ANALYSIS REASONING")
                print("=" * 80)
                print("\nINITIAL ANALYSIS:\n")
                print(analysis.initial_analysis)
                print("\nCORRELATIONS:\n")
                print(analysis.correlations)
                print("\nMITRE MAPPING:\n")
                print(analysis.mitre_reasoning)
                print("\n" + "=" * 80)

    except KeyboardInterrupt:
        print("\nInterrupted")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
