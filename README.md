# PDG Decoder

Single-file pure Python PDG decoder/copier CLI.

## Background

PDG decoding can be achieved through two approaches: a DLL-based implementation and a pure Python implementation. The DLL approach is limited to Windows environments, which motivated the development of a cross-platform pure Python version.

Previously, reverse-engineering the DLL using IDA Pro and manually porting it to Python was prohibitively time-consuming, causing the project to stall. With recent advances in AI-assisted reverse engineering, we leveraged [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) to automatically disassemble and translate the DLL logic into pure Python.

The current pure Python implementation is functional but not yet feature-complete. Some PDG files that decode successfully with the DLL may not fully decode with the Python version. Further optimization and refinement are ongoing.

## Installation

This project uses [uv](https://github.com/astral-sh/uv) for dependency management.

### Setup

```bash
# Install dependencies and create virtual environment
uv sync

# Or install in development mode
uv pip install -e .
```

## Usage

```bash
# Using uv run
uv run pdg_decoder.py <input_path> [-o OUTPUT_DIR] [-r] [-j JOBS] [--overwrite] [--fail-fast]

# Or activate the virtual environment
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
python pdg_decoder.py <input_path> [options]
```

## Development

```bash
# Sync dependencies
uv sync

# Run the script
uv run python pdg_decoder.py <input_path>
```
