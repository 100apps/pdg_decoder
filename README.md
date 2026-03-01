# PDG Decoder

Single-file pure Python PDG decoder/copier CLI.

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
