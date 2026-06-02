# Convenience targets for development tasks that don't fit into the
# Python build system (pyproject.toml / hatchling). Distribution-specific
# packaging lives under debian/ and packaging/fedora/ — those are not
# driven from here.

.PHONY: completion clean

# Regenerate shell completion scripts from src/sigillum/cli.py:build_parser.
# Run this whenever the CLI parser changes (new subcommand, new flag).
completion:
	@mkdir -p completion/bash completion/zsh
	PYTHONPATH=src python3 -m shtab --shell=bash --prog sigillum \
	    sigillum.cli.build_parser > completion/bash/sigillum
	PYTHONPATH=src python3 -m shtab --shell=zsh --prog sigillum \
	    sigillum.cli.build_parser > completion/zsh/_sigillum
	@echo "regenerated completion/bash/sigillum and completion/zsh/_sigillum"

clean:
	rm -rf dist build src/sigillum.egg-info
