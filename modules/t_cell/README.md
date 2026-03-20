# T Cell Module

`modules/t_cell/t_cell.py` implements an immune-inspired responder for Slips.

It does not modify detector modules. Instead, it subscribes to the shared
`evidence_added` channel, reads the centrally assigned `evidence_signal`, and
creates one T Cell per:

- `profile.ip`
- regex type
- normalized antigen value

Main behavior:

- only `PAMP` evidence activates the module in v1
- antigens are extracted from evidence fields plus linked DNS/HTTP/SSL altflows
- accepted regexes come from the existing RegexGenerator SQLite store
- co-stimulation and context scores decide whether the cell becomes tolerant,
  activates, requests containment, or stores memory
- containment reuses the existing `new_blocking` payload shape
- all T Cell state is stored in its own SQLite DB and log file

Artifacts:

- module log: `output/t_cell.log`
- module DB: `<run_output_dir>/t_cell/t_cell.sqlite`

See [docs/t_cell_module.md](../../docs/t_cell_module.md) for the full design,
configuration, formulas, and DB schema.
