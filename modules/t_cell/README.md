# T Cell Module

`modules/t_cell/t_cell.py` implements an immune-inspired responder for Slips.

It does not modify detector modules. Instead, it subscribes to the shared
`evidence_added` channel, reads the centrally assigned `evidence_signal`, and
creates one T Cell per:

- responsible IP
- regex type
- normalized antigen value

Main behavior:

- only `PAMP` evidence starts antigen recognition and cell creation
- antigens are extracted from evidence fields plus linked DNS/HTTP/SSL altflows
- accepted regexes come from the existing RegexGenerator SQLite store
- `evidence.profile.ip` is the related host context, while containment and
  T-cell ownership use the evidence's responsible IP
- stored `DAMP` observations raise the danger pressure used by
  co-stimulation and context for the same responsible IP
- co-stimulation and context scores decide whether the cell becomes tolerant,
  activates, requests containment, or stores memory
- state `1 - antigen-recognized` and state `3 - activated` can each wait for
  at most one configured Slips time window before timing out to `2 - anergic`
  or `0 - mature`
- once a cell reaches `5 - memory`, later matching evidence keeps it in memory
  without emitting repeated `memory_stored` actions
- containment reuses the existing `new_blocking` payload shape
- all T Cell state is stored in its own SQLite DB and log file

Artifacts:

- module log: `output/t_cell.log`
- module DB: `<run_output_dir>/t_cell/t_cell.sqlite`

See [docs/t_cell_module.md](../../docs/t_cell_module.md) for the full design,
configuration, formulas, and DB schema.
