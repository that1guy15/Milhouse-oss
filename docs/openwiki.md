# Generated documentation

Human-maintained Markdown under `docs/` and the generated MkDocs Material site are canonical for Milhouse 1.0. Agent instruction files and skills stay concise and link to those docs.

OpenWiki is optional and noncanonical. It is excluded from release gates unless its workflow is explicitly reviewed to prove that it:

- sends no private repository data, telemetry, credentials, local paths, or raw agent content to an unintended service;
- generates only into a declared path without overwriting canonical source;
- is reproducible and version-pinned;
- labels generated material and links back to canonical versioned docs.

Do not run or configure an OpenWiki workflow as part of normal setup. W17 may remove the remaining `openwiki/` scaffold if no safe, maintained workflow is justified.
