# Unified Config Usage (Phase 2.1)

Chimera supports a unified tool configuration file that centralizes
tool paths, timeouts, and per-tool options. This config is separate
from the existing JSON config.

## File Location

Default location: `./chimera_config.yml` (repository root).

Override with environment variable:

```
CHIMERA_UNIFIED_CONFIG=/path/to/chimera_config.yml
```

## Commands

Initialize (creates default file if missing):

```
chimera config --unified-init
```

Validate:

```
chimera config --unified-validate
```

Show current unified config:

```
chimera config --unified-show
```

Set a value:

```
chimera config --unified-set tools.zypheron.enabled true
chimera config --unified-set tools.zypheron.binary /app/tools/zypheron/zypheron
```

## Example

```yaml
tools:
  zypheron:
    enabled: true
    version: "1.2.0"
    type: binary
    binary: /app/tools/zypheron/zypheron
    timeout_s: 1800
    options:
      threads: 10
      aggressive: false
```
