# Architecture Overview

This document explains the key architectural patterns used in the Supabase Query Alert system.

## Input Abstraction Layer

The system uses the adapter pattern to decouple query sources from analysis logic. Any class implementing the `QueryInput` protocol can feed queries into the pipeline.

### QueryInput Protocol

```python
from typing import Protocol, Self, runtime_checkable
from supabase_query_alert.domain import Query

@runtime_checkable
class QueryInput(Protocol):
    def __aiter__(self) -> Self: ...
    async def __anext__(self) -> Query: ...
```

All input adapters implement this async iterator protocol, enabling uniform consumption:

```python
async for query in input_source:
    findings = await registry.analyze_all(query)
```

### Available Input Adapters

**ManualInput** - Programmatic input for testing and scripting.
- Use case: Unit tests, one-off analysis, REPL exploration
- Input format: List of Query objects
- Example: `ManualInput([Query(sql="SELECT * FROM users")])`

**SupabaseLogInput** - Supabase Management API integration.
- Use case: Production monitoring of hosted Supabase projects
- Input format: JSON from `/v1/projects/{ref}/analytics/endpoints/logs.all`
- Factory method: `SupabaseLogInput.from_log_rows(log_data)` for testing
- See: `docs/HOSTED_SETUP.md`

**LogFileInput** - PostgreSQL log file reader.
- Use case: Local development, log replay, exported log analysis
- Input format: PostgreSQL log files with pgaudit entries
- Factory method: `LogFileInput.from_lines(lines)` for testing
- Log format: `timestamp tz:client:user@db:[pid]: LOG: AUDIT: ...`

### Pipeline Architecture

The `QueryPipeline` class connects input adapters to analyzers and output handlers:

```
QueryInput → AnalyzerRegistry → AlertOutput
   │              │                  │
   │              ├─ SQLInjection    ├─ ConsoleAlertOutput
   │              ├─ DataExfil       └─ (future: webhook, email)
   │              └─ VolumeAnomaly
   │
   ├─ ManualInput
   ├─ LogFileInput
   └─ SupabaseLogInput
```

Each component is replaceable without affecting others.

### Adding New Input Sources

1. Create a class implementing `QueryInput` protocol
2. Parse your input format into `Query` objects
3. Populate `QueryMetadata` with available context (user, timestamp, source)
4. Add exports to `input/__init__.py`

Example skeleton:

```python
from supabase_query_alert.domain import Query, QueryMetadata

class MyCustomInput:
    def __init__(self, data_source):
        self._data = data_source
        self._index = 0

    def __aiter__(self) -> "MyCustomInput":
        return self

    async def __anext__(self) -> Query:
        if self._index >= len(self._data):
            raise StopAsyncIteration
        item = self._data[self._index]
        self._index += 1
        return Query(
            sql=item["query"],
            metadata=QueryMetadata(
                timestamp=item.get("ts"),
                user_id=item.get("user"),
            )
        )
```

The pipeline remains unchanged - only the input adapter needs implementation.

## Analyzer Framework

Analyzers implement the `QueryAnalyzer` protocol:

```python
@runtime_checkable
class QueryAnalyzer(Protocol):
    @property
    def name(self) -> str: ...
    async def analyze(self, query: Query) -> Finding | None: ...
```

The `AnalyzerRegistry` manages registered analyzers and provides batch analysis:

```python
registry = AnalyzerRegistry()
registry.register(SQLInjectionAnalyzer())
registry.register(DataExfiltrationAnalyzer())

findings = await registry.analyze_all(query)
```

### Adding New Analyzers

1. Create a class implementing `QueryAnalyzer` protocol
2. Return `Finding` for suspicious queries, `None` otherwise
3. Register with `AnalyzerRegistry`

## Alert Output

Output handlers implement the `AlertOutput` protocol:

```python
@runtime_checkable
class AlertOutput(Protocol):
    async def emit(self, alert: Alert) -> None: ...
```

The pipeline accepts multiple outputs for parallel delivery (console + webhook + email).

## Design Principles

- **Protocol over inheritance**: Runtime-checkable protocols enable duck typing with type safety
- **Immutable domain models**: Frozen dataclasses prevent accidental mutation
- **Factory methods for testing**: `from_log_rows()`, `from_lines()` enable testing without real I/O
- **Async throughout**: All I/O operations are async for scalability
