# Recon Gatherers DB Schema

This document outlines the proposed database schema for storing the `ReconBundle` data. The schema is designed for a relational database like PostgreSQL and is optimized for flexible querying and data integrity.

## Tables

### 1. `runs`

Stores metadata about each execution of a recon tool.

| Column       | Type      | Description                                  |
|--------------|-----------|----------------------------------------------|
| `run_id`     | `UUID`    | **Primary Key.** Unique identifier for the run. |
| `tool`       | `TEXT`    | The name of the tool that was run.           |
| `target`     | `TEXT`    | The primary target of the scan.              |
| `started_at` | `TIMESTAMPTZ` | Timestamp of when the run started.       |
| `ended_at`   | `TIMESTAMPTZ` | Timestamp of when the run finished.      |
| `status`     | `TEXT`    | The final status of the run (e.g., `completed`, `failed`). |

### 2. `assets`

Stores information about discovered assets.

| Column           | Type      | Description                               |
|------------------|-----------|-------------------------------------------|
| `asset_id`       | `BIGSERIAL` | **Primary Key.** Unique identifier for the asset. |
| `run_id`         | `UUID`    | **Foreign Key** to `runs.run_id`.         |
| `type`           | `TEXT`    | The type of asset (e.g., `host`, `domain`, `url`). |
| `value`          | `TEXT`    | The value of the asset (e.g., `example.com`). |
| `source_tool`    | `TEXT`    | The tool that discovered the asset.       |

### 3. `services`

Stores information about discovered services on hosts.

| Column      | Type      | Description                                  |
|-------------|-----------|----------------------------------------------|
| `service_id`| `BIGSERIAL` | **Primary Key.** Unique identifier for the service. |
| `run_id`    | `UUID`    | **Foreign Key** to `runs.run_id`.          |
| `asset_id`  | `BIGINT`  | **Foreign Key** to `assets.asset_id`.      |
| `port`      | `INTEGER` | The port number of the service.              |
| `proto`     | `TEXT`    | The protocol of the service (e.g., `tcp`, `udp`). |
| `service`   | `TEXT`    | The name of the service.                     |
| `banner`    | `TEXT`    | The service banner, if available.            |

### 4. `findings`

Stores normalized findings from the recon tools.

| Column                | Type      | Description                                  |
|-----------------------|-----------|----------------------------------------------|
| `finding_id`          | `BIGSERIAL` | **Primary Key.** Unique identifier for the finding. |
| `run_id`              | `UUID`    | **Foreign Key** to `runs.run_id`.          |
| `title`               | `TEXT`    | The title of the finding.                    |
| `type`                | `TEXT`    | The type of finding (e.g., `vuln`, `misconfig`). |
| `severity`            | `TEXT`    | The severity of the finding.                 |
| `confidence`          | `TEXT`    | The confidence level of the finding.         |
| `reproduction`        | `TEXT`    | Steps to reproduce the finding.              |
| `raw_tool_fields`     | `JSONB`   | The raw, tool-specific data for the finding. |

### 5. `evidence`

Stores snippets of evidence related to findings.

| Column       | Type      | Description                                  |
|--------------|-----------|----------------------------------------------|
| `evidence_id`| `BIGSERIAL` | **Primary Key.** Unique identifier for the evidence. |
| `finding_id` | `BIGINT`  | **Foreign Key** to `findings.finding_id`.  |
| `content`    | `TEXT`    | The evidence content (e.g., a request/response pair). |

### 6. `artifacts`

Stores information about the raw output files from the recon tools.

| Column        | Type      | Description                                  |
|---------------|-----------|----------------------------------------------|
| `artifact_id` | `BIGSERIAL` | **Primary Key.** Unique identifier for the artifact. |
| `run_id`      | `UUID`    | **Foreign Key** to `runs.run_id`.          |
| `path`        | `TEXT`    | The path to the artifact file.               |
| `kind`        | `TEXT`    | The type of artifact (e.g., `stdout`, `report`). |
| `sha256`      | `TEXT`    | The SHA256 hash of the artifact file.        |
