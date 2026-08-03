"""
SQLAlchemy database models for CyberSec.
"""
import datetime
from sqlalchemy import Column, String, Boolean, Enum, Integer, Text, ForeignKey, TIMESTAMP, Index, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from cybersec.database.base import Base, UUIDPrimaryKeyMixin, TimestampMixin

# Shared run-status vocabulary used by both scans and tool_results. The
# underlying Postgres type is scan_status_enum (legacy name) so the two tables
# literally share one enum type — a single source of truth for status values.
RunStatusEnum = Enum(
    'pending', 'running', 'completed', 'failed', 'cancelled', 'timed_out',
    name='scan_status_enum',
)

class User(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "users"

    # email: nullable so Clerk users who don't expose their email can still be stored
    email = Column(String(255), unique=True, nullable=True)
    # clerk_user_id: the Clerk identity token (format: user_XXXX); NULL for legacy users
    clerk_user_id = Column(String(255), unique=True, nullable=True, index=True)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)

    # Tier system — free users get 5 tool executions per tool per day
    tier = Column(
        Enum('free', 'paid', name='user_tier_enum'),
        nullable=False,
        default='free',
        server_default='free',
    )
    # Per-tool usage tracking.
    # Schema: { "<tool_name>": { "count": int, "date": "YYYY-MM-DD" }, ... }
    # e.g.  { "dns": { "count": 3, "date": "2026-06-30" }, "whois": { "count": 1, "date": "2026-06-30" } }
    tool_usage = Column(JSONB, nullable=False, default=dict, server_default='{}')

class ToolRun(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Unified parent entity for every tool execution.

    One row per run, regardless of tool: port scans and web-app scans
    (backfilled from the legacy scans table) as well as the JSONB-payload
    tools (backfilled from tool_results). Structured results live in
    scan_results (port/web details), JSONB payloads in tool_results.result_data
    — both children point here via tool_run_id.

    tool_name uses the tier vocabulary: 'port_scan', 'webapp', 'dns', 'whois',
    'ping', 'traceroute', 'ssl', 'http_headers', 'subdomain', 'geoip',
    'os_fingerprint', ...
    """
    __tablename__ = "tool_runs"

    # user_id: nullable (anonymous/pre-auth runs) — orphan the row if the user is deleted
    user_id = Column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    tool_name = Column(String(50), nullable=False)
    target = Column(String(255), nullable=False)
    status = Column(
        RunStatusEnum,
        default='pending',
    )
    # Port-scan-specific (unused by JSONB tools)
    port_range = Column(String(100), nullable=True)
    options = Column(JSONB, nullable=True)
    started_at = Column(TIMESTAMP(timezone=True), nullable=True)
    completed_at = Column(TIMESTAMP(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)

    # Distributed state tracking — port-scan recovery use only
    heartbeat_at = Column(TIMESTAMP(timezone=True), nullable=True)
    worker_id = Column(String(100), nullable=True)
    progress_pct = Column(Integer, default=0)


class Scan(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Legacy port-scan/web-scan parent — superseded by ToolRun (add_tool_runs_parent).

    Kept as the historical carrier so existing routes keep working; the
    follow-up pass repoints writers to ToolRun and drops this table.
    """
    __tablename__ = "scans"

    # user_id: nullable (anonymous/pre-auth scans) — orphan the row if the user is deleted
    user_id = Column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    target = Column(String(255), nullable=False)
    scan_type = Column(String(50), nullable=False)
    status = Column(
        RunStatusEnum,
        default='pending',
    )
    port_range = Column(String(100), nullable=True)
    options = Column(JSONB, nullable=True)
    started_at = Column(TIMESTAMP(timezone=True), nullable=True)
    completed_at = Column(TIMESTAMP(timezone=True), nullable=True)

    # Distributed state tracking
    heartbeat_at = Column(TIMESTAMP(timezone=True), nullable=True)
    worker_id = Column(String(100), nullable=True)
    progress_pct = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)

class ScanResult(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "scan_results"

    scan_id = Column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    # Unified lineage — points at tool_runs (backfilled from scan_id in
    # add_tool_runs_parent); nullable until writers are repointed.
    tool_run_id = Column(ForeignKey("tool_runs.id", ondelete="CASCADE"), nullable=True, index=True)
    port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=True)
    state = Column(String(20), nullable=True)
    service = Column(String(100), nullable=True)
    version = Column(String(255), nullable=True)
    banner = Column(Text, nullable=True)
    cves = Column(JSONB, nullable=True)

class ToolResult(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Legacy JSONB-payload carrier — the parent run now lives in ToolRun.

    Kept so existing writers (tools.py _save_tool_result) keep working; the
    follow-up pass creates a ToolRun row and links it here via tool_run_id.
    """
    __tablename__ = "tool_results"

    # user_id: nullable (anonymous/pre-auth results) — orphan the row if the user is deleted
    user_id = Column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    tool_name = Column(String(50), nullable=False)
    target = Column(String(255), nullable=False)
    result_data = Column(JSONB, nullable=False)
    # Unified lineage — points at tool_runs (backfilled from id in
    # add_tool_runs_parent); nullable until writers are repointed.
    tool_run_id = Column(ForeignKey("tool_runs.id", ondelete="CASCADE"), nullable=True, index=True)

    # Lifecycle tracking — same status vocabulary as Scan (shared enum type).
    # server_default='completed': current insert paths (tools.py _save_tool_result)
    # write rows only after a run finishes, so 'completed' is accurate until those
    # paths adopt explicit pending/running transitions.
    status = Column(RunStatusEnum, nullable=True, server_default='completed')
    started_at = Column(TIMESTAMP(timezone=True), nullable=True)
    completed_at = Column(TIMESTAMP(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)

    # Distributed state tracking — mirrors Scan; for long-running/streaming tools only
    heartbeat_at = Column(TIMESTAMP(timezone=True), nullable=True)
    worker_id = Column(String(100), nullable=True)
    progress_pct = Column(Integer, nullable=True)

class Report(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "reports"

    scan_id = Column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    # Unified lineage — points at tool_runs (backfilled from scan_id in
    # add_tool_runs_parent); nullable until writers are repointed.
    tool_run_id = Column(ForeignKey("tool_runs.id", ondelete="CASCADE"), nullable=True, index=True)
    # user_id: nullable (anonymous/pre-auth reports) — orphan the row if the user is deleted
    user_id = Column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    format = Column(Enum('json', 'csv', 'pdf', name='report_format_enum'), nullable=False)
    file_path = Column(String(500), nullable=True)

class ToolUsageEvent(Base, UUIDPrimaryKeyMixin):
    """Append-only per-invocation usage event for analytics.

    Complements (does not replace) the live same-day counter in
    users.tool_usage: one row per gated tool invocation, kept forever so
    per-tool usage history can be queried (e.g. "whois runs in the last 30
    days"). Deliberately minimal — no created_at/updated_at mixin.
    """
    __tablename__ = "tool_usage_events"

    user_id = Column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    tool_name = Column(String(50), nullable=False)
    used_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        Index("ix_tool_usage_events_user_tool_used_at", "user_id", "tool_name", "used_at"),
        Index("ix_tool_usage_events_used_at", "used_at"),
    )

class WorkerHeartbeat(Base):
    """Tracks worker process liveness for scan ownership recovery."""
    __tablename__ = "worker_heartbeats"

    worker_id = Column(String(100), primary_key=True)
    hostname = Column(String(255), nullable=True)
    pid = Column(Integer, nullable=True)
    active_scans = Column(Integer, default=0)
    last_heartbeat = Column(TIMESTAMP(timezone=True), nullable=False)


class NVDCveCache(Base):
    __tablename__ = "nvd_cve_cache"
    
    cve_id = Column(String(20), primary_key=True)  # CVE-YYYY-NNNNN format
    data = Column(JSONB, nullable=False)          # full CVEResult as JSON
    fetched_at = Column(TIMESTAMP(timezone=True), nullable=False)
    expires_at = Column(TIMESTAMP(timezone=True), nullable=False)


class NVDServiceLookupCache(Base):
    """Cache for NVDClient.lookup_cves_for_service() results keyed by service/version pair."""
    __tablename__ = "nvd_service_lookup_cache"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cache_key = Column(String(64), unique=True, nullable=False, index=True)  # sha256 hex
    service_name = Column(String(255), nullable=False)
    service_version = Column(String(255), nullable=False)
    results = Column(JSONB, nullable=False)  # list of CVEResult dicts
    fetched_at = Column(TIMESTAMP(timezone=True), nullable=False)
    expires_at = Column(TIMESTAMP(timezone=True), nullable=False)

# TODO: implement relationships and other columns if needed
