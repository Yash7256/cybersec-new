import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth, useUser } from '@clerk/react';
import { useTier } from '../context/TierContext';
import { apiGet } from '../utils/apiClient';
import {
  LayoutDashboard, Clock, ArrowLeft, ChevronLeft, ChevronRight,
  ScanLine, Wifi, Route, Shield, FileText, Globe2, Fingerprint,
  Search, MapPin, Contact, Crosshair, Crown,
} from 'lucide-react';


const TOOL_META = {
  dns:            { label: 'DNS Lookup',      icon: Search },
  whois:          { label: 'WHOIS',           icon: Contact },
  ping:           { label: 'Ping',            icon: Wifi },
  traceroute:     { label: 'Traceroute',      icon: Route },
  ssl:            { label: 'SSL Check',       icon: Shield },
  http_headers:   { label: 'HTTP Headers',    icon: FileText },
  subdomain:      { label: 'Subdomains',      icon: Search },
  geoip:          { label: 'Geo IP',          icon: MapPin },
  os_fingerprint: { label: 'OS Fingerprint',  icon: Fingerprint },
  port_scan:      { label: 'Port Scanner',    icon: ScanLine },
  webapp:         { label: 'Web App Scanner', icon: Globe2 },
  unified:        { label: 'Unified Scan',    icon: Crosshair },
  ai_chat:        { label: 'AI Chat',         icon: Crown },
  ai_analyze:     { label: 'AI Analyze',      icon: Crown },
};

const HISTORY_PAGE_SIZE = 15;

function timeAgo(isoString) {
  if (!isoString) return '';
  const seconds = Math.floor((Date.now() - new Date(isoString).getTime()) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function UsageBar({ count, limit }) {
  const pct = limit > 0 ? (count / limit) * 100 : 0;
  const color =
    pct >= 100 ? '#FF4D4D' :
    pct >= 60  ? '#F97316' :
    pct >= 30  ? '#FBBF24' :
    '#7CFF9A';

  return (
    <div className="w-full h-2 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.06)' }}>
      <div
        className="h-full rounded-full transition-all duration-500"
        style={{ width: `${Math.min(pct, 100)}%`, background: color }}
      />
    </div>
  );
}

export default function Dashboard() {
  const navigate = useNavigate();
  const { getToken, signOut } = useAuth();
  const { user } = useUser();
  const { tier, toolUsage, limit, unlimited, loading: tierLoading, refresh: refreshTier } = useTier();

  const [history, setHistory] = useState([]);
  const [historyTotal, setHistoryTotal] = useState(0);
  const [historyPage, setHistoryPage] = useState(0);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [historyFilter, setHistoryFilter] = useState('');

  const fetchHistory = useCallback(async (page = 0, filter = '') => {
    setHistoryLoading(true);
    try {
      const params = { limit: HISTORY_PAGE_SIZE, offset: page * HISTORY_PAGE_SIZE };
      if (filter) params.tool = filter;
      const res = await apiGet('/api/user/history', params, getToken);
      if (res && res.ok) {
        const data = await res.json();
        setHistory(data.results || []);
        setHistoryTotal(data.total || 0);
      }
    } catch {
      // silent
    } finally {
      setHistoryLoading(false);
    }
  }, [getToken]);

  useEffect(() => { refreshTier(); }, [refreshTier]);
  // eslint-disable-next-line react-hooks/set-state-in-effect
  useEffect(() => { fetchHistory(historyPage, historyFilter); }, [fetchHistory, historyPage, historyFilter]);

  const historyPages = Math.ceil(historyTotal / HISTORY_PAGE_SIZE);

  const email = user?.primaryEmailAddress?.emailAddress || user?.emailAddresses?.[0]?.emailAddress || '';

  return (
    <div className="flex flex-col gap-6 h-full overflow-y-auto pr-2">
      {/* Header */}
      <div className="flex items-center gap-3">
        <button onClick={() => navigate(-1)} className="p-2 rounded-lg hover:bg-white/5 transition" aria-label="Go back">
          <ArrowLeft className="w-4 h-4" />
        </button>
        <LayoutDashboard className="w-5 h-5" style={{ color: '#a78bfa' }} />
        <h1 className="text-xl font-semibold" style={{ color: '#e9d5ff' }}>Dashboard</h1>
      </div>

      {/* ── Section 1: Limit Meter ───────────────────────────────── */}
      <section>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold" style={{ color: '#c4b5fd' }}>Daily Usage</h2>
          <button
            onClick={refreshTier}
            disabled={tierLoading}
            className="text-xs px-2 py-1 rounded-lg transition"
            style={{
              background: 'rgba(255,255,255,0.04)',
              border: '1px solid rgba(199,183,232,0.15)',
              color: tierLoading ? '#4a3960' : '#c4b5fd',
              cursor: tierLoading ? 'not-allowed' : 'pointer',
            }}
          >
            {tierLoading ? 'Refreshing…' : '↻ Refresh'}
          </button>
        </div>
        {tierLoading ? (
          <div className="text-sm" style={{ color: '#6b5fa0' }}>Loading usage data...</div>
        ) : unlimited ? (
          <div className="flex items-center gap-2 text-sm" style={{ color: '#7CFF9A' }}>
            <Crown className="w-4 h-4" /> Unlimited — no daily limits apply to your account
          </div>
        ) : (
          <div className="grid gap-3" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(175px, 1fr))' }}>
            {Object.entries(TOOL_META).map(([tool, meta]) => {
              // Merge API data with defaults — tools never used get full remaining
              const apiData = toolUsage[tool];
              const count   = apiData?.count     ?? 0;
              const dailyLimit = limit ?? 5;
              const remaining  = apiData?.remaining ?? dailyLimit;
              const pct        = dailyLimit > 0 ? (count / dailyLimit) * 100 : 0;
              const isExhausted = remaining === 0;
              const barColor =
                pct >= 100 ? '#FF4D4D' :
                pct >= 60  ? '#F97316' :
                pct >= 30  ? '#FBBF24' :
                '#7CFF9A';
              const remainColor =
                isExhausted ? '#FF4D4D' :
                remaining <= 1 ? '#F97316' :
                remaining <= 2 ? '#FBBF24' :
                '#7CFF9A';
              const Icon = meta.icon;
              return (
                <div
                  key={tool}
                  className="rounded-xl p-3 flex flex-col gap-2"
                  style={{
                    background: isExhausted
                      ? 'rgba(255, 77, 77, 0.05)'
                      : 'rgba(19, 9, 33, 0.6)',
                    border: isExhausted
                      ? '1px solid rgba(255, 77, 77, 0.25)'
                      : '1px solid rgba(199, 183, 232, 0.1)',
                  }}
                >
                  {/* Tool name row */}
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5 min-w-0">
                      <Icon className="w-3.5 h-3.5 flex-shrink-0" style={{ color: '#a78bfa' }} />
                      <span className="text-xs font-medium truncate" style={{ color: '#c4b5fd' }}>
                        {meta.label}
                      </span>
                    </div>
                    {isExhausted && (
                      <span className="text-[9px] font-bold uppercase tracking-wide px-1.5 py-0.5 rounded"
                        style={{ background: 'rgba(255,77,77,0.15)', color: '#FF4D4D' }}>
                        Limit
                      </span>
                    )}
                  </div>

                  {/* Remaining — this is the headline number */}
                  <div className="flex items-baseline gap-1">
                    <span className="text-xl font-bold leading-none font-mono" style={{ color: remainColor }}>
                      {remaining}
                    </span>
                    <span className="text-[10px]" style={{ color: '#4a3960' }}>
                      / {dailyLimit} left today
                    </span>
                  </div>

                  {/* Progress bar (used → limit) */}
                  <UsageBar count={count} limit={dailyLimit} />

                  <span className="text-[10px]" style={{ color: '#4a3960' }}>
                    {count === 0 ? 'No uses today' : `${count} used today`}
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </section>


      {/* ── Section 2: Account ──────────────────────────────────── */}
      <section
        className="rounded-xl p-4 flex flex-col sm:flex-row sm:items-center gap-4"
        style={{ background: 'rgba(19, 9, 33, 0.6)', border: '1px solid rgba(199, 183, 232, 0.1)' }}
      >
        <div className="flex flex-col gap-1 flex-1">
          <h2 className="text-sm font-semibold" style={{ color: '#c4b5fd' }}>Account</h2>
          <span className="text-sm" style={{ color: '#e9d5ff' }}>{email || 'Signed in'}</span>
          <span className="text-xs font-mono" style={{ color: '#6b5fa0' }}>
            Tier: {tier?.toUpperCase() || 'FREE'} · {unlimited ? 'Unlimited' : `${limit ?? 5}/tool/day`}
          </span>
        </div>
        <button
          onClick={() => signOut()}
          className="btn-secondary text-sm px-4 py-2 rounded-lg self-start"
          style={{
            background: 'rgba(255,255,255,0.04)',
            border: '1px solid rgba(199, 183, 232, 0.2)',
            color: '#c4b5fd',
          }}
        >
          Sign Out
        </button>
      </section>

      {/* ── Section 3: Scan History ────────────────────────────── */}
      <section>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold" style={{ color: '#c4b5fd' }}>
            <Clock className="w-4 h-4 inline mr-1.5" style={{ color: '#a78bfa' }} />
            Scan History
          </h2>
          <div className="flex items-center gap-2">
            <select
              value={historyFilter}
              onChange={(e) => { setHistoryFilter(e.target.value); setHistoryPage(0); }}
              className="text-xs rounded-lg px-2 py-1"
              style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(199,183,232,0.15)', color: '#c4b5fd' }}
            >
              <option value="">All tools</option>
              {Object.entries(TOOL_META).map(([key, meta]) => (
                <option key={key} value={key}>{meta.label}</option>
              ))}
            </select>
          </div>
        </div>

        <div
          className="rounded-xl overflow-hidden"
          style={{ background: 'rgba(19, 9, 33, 0.6)', border: '1px solid rgba(199, 183, 232, 0.1)' }}
        >
          {historyLoading ? (
            <div className="p-8 text-center text-sm" style={{ color: '#6b5fa0' }}>Loading history...</div>
          ) : history.length === 0 ? (
            <div className="p-8 text-center text-sm" style={{ color: '#6b5fa0' }}>No scan history yet. Run a tool to get started.</div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr style={{ borderBottom: '1px solid rgba(199,183,232,0.1)' }}>
                  <th className="text-left px-4 py-2.5 font-medium text-xs" style={{ color: '#6b5fa0' }}>Tool</th>
                  <th className="text-left px-4 py-2.5 font-medium text-xs" style={{ color: '#6b5fa0' }}>Target</th>
                  <th className="text-right px-4 py-2.5 font-medium text-xs" style={{ color: '#6b5fa0' }}>Time</th>
                </tr>
              </thead>
              <tbody>
                {history.map((row) => {
                  const meta = TOOL_META[row.tool_name] || { label: row.tool_name, icon: ScanLine };
                  const Icon = meta.icon;
                  return (
                    <tr
                      key={row.id}
                      className="transition hover:bg-white/[0.02]"
                      style={{ borderBottom: '1px solid rgba(199,183,232,0.06)' }}
                    >
                      <td className="px-4 py-2.5">
                        <div className="flex items-center gap-2">
                          <Icon className="w-3.5 h-3.5" style={{ color: '#a78bfa' }} />
                          <span style={{ color: '#e9d5ff' }}>{meta.label}</span>
                        </div>
                      </td>
                      <td className="px-4 py-2.5 font-mono text-xs" style={{ color: '#c4b5fd' }}>
                        {row.target}
                      </td>
                      <td className="px-4 py-2.5 text-right text-xs" style={{ color: '#6b5fa0' }}>
                        {timeAgo(row.created_at)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}

          {/* Pagination */}
          {historyPages > 1 && (
            <div
              className="flex items-center justify-between px-4 py-2.5"
              style={{ borderTop: '1px solid rgba(199,183,232,0.1)' }}
            >
              <span className="text-xs" style={{ color: '#6b5fa0' }}>
                {historyTotal} total · Page {historyPage + 1} of {historyPages}
              </span>
              <div className="flex items-center gap-1">
                <button
                  onClick={() => setHistoryPage((p) => Math.max(0, p - 1))}
                  disabled={historyPage === 0}
                  className="p-1.5 rounded-lg disabled:opacity-30 hover:bg-white/5 transition"
                  aria-label="Previous page"
                >
                  <ChevronLeft className="w-4 h-4" />
                </button>
                <button
                  onClick={() => setHistoryPage((p) => Math.min(historyPages - 1, p + 1))}
                  disabled={historyPage >= historyPages - 1}
                  className="p-1.5 rounded-lg disabled:opacity-30 hover:bg-white/5 transition"
                  aria-label="Next page"
                >
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
