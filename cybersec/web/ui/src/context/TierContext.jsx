/**
 * TierContext — provides free/paid tier status and per-tool daily usage globally.
 *
 * Polls /api/user/me on mount (signed-in users only) and exposes:
 *   { tier, toolUsage, limit, unlimited, loading, refresh, getToolUsage }
 *
 * toolUsage shape (from API):
 *   { "dns": { count: 2, remaining: 3 }, "whois": { count: 5, remaining: 0 }, ... }
 *
 * Components that run tools should call refresh() after a successful scan so
 * the navbar badge stays in sync without a full page reload.
 *
 * getToolUsage(toolName) returns { count, remaining } for a given tool,
 * defaulting to { count: 0, remaining: limit } if never used.
 */
import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import { useAuth, useSession } from '@clerk/react';
import { apiGet } from '../utils/apiClient';

const TierContext = createContext(null);

const DEFAULT_STATE = {
  tier: 'free',
  toolUsage: {},   // { [toolName]: { count: number, remaining: number } }
  limit: 5,
  unlimited: false,
  loading: true,
};

export function TierProvider({ children }) {
  const { isSignedIn } = useAuth();
  // useSession gives us the React-state-synchronized session object.
  // session.getToken() is always in sync with what React knows — unlike
  // useAuth().getToken() which reads from isomorphicClerk.session that can
  // be null briefly after sign-in in Clerk Core 3.
  const { session } = useSession();
  const [state, setState] = useState(DEFAULT_STATE);
  const fetchingRef = useRef(false);

  // Keep a ref to the latest session so refresh() never needs it as a dep.
  const sessionRef = useRef(session);
  useEffect(() => {
    sessionRef.current = session;
  });

  // Stable getToken wrapper that reads from the session ref.
  const getTokenFromSession = useCallback(async (opts) => {
    const s = sessionRef.current;
    if (!s) return null;
    try {
      return await s.getToken(opts);
    } catch {
      return null;
    }
  }, []);

  // refresh is stable across renders (empty dep array) because it reads
  // session via the ref rather than closing over the prop directly.
  const refresh = useCallback(async () => {
    if (fetchingRef.current) return;
    fetchingRef.current = true;
    try {
      const res = await apiGet('/api/user/me', null, getTokenFromSession);
      // Silently swallow 401 — token may not be ready on the very first
      // render immediately after sign-in; the next isSignedIn change will retry.
      if (!res || !res.ok) {
        setState((prev) => ({ ...prev, loading: false }));
        return;
      }
      const data = await res.json();
      setState({
        tier: data.tier ?? 'free',
        toolUsage: data.tool_usage ?? {},
        limit: data.daily_limit ?? 5,
        unlimited: data.unlimited ?? false,
        loading: false,
      });
    } catch {
      setState((prev) => ({ ...prev, loading: false }));
    } finally {
      fetchingRef.current = false;
    }
  }, [getTokenFromSession]); // getTokenFromSession is stable (empty useCallback deps)

  // Fetch on mount and whenever sign-in state changes.
  // refresh is stable so this only fires when isSignedIn actually changes.
  useEffect(() => {
    if (isSignedIn) {
      refresh();
    } else {
      setState({ ...DEFAULT_STATE, loading: false });
    }
  }, [isSignedIn, refresh]);

  // Listen for limit_reached events dispatched by apiClient / streaming callers
  useEffect(() => {
    const handler = () => refresh();
    window.addEventListener('tier:limit_reached', handler);
    return () => window.removeEventListener('tier:limit_reached', handler);
  }, [refresh]);

  /**
   * Get usage for a specific tool.
   * Returns { count, remaining } — defaults to { count: 0, remaining: limit } if unused.
   */
  const getToolUsage = useCallback((toolName) => {
    const entry = state.toolUsage[toolName];
    if (entry) return entry;
    return { count: 0, remaining: state.limit };
  }, [state.toolUsage, state.limit]);

  return (
    <TierContext.Provider value={{ ...state, refresh, getToolUsage }}>
      {children}
    </TierContext.Provider>
  );
}

export function useTier() {
  const ctx = useContext(TierContext);
  if (!ctx) throw new Error('useTier must be used inside <TierProvider>');
  return ctx;
}
