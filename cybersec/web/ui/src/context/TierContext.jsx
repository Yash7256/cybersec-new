/**
 * TierContext — provides free/paid tier status and per-tool daily usage globally.
 *
 * Authentication has been disabled. Always fetches /api/user/me unconditionally
 * (no JWT token required) and exposes:
 *   { tier, toolUsage, limit, unlimited, loading, refresh, getToolUsage }
 */
import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import { apiGet } from '../utils/apiClient';

const TierContext = createContext(null);

const DEFAULT_STATE = {
  tier: 'paid',
  toolUsage: {},
  limit: null,
  unlimited: true,
  loading: true,
};

export function TierProvider({ children }) {
  const [state, setState] = useState(DEFAULT_STATE);
  const fetchingRef = useRef(false);

  const refresh = useCallback(async () => {
    if (fetchingRef.current) return;
    fetchingRef.current = true;
    try {
      // No getToken argument — backend returns default user for all requests
      const res = await apiGet('/api/user/me', null, null);
      if (!res || !res.ok) {
        // Backend not ready yet; show unlimited defaults
        setState((prev) => ({ ...prev, loading: false }));
        return;
      }
      const data = await res.json();
      setState({
        tier: data.tier ?? 'paid',
        toolUsage: data.tool_usage ?? {},
        limit: data.daily_limit ?? null,
        unlimited: data.unlimited ?? true,
        loading: false,
      });
    } catch {
      setState((prev) => ({ ...prev, loading: false }));
    } finally {
      fetchingRef.current = false;
    }
  }, []);

  // Fetch on mount
  useEffect(() => {
    refresh();
  }, [refresh]);

  // Listen for limit_reached events (kept for compatibility, won't fire for paid users)
  useEffect(() => {
    const handler = () => refresh();
    window.addEventListener('tier:limit_reached', handler);
    return () => window.removeEventListener('tier:limit_reached', handler);
  }, [refresh]);

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

