/**
 * useGetToken — stable Clerk token getter for Clerk Core 3 / @clerk/react v6.
 *
 * Returns a stable `getToken` function that always reads from the latest
 * session ref, avoiding the stale-closure problem where `session` is null
 * on the first render and never re-captured in memoized callbacks.
 *
 * Usage:
 *   const getToken = useGetToken()
 *   // pass to apiPost / apiGet / apiStream as the third argument
 */
import { useCallback, useEffect, useRef } from 'react'
import { useSession } from '@clerk/react'

export function useGetToken() {
  const { session } = useSession()
  const sessionRef = useRef(session)

  // Keep the ref up-to-date on every render without causing re-renders.
  useEffect(() => {
    sessionRef.current = session
  })

  // Stable function — never changes identity, always reads the latest session.
  const getToken = useCallback(async (opts) => {
    const s = sessionRef.current
    if (!s) return null
    try {
      return await s.getToken(opts)
    } catch {
      return null
    }
  }, []) // empty deps — stability is guaranteed via the ref

  return getToken
}
