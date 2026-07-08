/**
 * useGetToken — authentication has been disabled.
 *
 * Returns a stable no-op async function that always returns null.
 * The backend accepts all requests without a token (default user is always returned).
 */
export function useGetToken() {
  return async () => null;
}
