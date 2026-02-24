import { useCallback, useEffect, useState } from "react";

const API_BASE = import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_URL || "http://localhost:9292";

export function useApiFetch(path, options = {}) {
  const { enabled = true, deps = [] } = options;
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchData = useCallback(async () => {
    if (!enabled || !path) {
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const resp = await fetch(`${API_BASE}${path}`, { credentials: "include" });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        throw new Error(err.detail || `Error ${resp.status}`);
      }
      const result = await resp.json();
      setData(result);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [path, enabled, ...deps]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  return { data, loading, error, refetch: fetchData };
}
