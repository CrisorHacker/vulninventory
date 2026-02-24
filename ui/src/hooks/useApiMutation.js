import { useCallback, useState } from "react";

const API_BASE = import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_URL || "http://localhost:9292";

function getCsrfToken() {
  const match = document.cookie.match(/(^| )csrf_token=([^;]+)/);
  return match ? decodeURIComponent(match[2]) : null;
}

export function useApiMutation(path, method = "POST") {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const mutate = useCallback(
    async (body, overridePath) => {
      setLoading(true);
      setError(null);
      try {
        const headers = { "Content-Type": "application/json" };
        const csrf = getCsrfToken();
        if (csrf) {
          headers["X-CSRF-Token"] = csrf;
        }
        const resp = await fetch(`${API_BASE}${overridePath || path}`, {
          method,
          credentials: "include",
          headers,
          body: body ? JSON.stringify(body) : undefined,
        });
        if (!resp.ok) {
          const err = await resp.json().catch(() => ({}));
          throw new Error(err.detail || `Error ${resp.status}`);
        }
        const data = await resp.json().catch(() => ({}));
        return data;
      } catch (err) {
        setError(err.message);
        throw err;
      } finally {
        setLoading(false);
      }
    },
    [path, method]
  );

  return { mutate, loading, error };
}
