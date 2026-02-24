import { useCallback, useEffect } from "react";

export function useKeyboardShortcut(key, callback, options = {}) {
  const {
    ctrl = false,
    shift = false,
    alt = false,
    enabled = true,
    ignoreInputs = true,
  } = options;

  const handleKeyDown = useCallback(
    (event) => {
      if (!enabled) return;

      if (ignoreInputs) {
        const tag = event.target.tagName.toLowerCase();
        const isEditable = event.target.isContentEditable;
        if (tag === "input" || tag === "textarea" || tag === "select" || isEditable) {
          if (key !== "Escape") return;
        }
      }

      const ctrlOrMeta = event.ctrlKey || event.metaKey;
      if (ctrl && !ctrlOrMeta) return;
      if (!ctrl && ctrlOrMeta) return;
      if (shift && !event.shiftKey) return;
      if (!shift && event.shiftKey && key !== "?") return;
      if (alt && !event.altKey) return;
      if (!alt && event.altKey) return;

      if (event.key === key || event.key.toLowerCase() === key.toLowerCase()) {
        event.preventDefault();
        callback(event);
      }
    },
    [key, callback, ctrl, shift, alt, enabled, ignoreInputs]
  );

  useEffect(() => {
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [handleKeyDown]);
}
