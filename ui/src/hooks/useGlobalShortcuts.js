import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useKeyboardShortcut } from "./useKeyboardShortcut";

export function useGlobalShortcuts() {
  const navigate = useNavigate();
  const [showShortcutsHelp, setShowShortcutsHelp] = useState(false);

  useKeyboardShortcut("d", () => navigate("/dashboard"), { alt: true });
  useKeyboardShortcut("f", () => navigate("/findings"), { alt: true });
  useKeyboardShortcut("a", () => navigate("/assets"), { alt: true });
  useKeyboardShortcut("s", () => navigate("/scans"), { alt: true });
  useKeyboardShortcut("t", () => navigate("/team"), { alt: true });
  useKeyboardShortcut("u", () => navigate("/audit"), { alt: true });
  useKeyboardShortcut("p", () => navigate("/profile"), { alt: true });

  useKeyboardShortcut("/", () => {
    const searchInput = document.querySelector("[data-shortcut-search]");
    if (searchInput) {
      searchInput.focus();
      searchInput.select();
    }
  });

  useKeyboardShortcut(
    "Escape",
    () => {
      document.dispatchEvent(new CustomEvent("shortcut:escape"));
    },
    { ignoreInputs: false }
  );

  useKeyboardShortcut("?", () => {
    setShowShortcutsHelp((prev) => !prev);
  });

  return { showShortcutsHelp, setShowShortcutsHelp };
}
