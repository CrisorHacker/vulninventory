import React, { createContext, useContext, useEffect, useMemo, useState } from "react";

const ThemeContext = createContext(null);

export function ThemeProvider({ children }) {
  const [themeOverride, setThemeOverride] = useState(() => {
    return Boolean(localStorage.getItem("vulninventory-theme"));
  });
  const [theme, setTheme] = useState(() => {
    const saved = localStorage.getItem("vulninventory-theme");
    if (saved) {
      return saved;
    }
    return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  });

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    if (themeOverride) {
      localStorage.setItem("vulninventory-theme", theme);
    } else {
      localStorage.removeItem("vulninventory-theme");
    }
  }, [theme, themeOverride]);

  useEffect(() => {
    const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
    const handleChange = (event) => {
      if (!themeOverride) {
        setTheme(event.matches ? "dark" : "light");
      }
    };
    mediaQuery.addEventListener("change", handleChange);
    return () => mediaQuery.removeEventListener("change", handleChange);
  }, [themeOverride]);

  const toggleTheme = () => {
    setThemeOverride(true);
    setTheme((prev) => (prev === "dark" ? "light" : "dark"));
  };

  const value = useMemo(
    () => ({ theme, setTheme, toggleTheme, themeOverride, setThemeOverride }),
    [theme, themeOverride]
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
  const ctx = useContext(ThemeContext);
  if (!ctx) {
    throw new Error("useTheme must be used within ThemeProvider");
  }
  return ctx;
}
