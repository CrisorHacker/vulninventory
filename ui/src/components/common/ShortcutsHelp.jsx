const SHORTCUT_GROUPS = [
  {
    title: "Navegación",
    shortcuts: [
      { keys: ["Alt", "D"], description: "Dashboard" },
      { keys: ["Alt", "F"], description: "Hallazgos" },
      { keys: ["Alt", "A"], description: "Activos" },
      { keys: ["Alt", "S"], description: "Escaneos" },
      { keys: ["Alt", "T"], description: "Equipo" },
      { keys: ["Alt", "U"], description: "Auditoría" },
      { keys: ["Alt", "P"], description: "Perfil" },
    ],
  },
  {
    title: "Acciones globales",
    shortcuts: [
      { keys: ["/"], description: "Buscar" },
      { keys: ["Esc"], description: "Cerrar modal / drawer" },
      { keys: ["?"], description: "Mostrar esta ayuda" },
    ],
  },
  {
    title: "En secciones",
    shortcuts: [
      { keys: ["N"], description: "Nuevo (hallazgo, activo, escaneo, invitación)" },
      { keys: ["I"], description: "Importar (Hallazgos)" },
      { keys: ["E"], description: "Exportar (Hallazgos)" },
    ],
  },
];

export function ShortcutsHelp({ onClose }) {
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="shortcuts-help" onClick={(event) => event.stopPropagation()}>
        <div className="shortcuts-help__header">
          <h2>Atajos de teclado</h2>
          <button className="btn btn-ghost" onClick={onClose} type="button">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>

        <div className="shortcuts-help__body">
          {SHORTCUT_GROUPS.map((group) => (
            <div className="shortcuts-help__group" key={group.title}>
              <h3 className="shortcuts-help__group-title">{group.title}</h3>
              <div className="shortcuts-help__list">
                {group.shortcuts.map((shortcut) => (
                  <div className="shortcuts-help__item" key={shortcut.description}>
                    <span className="shortcuts-help__description">{shortcut.description}</span>
                    <span className="shortcuts-help__keys">
                      {shortcut.keys.map((key, index) => (
                        <span key={`${shortcut.description}-${key}`} className="shortcuts-help__keys-group">
                          {index > 0 && <span className="shortcuts-help__plus">+</span>}
                          <kbd className="shortcuts-help__kbd">{key}</kbd>
                        </span>
                      ))}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        <div className="shortcuts-help__footer">
          <span className="text-muted">
            Presiona <kbd className="shortcuts-help__kbd">?</kbd> para cerrar
          </span>
        </div>
      </div>
    </div>
  );
}
