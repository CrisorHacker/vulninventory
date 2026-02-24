export function EmptyState({
  icon = "default",
  title,
  description,
  action,
  secondaryAction,
  compact = false,
}) {
  return (
    <div className={`empty-state ${compact ? "empty-state--compact" : ""}`}>
      <div className="empty-state__icon">
        <EmptyStateIcon name={icon} />
      </div>
      <h3 className="empty-state__title">{title}</h3>
      {description && <p className="empty-state__description">{description}</p>}
      {(action || secondaryAction) && (
        <div className="empty-state__actions">
          {action && (
            <button className="btn btn-primary" onClick={action.onClick} type="button">
              {action.label}
            </button>
          )}
          {secondaryAction && (
            <button className="btn btn-secondary" onClick={secondaryAction.onClick} type="button">
              {secondaryAction.label}
            </button>
          )}
        </div>
      )}
    </div>
  );
}

function EmptyStateIcon({ name }) {
  const icons = {
    findings: (
      <svg viewBox="0 0 80 80" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path
          d="M40 8L12 20v20c0 16.57 11.93 32.08 28 36 16.07-3.92 28-19.43 28-36V20L40 8z"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          opacity="0.3"
        />
        <path
          d="M28 40l8 8 16-16"
          stroke="currentColor"
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    ),
    assets: (
      <svg viewBox="0 0 80 80" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect x="16" y="12" width="48" height="20" rx="3" stroke="currentColor" strokeWidth="2" opacity="0.3" />
        <rect x="16" y="38" width="48" height="20" rx="3" stroke="currentColor" strokeWidth="2" opacity="0.3" />
        <circle cx="26" cy="22" r="2" fill="currentColor" opacity="0.5" />
        <circle cx="26" cy="48" r="2" fill="currentColor" opacity="0.5" />
        <line x1="34" y1="22" x2="54" y2="22" stroke="currentColor" strokeWidth="2" opacity="0.3" />
        <line x1="34" y1="48" x2="54" y2="48" stroke="currentColor" strokeWidth="2" opacity="0.3" />
        <path d="M40 58v10M32 68h16" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      </svg>
    ),
    scans: (
      <svg viewBox="0 0 80 80" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="36" cy="36" r="24" stroke="currentColor" strokeWidth="2" opacity="0.3" />
        <circle cx="36" cy="36" r="16" stroke="currentColor" strokeWidth="1.5" opacity="0.2" />
        <circle cx="36" cy="36" r="8" stroke="currentColor" strokeWidth="1.5" opacity="0.15" />
        <line x1="36" y1="36" x2="52" y2="20" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" />
        <circle cx="36" cy="36" r="3" fill="currentColor" opacity="0.5" />
        <line x1="54" y1="54" x2="68" y2="68" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
      </svg>
    ),
    team: (
      <svg viewBox="0 0 80 80" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="40" cy="24" r="10" stroke="currentColor" strokeWidth="2" opacity="0.3" />
        <path
          d="M20 62c0-11.05 8.95-20 20-20s20 8.95 20 20"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          opacity="0.3"
        />
        <circle cx="60" cy="28" r="7" stroke="currentColor" strokeWidth="1.5" opacity="0.2" />
        <path d="M62 58c4.42-2.58 8-7.54 8-14" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" opacity="0.2" />
        <circle cx="20" cy="28" r="7" stroke="currentColor" strokeWidth="1.5" opacity="0.2" />
        <path d="M18 58c-4.42-2.58-8-7.54-8-14" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" opacity="0.2" />
      </svg>
    ),
    audit: (
      <svg viewBox="0 0 80 80" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect x="18" y="10" width="44" height="60" rx="4" stroke="currentColor" strokeWidth="2" opacity="0.3" />
        <line x1="28" y1="26" x2="52" y2="26" stroke="currentColor" strokeWidth="2" opacity="0.25" />
        <line x1="28" y1="36" x2="52" y2="36" stroke="currentColor" strokeWidth="2" opacity="0.2" />
        <line x1="28" y1="46" x2="44" y2="46" stroke="currentColor" strokeWidth="2" opacity="0.15" />
        <circle cx="54" cy="56" r="12" stroke="currentColor" strokeWidth="2" fill="var(--bg-primary)" />
        <path d="M50 56l3 3 6-6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    ),
    search: (
      <svg viewBox="0 0 80 80" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="34" cy="34" r="20" stroke="currentColor" strokeWidth="2" opacity="0.3" />
        <line x1="48" y1="48" x2="66" y2="66" stroke="currentColor" strokeWidth="3" strokeLinecap="round" opacity="0.3" />
        <line x1="26" y1="26" x2="42" y2="42" stroke="currentColor" strokeWidth="2" strokeLinecap="round" opacity="0.25" />
        <line x1="42" y1="26" x2="26" y2="42" stroke="currentColor" strokeWidth="2" strokeLinecap="round" opacity="0.25" />
      </svg>
    ),
    import: (
      <svg viewBox="0 0 80 80" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect x="16" y="20" width="48" height="44" rx="4" stroke="currentColor" strokeWidth="2" opacity="0.3" />
        <path d="M40 12v28M30 30l10 10 10-10" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    ),
    error: (
      <svg viewBox="0 0 80 80" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="40" cy="40" r="28" stroke="currentColor" strokeWidth="2" opacity="0.3" />
        <line x1="40" y1="24" x2="40" y2="44" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
        <circle cx="40" cy="52" r="2.5" fill="currentColor" opacity="0.5" />
      </svg>
    ),
    default: (
      <svg viewBox="0 0 80 80" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M12 28l28-16 28 16v24l-28 16-28-16V28z" stroke="currentColor" strokeWidth="2" opacity="0.3" />
        <path d="M12 28l28 16 28-16M40 44v24" stroke="currentColor" strokeWidth="1.5" opacity="0.2" />
      </svg>
    ),
  };

  return icons[name] || icons.default;
}
