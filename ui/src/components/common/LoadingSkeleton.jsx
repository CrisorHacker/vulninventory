export function Skeleton({ width = "100%", height = "16px", borderRadius, style = {} }) {
  return (
    <div
      className="skeleton"
      style={{
        width,
        height,
        borderRadius: borderRadius || "var(--radius-md)",
        ...style,
      }}
    />
  );
}

export function SkeletonTable({ rows = 5, columns = 5 }) {
  return (
    <div className="skeleton-table">
      <div className="skeleton-table__header">
        {Array.from({ length: columns }).map((_, i) => (
          <Skeleton key={`h-${i}`} width={`${60 + Math.random() * 40}%`} height="12px" />
        ))}
      </div>
      {Array.from({ length: rows }).map((_, r) => (
        <div className="skeleton-table__row" key={`r-${r}`}>
          {Array.from({ length: columns }).map((_, c) => (
            <Skeleton
              key={`r-${r}-c-${c}`}
              width={`${40 + Math.random() * 50}%`}
              height="14px"
            />
          ))}
        </div>
      ))}
    </div>
  );
}

export function SkeletonKpiCards({ count = 4 }) {
  return (
    <div className="skeleton-kpi-grid">
      {Array.from({ length: count }).map((_, i) => (
        <div className="skeleton-kpi-card card" key={i}>
          <Skeleton width="40%" height="12px" />
          <Skeleton width="60%" height="28px" style={{ marginTop: 12 }} />
          <Skeleton width="80%" height="10px" style={{ marginTop: 8 }} />
        </div>
      ))}
    </div>
  );
}

export function SkeletonChart({ height = "240px" }) {
  return (
    <div className="skeleton-chart card">
      <Skeleton width="30%" height="16px" />
      <Skeleton
        width="100%"
        height={height}
        style={{ marginTop: 16 }}
        borderRadius="var(--radius-lg)"
      />
    </div>
  );
}
