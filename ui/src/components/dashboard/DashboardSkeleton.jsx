import { SkeletonChart, SkeletonKpiCards } from "../common/LoadingSkeleton";

export function DashboardSkeleton() {
  return (
    <>
      <SkeletonKpiCards count={4} />
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "var(--space-md)" }}>
        <SkeletonChart height="240px" />
        <SkeletonChart height="240px" />
      </div>
      <SkeletonChart height="200px" />
    </>
  );
}
