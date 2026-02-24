import { SkeletonTable } from "../common/LoadingSkeleton";

export function FindingsTableSkeleton() {
  return <SkeletonTable rows={8} columns={6} />;
}
