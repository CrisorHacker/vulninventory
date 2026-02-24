import { SkeletonTable } from "../common/LoadingSkeleton";

export function ScansTableSkeleton() {
  return <SkeletonTable rows={4} columns={5} />;
}
