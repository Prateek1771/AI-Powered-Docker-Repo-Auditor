import { CircleCheck, CircleSlash } from "lucide-react";

/**
 * Say why there are no findings, which is two different messages.
 *
 * A complete scan that found nothing and a degraded scan that could not
 * look are not the same claim, and rendering them alike is exactly the
 * dishonesty this UI exists to avoid.
 */
export function FindingsEmpty({ degraded }: { degraded: boolean }) {
  // Same zero findings, two completely different meanings. Every guard and
  // trust gate on the backend exists so this component can tell them apart.
  if (degraded) {
    return (
      <div className="rounded-lg border border-dashed border-border-strong p-8 text-center">
        <CircleSlash aria-hidden className="mx-auto size-5 text-warn" />
        <p className="mt-3 font-medium text-foreground">No findings recorded</p>
        <p className="mx-auto mt-1 max-w-sm text-sm text-muted">
          Some checks did not finish, so this image has not been fully
          reviewed. Run the scan again for a complete picture.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-border bg-surface-raised p-8 text-center">
      <CircleCheck aria-hidden className="mx-auto size-5 text-ok" />
      <p className="mt-3 font-medium text-foreground">Nothing to fix</p>
      <p className="mx-auto mt-1 max-w-sm text-sm text-muted">
        Every check completed and none of them found a problem.
      </p>
    </div>
  );
}
