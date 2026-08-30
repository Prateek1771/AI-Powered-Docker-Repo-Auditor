import { Card, SectionHeading } from "@/components/ui/Card";

/** List the fixes the risk scorer put first. */
export function TopPriorities({ priorities }: { priorities: string[] }) {
  if (priorities.length === 0) return null;

  return (
    <section>
      <SectionHeading>Do these first</SectionHeading>

      <Card className="divide-y divide-border">
        {priorities.map((priority, index) => (
          <div key={priority} className="flex gap-3 p-3">
            <span className="font-mono text-sm tabular-nums text-faint">
              {String(index + 1).padStart(2, "0")}
            </span>
            <p className="text-sm text-foreground">{priority}</p>
          </div>
        ))}
      </Card>
    </section>
  );
}
