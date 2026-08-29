export function ScoreCard({
  label,
  value,
  confidence,
}: {
  label: string;
  value: number;
  confidence: number;
}) {
  const partial = confidence < 1;

  return (
    <div className={`rounded border p-4 ${partial ? "border-dashed" : ""}`}>
      <p className="text-sm text-neutral-600">{label}</p>

      {/* The number is still shown - hiding it would be its own dishonesty -
          but a dashed border and muted numerals stop it being mistaken for a
          complete one at a glance. */}
      <p
        className={`mt-1 text-3xl font-semibold tabular-nums ${
          partial ? "text-neutral-500" : "text-neutral-900"
        }`}
      >
        {value}
        <span className="text-base font-normal text-neutral-500">/100</span>
      </p>

      {partial && (
        <p className="mt-1 text-xs text-neutral-600">
          Based on {Math.round(confidence * 100)}% of the usual inputs
        </p>
      )}
    </div>
  );
}
