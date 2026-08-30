import { cn } from "@/lib/cn";

type Props = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "ghost" | "outline";
};

const VARIANTS = {
  primary: "bg-accent text-accent-fg hover:opacity-90",
  outline: "border border-border-strong text-foreground hover:bg-surface",
  ghost: "text-muted hover:text-foreground hover:bg-surface",
};

/** A button in one of the app's variants. */
export function Button({ variant = "primary", className, ...props }: Props) {
  return (
    <button
      {...props}
      className={cn(
        "inline-flex items-center justify-center gap-2 rounded-md px-3 py-2",
        "text-sm font-medium transition-colors",
        "disabled:cursor-not-allowed disabled:opacity-50",
        VARIANTS[variant],
        className,
      )}
    />
  );
}
