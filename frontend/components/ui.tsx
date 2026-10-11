import { useId, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode } from "react";

export function Card({
  title,
  children,
  className = "",
}: {
  title?: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`rounded-xl border border-border bg-surface p-5 ${className}`}>
      {title && (
        <h2 className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted">{title}</h2>
      )}
      {children}
    </section>
  );
}

export function Button({
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      className={`inline-flex h-10 items-center justify-center rounded-lg bg-accent-strong px-4 text-sm font-semibold text-background transition hover:bg-accent focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent disabled:cursor-not-allowed disabled:opacity-50 ${className}`}
      {...props}
    />
  );
}

export function Field({
  label,
  hint,
  ...props
}: InputHTMLAttributes<HTMLInputElement> & { label: string; hint?: string }) {
  const id = useId();
  const hintId = `${id}-hint`;
  // The hint is *described by*, not part of, the label: a screen reader announces the field as
  // "Password", then reads the hint as its description.
  return (
    <div className="flex flex-col gap-1.5 text-sm">
      <label htmlFor={id} className="font-medium">
        {label}
      </label>
      <input
        id={id}
        aria-describedby={hint ? hintId : undefined}
        className="h-10 rounded-lg border border-border bg-background px-3 text-foreground placeholder:text-muted focus:border-accent focus:outline-none"
        {...props}
      />
      {hint && (
        <span id={hintId} className="text-xs text-muted">
          {hint}
        </span>
      )}
    </div>
  );
}

export function ErrorMessage({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <p role="alert" className="rounded-lg border border-danger/40 bg-danger/10 px-3 py-2 text-sm text-danger">
      {message}
    </p>
  );
}

export function StatusDot({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span className="inline-flex items-center gap-2 text-sm">
      <span className={`h-2 w-2 rounded-full ${ok ? "bg-success" : "bg-warning"}`} aria-hidden />
      {label}
    </span>
  );
}
