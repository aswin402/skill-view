const isProd = process.env.NODE_ENV === "production" || Boolean(process.env.VERCEL);

function emit(level: "info" | "warn" | "error" | "debug", first: unknown, second?: string): void {
  if (level === "debug" && isProd) return;
  const msg = typeof first === "string" ? first : second ?? "";
  const extra = typeof first === "object" && first !== null ? first : undefined;
  const payload = {
    level,
    time: new Date().toISOString(),
    msg,
    ...(extra ?? {}),
  };
  const line = JSON.stringify(payload, (_key, val) =>
    val instanceof Error ? { name: val.name, message: val.message, stack: val.stack } : val,
  );
  if (level === "error") {
    console.error(line);
  } else if (level === "warn") {
    console.warn(line);
  } else {
    console.log(line);
  }
}

export const logger = {
  debug: (first: unknown, second?: string) => emit("debug", first, second),
  info: (first: unknown, second?: string) => emit("info", first, second),
  warn: (first: unknown, second?: string) => emit("warn", first, second),
  error: (first: unknown, second?: string) => emit("error", first, second),
};
