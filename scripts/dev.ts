import { resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const apiPort = process.env.API_PORT || process.env.PORT || "3847";
const webPort = process.env.WEB_PORT || "5173";

console.log(
  `\x1b[36m\x1b[1m⚡ Starting SkillSpectator API (port ${apiPort}) + Web UI (port ${webPort})...\x1b[0m\n`,
);

const apiProc = Bun.spawn(["bun", "run", "--watch", "src/server.ts"], {
  cwd: resolve(root, "apps/api"),
  stdio: ["inherit", "inherit", "inherit"],
  env: { ...process.env, PORT: apiPort },
});

const webProc = Bun.spawn(["bun", "run", "dev"], {
  cwd: resolve(root, "apps/web"),
  stdio: ["inherit", "inherit", "inherit"],
  env: {
    ...process.env,
    WEB_PORT: webPort,
    API_PORT: apiPort,
  },
});

function shutdown() {
  apiProc.kill();
  webProc.kill();
  process.exit(0);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

await Promise.race([apiProc.exited, webProc.exited]);
shutdown();
