import path from "node:path";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const webPort = Number(process.env.WEB_PORT || 5173);
const apiTarget = process.env.VITE_API_TARGET || `http://localhost:${process.env.API_PORT || 3847}`;

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: webPort,
    hmr: {
      overlay: true,
    },
    proxy: {
      "/api": {
        target: apiTarget,
        changeOrigin: true,
        secure: false,
      },
    },
  },
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "./src"),
    },
  },
});
