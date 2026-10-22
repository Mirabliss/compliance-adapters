import { defineConfig } from 'vite';

export default defineConfig({
  // Expose VITE_* env vars to the browser bundle.
  // Set VITE_SERVER_URL in .env (defaults to http://localhost:3001).
  server: {
    port: 5173,
    // Proxy /auth to the example server so CORS is never an issue in dev.
    proxy: {
      '/auth': {
        target: process.env.VITE_SERVER_URL ?? 'http://localhost:3001',
        changeOrigin: true,
      },
    },
  },
});
