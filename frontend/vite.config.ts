import { defineConfig } from 'vitest/config';
import { loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', '');
  const gateway = env.AGENTSHIELD_GATEWAY_TARGET || 'http://localhost:8080';
  return {
    plugins: [react()],
    server: {
      port: 3000,
      proxy: Object.fromEntries(['/api', '/oauth2', '/.well-known', '/login'].map((path) => [path, { target: gateway, changeOrigin: true }])),
    },
    test: { environment: 'jsdom', setupFiles: './src/test/setup.ts', restoreMocks: true },
  };
});
