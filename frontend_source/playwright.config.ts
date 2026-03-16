import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './src',
  timeout: 60_000,
  use: {
    baseURL: 'http://127.0.0.1:4173',
    trace: 'retain-on-failure',
  },
});
