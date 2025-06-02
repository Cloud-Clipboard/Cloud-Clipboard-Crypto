/// <reference types="vitest" />
import { defineConfig } from 'vite'
import tsconfigPaths from 'vite-tsconfig-paths'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [tsconfigPaths()],
  test: {
    // Vitest configuration options go here
    globals: true, // Optional: to use vitest globals like describe, it, expect without importing
    environment: 'jsdom', // Since this is a frontend library we use jsdom
  },
})
