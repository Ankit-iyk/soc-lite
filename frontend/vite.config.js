import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    tailwindcss(), // Tailwind v4 uses a Vite plugin — no postcss.config needed
  ],
  server: {
    port: 5173,
    // Proxy /api requests to the backend during development
    // so the browser never hits a CORS issue
    proxy: {
      '/api': {
        target: 'http://localhost:3000',
        changeOrigin: true,
      },
    },
  },
})
