import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// base './' keeps built asset paths relative so the dashboard opens locally
// from any folder — local-only, nothing hosted.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: './',
})
