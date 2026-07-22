import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

export default defineConfig({
  plugins: [svelte()],
  base: '/admin/',
  build: {
    outDir: '../cmd/discord-auth/admin',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/api': 'http://localhost:4181',
      '/_oauth': 'http://localhost:4181',
    },
  },
})
