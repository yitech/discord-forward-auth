import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

export default defineConfig({
  plugins: [svelte()],
  base: '/',
  appType: 'spa',
  build: {
    outDir: '../cmd/discord-auth/web',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/api': 'http://localhost:4181',
      '/_oauth': 'http://localhost:4181',
    },
  },
})
