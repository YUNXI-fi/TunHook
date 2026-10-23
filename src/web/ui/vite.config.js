import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// 构建产物输出到 ../static（Go 后端 go:embed 嵌入目录）
// base: './' 使资源使用相对路径，应用可部署在飞牛统一网关前缀（/app/TunHook）下
export default defineConfig({
  plugins: [svelte()],
  base: './',
  build: {
    outDir: '../static',
    emptyOutDir: true,
    assetsDir: 'assets',
    target: 'es2018'
  },
  server: {
    port: 5173,
    // 开发模式代理 API 到本地后端（go run . web --addr 127.0.0.1 --port 19090）
    proxy: {
      '/api': 'http://127.0.0.1:19090',
      '/static': 'http://127.0.0.1:19090'
    }
  }
});
