import { defineConfig, loadEnv } from "vite";
import vue from "@vitejs/plugin-vue";
import vueJsx from "@vitejs/plugin-vue-jsx";
import svgLoader from "vite-svg-loader";
import Icons from "unplugin-icons/vite";
import { resolve } from "path";

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  // 加载环境变量
  const env = loadEnv(mode, process.cwd(), '');
  
  return {
    plugins: [
      vue({
        script: {
          defineModel: true,
          propsDestructure: true
        }
      }),
      vueJsx(),
      svgLoader(),
      Icons({
        compiler: "vue3",
        autoInstall: true
      })
    ],
    
    resolve: {
      alias: {
        "@": resolve(__dirname, "src"),
        "~/": resolve(__dirname, "src"),
        "vue-i18n": "vue-i18n/dist/vue-i18n.cjs.js"
      }
    },
    
    server: {
      host: "0.0.0.0",
      port: parseInt(env.VITE_PORT) || 8848,
      open: true,
      proxy: env.VITE_DEV_PROXY === 'true' ? {
        "/api": {
          target: env.VITE_BACKEND_URL || "http://localhost:8787",
          changeOrigin: true,
          secure: false,
          configure: (proxy) => {
            proxy.on('proxyReq', (proxyReq, req) => {
              console.log(`[Proxy] ${req.method} ${req.url} -> ${env.VITE_BACKEND_URL || "http://localhost:8787"}${req.url}`);
            });
            proxy.on('proxyRes', (proxyRes, req) => {
              console.log(`[Proxy] ${proxyRes.statusCode} ${req.method} ${req.url}`);
            });
            proxy.on('error', (err, req) => {
              console.error(`[Proxy Error] ${req.method} ${req.url}:`, err.message);
            });
          }
        }
      } : {}
    },
  
    
    build: {
      // VLESS Encryption 依赖 BigInt；es2015 会将 ** 转成 Math.pow 导致运行时异常
      target: "es2020",
      outDir: "dist",
      assetsDir: "assets",
      sourcemap: false,
      chunkSizeWarningLimit: 2000,
      rollupOptions: {
        output: {
          chunkFileNames: "js/[name]-[hash].js",
          entryFileNames: "js/[name]-[hash].js",
          assetFileNames: "[ext]/[name]-[hash].[ext]",
          manualChunks: (id: string) => {
            if (!id.includes("/node_modules/")) {
              return;
            }

            if (id.includes("/echarts/") || id.includes("/vue-echarts/")) {
              return "echarts";
            }

            if (id.includes("/element-plus/")) {
              return "ui";
            }

            if (
              id.includes("/vue/") ||
              id.includes("/vue-router/") ||
              id.includes("/pinia/")
            ) {
              return "vendor";
            }
          }
        }
      }
    },
    
    define: {
      __INTLIFY_PROD_DEVTOOLS__: false,
      // 在构建时生成构建时间
      'import.meta.env.VITE_BUILD_TIME': JSON.stringify(new Date().toLocaleString('zh-CN', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      }))
    }
  };
});
