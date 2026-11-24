/// <reference types="vite/client" />
/// <reference types="vite-plugin-monkey/client" />

declare module 'virtual:pw-page-hook' {
  /** The page-world hook as one IIFE (src/page-hook.ts). */
  const source: string;
  export default source;
}

declare module 'virtual:pw-wasm' {
  /** The engine's .wasm, gzip-compressed and base64-encoded. */
  const gzipBase64: string;
  export default gzipBase64;
}
