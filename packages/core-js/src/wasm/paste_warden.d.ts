// Types of the wasm-bindgen glue generated into dist/wasm/ by scripts/build.mjs.
export default function init(options: { module_or_path: unknown }): Promise<unknown>;
export function analyze(text: string, optsJson: string): string;
export function mask(text: string, reportJson: string, locale: string): string;
export function messages(locale: string): string;
export function deobfuscate(text: string, locale: string): string;
export function engine_version(): string;
