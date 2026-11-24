import starlight from '@astrojs/starlight';
import { defineConfig } from 'astro/config';

const REPO = 'https://github.com/aionyx02/paste-warden';

// phase-3 §3.5: the playground lives at `/`, the docs at `/docs/`. A project Pages site without a
// custom domain is served under /<repo>/, so the deploy workflow can override the base.
const base = process.env.DOCS_BASE ?? '/docs/';

export default defineConfig({
  site: process.env.DOCS_SITE ?? 'https://aionyx02.github.io',
  base,
  trailingSlash: 'always',
  integrations: [
    starlight({
      title: { 'zh-TW': 'PasteWarden 剪貼簿守門員', en: 'PasteWarden' },
      description: 'PasteWarden：把剪貼簿當成信任邊界，擋下 ClickFix 假驗證指令與機密外洩。',
      logo: { src: './src/assets/logo.svg' },
      favicon: '/favicon.svg',
      defaultLocale: 'root',
      locales: {
        root: { label: '繁體中文', lang: 'zh-TW' },
        en: { label: 'English', lang: 'en' },
      },
      social: [{ icon: 'github', label: 'GitHub', href: REPO }],
      editLink: { baseUrl: `${REPO}/edit/dev/apps/docs/` },
      customCss: ['./src/styles/theme.css'],
      lastUpdated: false,
      sidebar: [
        {
          label: '使用者',
          translations: { en: 'Users' },
          items: [
            'user/intro',
            {
              label: '安裝',
              translations: { en: 'Install' },
              items: [{ autogenerate: { directory: 'user/install' } }],
            },
            'user/features',
            'user/privacy',
          ],
        },
        {
          label: '開發者',
          translations: { en: 'Developers' },
          items: [
            'dev',
            'dev/agent-hooks',
            'dev/mcp',
            {
              label: '規格',
              translations: { en: 'Specifications' },
              items: [{ autogenerate: { directory: 'dev/generated' } }],
            },
          ],
        },
      ],
    }),
  ],
});
