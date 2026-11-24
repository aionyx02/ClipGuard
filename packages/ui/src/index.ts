export { ActionIcon, ShieldMark } from './components/icons';
export { MaskPreview, type MaskPreviewProps, segmentMasked } from './components/MaskPreview';
export { OnionTrace, type OnionTraceProps } from './components/OnionTrace';
export { LocaleSwitcher, ThemeSwitcher } from './components/Preferences';
export { SecretList, type SecretListProps } from './components/SecretList';
export { VerdictCard, type VerdictCardProps } from './components/VerdictCard';
export { createBundles, matchLocale, type Translate, translator } from './i18n/fluent';
export {
  LOCALE_STORAGE_KEY,
  type LocaleMode,
  LocaleProvider,
  type LocaleProviderProps,
  useLocale,
  useT,
} from './i18n/LocaleProvider';
export type * from './report';
export { localPreferenceStore, type PreferenceStore } from './storage';
export {
  type ResolvedTheme,
  THEME_STORAGE_KEY,
  type ThemeMode,
  ThemeProvider,
  type ThemeProviderProps,
  useTheme,
} from './theme/ThemeProvider';
