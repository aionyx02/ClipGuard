// §4.8.3: which paste methods each protection covers, stated plainly. The paste-confirm column
// follows the live status (§4.8.1), so the table never claims more than what works right now.
import { useT } from '@paste-warden/ui';
import type { Capability, Platform, ProtectionStatus } from '../lib/ipc';
import { cx } from './controls';

type Cell = 'covered' | 'partial' | 'not-covered' | 'unavailable';

interface Row {
  method: string;
  copy: Cell;
  confirm: Cell;
}

function fromCapability(cap: Capability | undefined): Cell {
  if (!cap || cap.state === 'active') return 'covered';
  return cap.state === 'degraded' ? 'partial' : 'unavailable';
}

export function scopeRows(platform: Platform, status: ProtectionStatus | null): Row[] {
  const copy = fromCapability(status?.watch);
  const keyboard = fromCapability(status?.intercept);
  const rows: Row[] = [
    { method: 'keyboard', copy, confirm: keyboard },
    { method: 'context-menu', copy, confirm: 'not-covered' },
    { method: 'edit-menu', copy, confirm: 'not-covered' },
    { method: 'drag-drop', copy, confirm: 'not-covered' },
    { method: 'remote-desktop', copy, confirm: 'not-covered' },
  ];
  if (platform === 'windows') rows.push({ method: 'elevated', copy, confirm: 'not-covered' });
  if (platform === 'macos') rows.push({ method: 'secure-input', copy, confirm: 'not-covered' });
  if (platform === 'linux') {
    rows.push({ method: 'middle-click', copy: 'not-covered', confirm: 'not-covered' });
  }
  return rows;
}

const CELL_STYLE: Record<Cell, string> = {
  covered: 'text-allow',
  partial: 'text-warn',
  'not-covered': 'text-quarantine',
  unavailable: 'text-quarantine',
};

const CELL_MARK: Record<Cell, string> = {
  covered: '✓',
  partial: '!',
  'not-covered': '✕',
  unavailable: '✕',
};

function CellView({ cell }: { cell: Cell }) {
  const t = useT();
  return (
    <td className={cx('px-3 py-2 text-sm', CELL_STYLE[cell])} data-cell={cell}>
      <span aria-hidden="true" className="mr-1.5 font-bold">
        {CELL_MARK[cell]}
      </span>
      {t(`ui-desktop-scope-cell-${cell}`)}
    </td>
  );
}

export function ScopeTable({
  platform,
  status,
}: {
  platform: Platform;
  status: ProtectionStatus | null;
}) {
  const t = useT();
  const rows = scopeRows(platform, status);
  return (
    <>
      <div className="overflow-x-auto rounded-lg border border-line">
        <table className="w-full border-collapse text-left">
          <caption className="sr-only">{t('ui-desktop-scope-caption')}</caption>
          <thead className="bg-surface-2 text-xs text-fg-muted">
            <tr>
              <th scope="col" className="px-3 py-2 font-medium">
                {t('ui-desktop-scope-col-method')}
              </th>
              <th scope="col" className="px-3 py-2 font-medium">
                {t('ui-desktop-scope-col-copy')}
              </th>
              <th scope="col" className="px-3 py-2 font-medium">
                {t('ui-desktop-scope-col-confirm')}
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {rows.map((r) => (
              <tr key={r.method} data-method={r.method}>
                <th scope="row" className="px-3 py-2 text-sm font-medium">
                  {t(`ui-desktop-scope-method-${r.method}`, { platform })}
                </th>
                <CellView cell={r.copy} />
                <CellView cell={r.confirm} />
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <ul className="mt-3 list-disc space-y-1 pl-5 text-xs leading-relaxed text-fg-muted">
        <li>{t('ui-desktop-scope-note-commands')}</li>
        <li>{t('ui-desktop-scope-note-secrets')}</li>
        {platform === 'windows' ? <li>{t('ui-desktop-scope-note-elevated')}</li> : null}
      </ul>
    </>
  );
}

const LIMITS: Record<Platform, number[]> = {
  windows: [1, 2],
  macos: [1, 2, 3],
  linux: [1, 2, 3, 4],
};

/** Platform limits the user should know about (§4.9.1, §4.9.2, §4.10). */
export function PlatformLimits({ platform }: { platform: Platform }) {
  const t = useT();
  return (
    <ul className="list-disc space-y-1.5 pl-5 text-sm leading-relaxed text-fg">
      {LIMITS[platform].map((n) => {
        const id = `ui-desktop-limits-${platform}-${n}`;
        return <li key={id}>{t(id)}</li>;
      })}
    </ul>
  );
}
