"""Write ``report.json``, ``report.md`` and the SVG charts (§5.4).

Each chart is written twice: ``<name>.svg`` (light) and ``<name>-dark.svg``.
Backgrounds are transparent; text and grid use the theme's inks, so the
docs site can pick the file that matches the reader's color scheme.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use('Agg')

import matplotlib.pyplot as plt  # noqa: E402

from .models import Report  # noqa: E402

THEMES = {
    'light': {
        'text': '#191919',
        'muted': '#666666',
        'grid': '#e3e3e3',
        'series': ('#257de0', '#f47230', '#00b894'),
    },
    'dark': {
        'text': '#efefef',
        'muted': '#9c9c9c',
        'grid': '#3a3a3a',
        'series': ('#338ced', '#e76624', '#00a888'),
    },
}
CHARTS = ('detection-fp', 'rounds', 'techniques')
# `redteam report` writes to REPORTS_DIR / <date> (§5.4).
REPORTS_DIR = Path(__file__).resolve().parents[3] / 'reports'


def _pct(x: float | None) -> str:
    return '–' if x is None else f'{x * 100:.1f}%'


def _style(ax, theme: dict, ylabel: str | None = None) -> None:
    ax.set_facecolor('none')
    for side in ('top', 'right'):
        ax.spines[side].set_visible(False)
    for side in ('left', 'bottom'):
        ax.spines[side].set_color(theme['muted'])
    ax.tick_params(colors=theme['muted'], labelcolor=theme['text'])
    ax.grid(axis='y', color=theme['grid'], linewidth=0.8)
    ax.set_axisbelow(True)
    if ylabel:
        ax.set_ylabel(ylabel, color=theme['muted'])


def _legend(ax, theme: dict) -> None:
    leg = ax.legend(frameon=False, loc='best')
    for t in leg.get_texts():
        t.set_color(theme['text'])


def _save(fig, path: Path) -> None:
    fig.patch.set_alpha(0)
    fig.savefig(path, format='svg', transparent=True, bbox_inches='tight')
    plt.close(fig)


def _title(ax, text: str, theme: dict) -> None:
    ax.set_title(text, color=theme['text'], loc='left', fontsize=11)


def chart_detection_fp(report: Report, theme: dict, path: Path) -> None:
    versions = list(report.versions)
    x = list(range(len(versions)))
    det = {d.version: d for d in report.detection if d.split == 'heldout'}
    fp = {f.version: f for f in report.false_positives if f.dataset == 'all'}
    lines = [
        (
            'heldout detection',
            [det.get(v) and det[v].detection_rate for v in versions],
        ),
        (
            'heldout ≥ warn',
            [det.get(v) and det[v].at_least_warn_rate for v in versions],
        ),
        ('false positives', [fp.get(v) and fp[v].fp_rate for v in versions]),
    ]
    fig, ax = plt.subplots(figsize=(6.4, 3.6))
    for (label, ys), color in zip(lines, theme['series'], strict=True):
        pts = [
            (xi, y * 100) for xi, y in zip(x, ys, strict=True) if y is not None
        ]
        if not pts:
            continue
        ax.plot(
            [p[0] for p in pts],
            [p[1] for p in pts],
            marker='o',
            markersize=6,
            linewidth=2,
            color=color,
            label=label,
        )
        last = pts[-1]
        ax.annotate(
            f'{last[1]:.1f}%',
            last,
            textcoords='offset points',
            xytext=(6, 0),
            va='center',
            color=theme['text'],
            fontsize=9,
        )
    ax.set_xticks(x, versions)
    ax.set_ylim(0, 105)
    _style(ax, theme, 'percent')
    _title(ax, 'Detection rate and false-positive rate by version', theme)
    _legend(ax, theme)
    _save(fig, path)


def chart_rounds(report: Report, theme: dict, path: Path) -> None:
    rounds = sorted({a.round for a in report.attack_success})
    gens = ('g0', 'g1')
    width = 0.38
    fig, ax = plt.subplots(figsize=(6.4, 3.6))
    for k, (gen, color) in enumerate(zip(gens, theme['series'], strict=False)):
        rows = {a.round: a for a in report.attack_success if a.generator == gen}
        xs = [r + (k - 0.5) * width for r in rounds if r in rows]
        ys = [(rows[r].success_rate or 0) * 100 for r in rounds if r in rows]
        if not xs:
            continue
        bars = ax.bar(
            xs, ys, width=width - 0.04, color=color, label=gen.upper()
        )
        ax.bar_label(
            bars, fmt='%.1f%%', color=theme['text'], fontsize=9, padding=2
        )
    ax.set_xticks(rounds, [f'round {r}' for r in rounds])
    ax.set_ylim(0, 105)
    _style(ax, theme, 'not blocked (%)')
    _title(ax, 'Attacker success rate per round (train)', theme)
    if rounds:
        _legend(ax, theme)
    _save(fig, path)


def chart_techniques(report: Report, theme: dict, path: Path) -> None:
    latest = report.versions[-1] if report.versions else None
    rows = [t for t in report.techniques if t.version == latest]
    rows.sort(key=lambda t: (t.detection_rate or 0))
    height = max(2.4, 0.28 * len(rows) + 1)
    fig, ax = plt.subplots(figsize=(6.4, height))
    labels = [t.technique + ('' if t.semantic else ' *') for t in rows]
    vals = [(t.detection_rate or 0) * 100 for t in rows]
    bars = ax.barh(labels, vals, color=theme['series'][0], height=0.7)
    ax.bar_label(bars, fmt='%.0f%%', color=theme['text'], fontsize=8, padding=2)
    ax.set_xlim(0, 110)
    _style(ax, theme)
    ax.grid(axis='y', visible=False)
    ax.grid(axis='x', color=theme['grid'], linewidth=0.8)
    ax.set_xlabel('quarantined (%)', color=theme['muted'])
    _title(
        ax,
        f'Detection rate per technique ({latest or "-"};'
        ' * = normalization probe)',
        theme,
    )
    _save(fig, path)


def write_charts(report: Report, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for name, fn in zip(
        CHARTS,
        (chart_detection_fp, chart_rounds, chart_techniques),
        strict=True,
    ):
        for mode, theme in THEMES.items():
            suffix = '' if mode == 'light' else '-dark'
            path = out_dir / f'{name}{suffix}.svg'
            with plt.rc_context({'svg.hashsalt': 'paste-warden'}):
                fn(report, theme, path)
            paths.append(path)
    return paths


def render_markdown(report: Report) -> str:
    out = [
        '# PasteWarden red-team report',
        '',
        f'Generated {report.generated_at}. Versions: '
        + ', '.join(
            f'{v} (`{report.rules_revs[v][:12]}`)' for v in report.versions
        )
        + '.',
        '',
        '## 1. Detection rate (syntax-valid malicious variants)',
        '',
        '| Version | Split | Valid | Quarantine | Warn | Allow | Detection |'
        ' ≥ warn |',
        '|---|---|---:|---:|---:|---:|---:|---:|',
    ]
    for d in report.detection:
        out.append(
            f'| {d.version} | {d.split} | {d.valid} | {d.blocked} | '
            f'{d.downgraded} | {d.bypassed} | {_pct(d.detection_rate)} | '
            f'{_pct(d.at_least_warn_rate)} |'
        )
    out += [
        '',
        '## 2. False-positive rate (benign)',
        '',
        '| Version | Dataset | N | Warn | Quarantine | FP rate |',
        '|---|---|---:|---:|---:|---:|',
    ]
    for f in report.false_positives:
        out.append(
            f'| {f.version} | {f.dataset} | {f.n} | {f.warn} | '
            f'{f.quarantine} | {_pct(f.fp_rate)} |'
        )
    out += [
        '',
        '## 3. Attacker success rate (new train variants per round)',
        '',
        '| Round | Version | Generator | Valid | Not blocked | Allowed | '
        'Success | G1 equivalent | G1 unconfirmed |',
        '|---:|---|---|---:|---:|---:|---:|---:|---:|',
    ]
    for a in report.attack_success:
        out.append(
            f'| {a.round} | {a.version} | {a.generator} | {a.valid} | '
            f'{a.not_blocked} | {a.allowed} | {_pct(a.success_rate)} | '
            f'{a.confirmed_equivalent} | {a.unconfirmed} |'
        )
    out += [
        '',
        '## 4. Patch cost (blue-team PRs)',
        '',
        '| Round | PR | Rule lines | Cases added | Heldout p99 | Budget ok | '
        'Minutes | Turns | Model |',
        '|---:|---|---:|---:|---:|---|---:|---:|---|',
    ]
    for p in report.patch_cost:
        p99 = '–' if p.heldout_p99_us is None else f'{p.heldout_p99_us} µs'
        ok = {None: '–', True: 'yes', False: '**no**'}[p.within_budget]
        out.append(
            f'| {p.round} | {p.pr or "–"} | {p.rules_lines_changed} | '
            f'{p.corpus_cases_added} | {p99} | {ok} | '
            f'{p.blue_minutes if p.blue_minutes is not None else "–"} | '
            f'{p.blue_turns if p.blue_turns is not None else "–"} | '
            f'{p.model or "–"} |'
        )
    out += [
        '',
        '## Latency (heldout)',
        '',
        '| Version | N | p50 | p99 | max |',
        '|---|---:|---:|---:|---:|',
    ]
    for lat in report.latency:
        out.append(
            f'| {lat.version} | {lat.n} | {lat.p50_us} µs | {lat.p99_us} µs | '
            f'{lat.max_us} µs |'
        )
    out += [
        '',
        '## Syntax validity',
        '',
        '| Generator | Total | Valid | Rate | Statuses |',
        '|---|---:|---:|---:|---|',
    ]
    for v in report.validity:
        statuses = ', '.join(f'{k}: {n}' for k, n in v.statuses.items())
        out.append(
            f'| {v.generator} | {v.total} | {v.valid} | '
            f'{_pct(v.valid_rate)} | {statuses} |'
        )
    if report.generation:
        out += [
            '',
            '## Generation',
            '',
            '| Round | Generator | Model | Requested | Produced | Refused | '
            'Invalid output |',
            '|---:|---|---|---:|---:|---:|---:|',
        ]
        for g in report.generation:
            out.append(
                f'| {g.round} | {g.generator} | {g.model or "–"} | '
                f'{g.requested} | {g.produced} | {g.refused} '
                f'({_pct(g.refusal_rate)}) | {g.invalid_output} '
                f'({_pct(g.invalid_output_rate)}) |'
            )
    latest = report.versions[-1] if report.versions else None
    out += [
        '',
        f'## Detection per technique ({latest or "–"})',
        '',
        '`*` marks normalization probes (zero-width, homoglyph, full-width):'
        ' not runnable as written, kept to test normalization.',
        '',
        '| Technique | N | Quarantine | ≥ warn |',
        '|---|---:|---:|---:|',
    ]
    for t in report.techniques:
        if t.version != latest:
            continue
        star = '' if t.semantic else ' *'
        out.append(
            f'| `{t.technique}`{star} | {t.n} | {_pct(t.detection_rate)} | '
            f'{_pct(t.at_least_warn_rate)} |'
        )
    if report.notes:
        out += ['', '## Notes', ''] + [f'- {n}' for n in report.notes]
    out += [
        '',
        '![Detection and false positives](detection-fp.svg)',
        '![Attacker success per round](rounds.svg)',
        '![Detection per technique](techniques.svg)',
        '',
    ]
    return '\n'.join(out)


def write_report(report: Report, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / 'report.json'
    json_path.write_text(
        report.model_dump_json(indent=2) + '\n', encoding='utf-8'
    )
    md_path = out_dir / 'report.md'
    md_path.write_text(render_markdown(report), encoding='utf-8')
    return [json_path, md_path, *write_charts(report, out_dir)]
