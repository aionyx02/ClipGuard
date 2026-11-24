//! Criterion benchmarks with the performance budgets of phase-1.md §1.6:
//! typical 1 KB input ≤ 1 ms; 1 Mi-char pathological input ≤ 150 ms.
//! Run: `cargo bench -p paste-warden-core`.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use paste_warden_core::secret::{self, PackSet};
use paste_warden_core::{command, hidden, wallet};

fn typical() -> String {
    let mut s = String::from(
        "Meeting notes 2026-11-24: deploy at 15:30, ticket #4821, call 02-2555-6666.\n\
         Run `cargo test --workspace` then `git push origin feature/x`.\n\
         See https://example.invalid/docs?id=42 for details.\n",
    );
    while s.len() < 1024 {
        s.push_str("The quick brown fox jumps over the lazy dog. 這是一段一般的中文句子。\n");
    }
    s
}

fn pathological() -> Vec<(&'static str, String)> {
    let mi = 1 << 20;
    vec![
        ("keywords", "api_key token secret password ".repeat(mi / 30)),
        (
            "assignments",
            "api_key=aB3dE5gH7jK9mN1pQ3sT5vX7zA9cE1gI ".repeat(mi / 40),
        ),
        ("digits", "4111 1111 1111 1111 A123456789 ".repeat(mi / 30)),
        (
            "powershell",
            "powershell -w hidden iex irm ".repeat(mi / 30),
        ),
        ("whitespace", " ".repeat(mi)),
        ("cjk", "中".repeat(mi)),
    ]
}

fn bench(c: &mut Criterion) {
    let t = typical();
    let mut g = c.benchmark_group("typical-1k");
    g.bench_function("command::analyze", |b| {
        b.iter(|| command::analyze(black_box(&t)))
    });
    g.bench_function("secret::find", |b| {
        b.iter(|| secret::find(black_box(&t), &PackSet::default()))
    });
    g.bench_function("hidden::analyze", |b| {
        b.iter(|| hidden::analyze(black_box(&t)))
    });
    g.bench_function("wallet::find_all", |b| {
        b.iter(|| wallet::find_all(black_box(&t)))
    });
    g.finish();

    let mut g = c.benchmark_group("pathological-1mi");
    g.sample_size(10);
    for (name, input) in pathological() {
        g.bench_function(format!("command::analyze/{name}"), |b| {
            b.iter(|| command::analyze(black_box(&input)))
        });
        g.bench_function(format!("secret::find/{name}"), |b| {
            b.iter(|| secret::find(black_box(&input), &PackSet::default()))
        });
        g.bench_function(format!("hidden::analyze/{name}"), |b| {
            b.iter(|| hidden::analyze(black_box(&input)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
