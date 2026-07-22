from __future__ import annotations

import csv
import os
from collections import defaultdict
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
SUMMARY_CSV = BASE_DIR / "enron_summary_results.csv"
FIGURE_DIR = BASE_DIR / "figures"
MPL_CONFIG_DIR = BASE_DIR / ".matplotlib"

MPL_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("MPLCONFIGDIR", str(MPL_CONFIG_DIR))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

SCHEME_ORDER = ["KR-PEKS", "KR-PAEKS"]
SCHEME_STYLE = {
    "KR-PEKS": {"color": "#1f77b4", "marker": "o", "linestyle": "-"},
    "KR-PAEKS": {"color": "#d62728", "marker": "s", "linestyle": "--"},
}
DATASET_TICKS = [100, 500, 1000, 5000, 10000]
DATASET_TICK_LABELS = ["100", "500", "1k", "5k", "10k"]
DPI = 300


def read_summary_rows() -> list[dict[str, str]]:
    with SUMMARY_CSV.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def average_by(rows: list[dict[str, str]], x_column: str, y_column: str) -> dict[str, list[tuple[float, float]]]:
    grouped: dict[tuple[str, float], list[float]] = defaultdict(list)
    for row in rows:
        scheme = row["scheme"]
        x_value = float(row[x_column])
        y_value = float(row[y_column])
        grouped[(scheme, x_value)].append(y_value)

    series: dict[str, list[tuple[float, float]]] = {}
    for scheme in SCHEME_ORDER:
        points = []
        for (row_scheme, x_value), values in grouped.items():
            if row_scheme == scheme:
                points.append((x_value, sum(values) / len(values)))
        series[scheme] = sorted(points)
    return series


def plot_line_chart(
    rows: list[dict[str, str]],
    *,
    x_column: str,
    y_column: str,
    x_label: str,
    y_label: str,
    title: str,
    output_name: str,
    log_x: bool = False,
) -> None:
    series = average_by(rows, x_column, y_column)

    fig, ax = plt.subplots(figsize=(8, 5))
    for scheme in SCHEME_ORDER:
        points = series.get(scheme, [])
        if not points:
            continue
        x_values = [point[0] for point in points]
        y_values = [point[1] for point in points]
        ax.plot(
            x_values,
            y_values,
            linewidth=2.2,
            markersize=8,
            label=scheme,
            **SCHEME_STYLE[scheme],
        )

    ax.set_xlabel(x_label, fontsize=15)
    ax.set_ylabel(y_label, fontsize=15)
    ax.set_title(title, fontsize=16, pad=12)
    ax.tick_params(axis="both", labelsize=13)
    ax.grid(True, which="major", linestyle="--", linewidth=0.7, alpha=0.45)
    ax.legend(fontsize=12, frameon=True)
    ax.set_axisbelow(True)

    if log_x:
        ax.set_xscale("log")
        ax.set_xticks(DATASET_TICKS)
        ax.set_xticklabels(DATASET_TICK_LABELS)
        ax.minorticks_off()
    elif x_column in {"dataset_size", "authorised_users"}:
        all_x_values = sorted({float(row[x_column]) for row in rows})
        ax.set_xticks(all_x_values)
        ax.set_xticklabels([str(int(value)) for value in all_x_values])

    fig.tight_layout()
    output_path = FIGURE_DIR / output_name
    fig.savefig(output_path, dpi=DPI, bbox_inches="tight")
    fig.savefig(output_path.with_suffix(".pdf"), bbox_inches="tight")
    plt.close(fig)


def main() -> None:
    FIGURE_DIR.mkdir(parents=True, exist_ok=True)
    rows = read_summary_rows()

    plot_line_chart(
        rows,
        x_column="dataset_size",
        y_column="total_upload_ms",
        x_label="Dataset size",
        y_label="Total upload time (ms)",
        title="Dataset Size vs. Total Upload Time",
        output_name="dataset_size_vs_upload_time.png",
        log_x=True,
    )
    plot_line_chart(
        rows,
        x_column="dataset_size",
        y_column="search_ms",
        x_label="Dataset size",
        y_label="Search, trapdoor, and test time (ms)",
        title="Dataset Size vs. Search Time",
        output_name="dataset_size_vs_search_time.png",
        log_x=True,
    )
    plot_line_chart(
        rows,
        x_column="dataset_size",
        y_column="total_retrieval_ms",
        x_label="Dataset size",
        y_label="Total retrieval time (ms)",
        title="Dataset Size vs. Total Retrieval Time",
        output_name="dataset_size_vs_retrieval_time.png",
        log_x=True,
    )
    plot_line_chart(
        rows,
        x_column="authorised_users",
        y_column="registration_ms",
        x_label="Authorised identities",
        y_label="Registration and key generation time (ms)",
        title="Authorised Identities vs. Registration Time",
        output_name="authorised_users_vs_registration_time.png",
    )

    print(f"Saved figures to {FIGURE_DIR}")


if __name__ == "__main__":
    main()
