#!/usr/bin/env python3
"""
Risk Matrix Heatmap Generator - XYZ Financial Portal
Genera un mapa de calor visual de la matriz de riesgos 4x5.
Metodologia: ISO 27005:2022 + NIST SP 800-30 Rev. 1

Columnas de probabilidad agrupadas: [1-2] [3] [4] [5]
Filas de impacto: 1 a 5
Leyenda: CRITICO (>=15) | ALTO (9-14) | MEDIO (5-8) | BAJO (1-4)
"""

import yaml
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.patheffects as pe
import numpy as np
import os
import argparse


# ── Paleta de colores ────────────────────────────────────────
COLORS = {
    'bg':       '#0B1120',
    'card':     '#131C2E',
    'border':   '#1E293B',
    'text':     '#E2E8F0',
    'muted':    '#64748B',
    'critical': '#DC2626',
    'high':     '#EA580C',
    'medium':   '#D97706',
    'low':      '#16A34A',
}


def load_risk_data(filepath="risk_register.yaml"):
    """Carga el registro de riesgos y retorna DataFrame + datos crudos."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(script_dir, filepath), 'r', encoding='utf-8') as f:
        register = yaml.safe_load(f)
    df = pd.DataFrame(register['risks'])
    return df, register


def risk_color(score):
    """Retorna color segun umbral de riesgo."""
    if score >= 15:
        return COLORS['critical']
    elif score >= 9:
        return COLORS['high']
    elif score >= 5:
        return COLORS['medium']
    return COLORS['low']


def risk_label(score):
    """Retorna etiqueta de nivel."""
    if score >= 15:
        return 'CRITICO'
    elif score >= 9:
        return 'ALTO'
    elif score >= 5:
        return 'MEDIO'
    return 'BAJO'


def generate_heatmap(df, register, output="risk_heatmap.png"):
    """Genera la matriz de riesgos 4 columnas x 5 filas."""

    # ── Mapeo de probabilidad a columnas ─────────────────
    # Columna 0 = prob 1-2 (agrupada), 1 = prob 3, 2 = prob 4, 3 = prob 5
    prob_to_col = {1: 0, 2: 0, 3: 1, 4: 2, 5: 3}
    col_representative_prob = [2, 3, 4, 5]  # prob representativa por columna
    col_labels = ['1-2', '3', '4', '5']
    n_cols, n_rows = 4, 5

    # ── Construir grid con pandas ────────────────────────
    df['col'] = df['probability'].map(prob_to_col)
    df['row'] = df['impact'] - 1  # 0-indexed

    grid = df.groupby(['col', 'row'])['id'].apply(list).to_dict()

    # ── Figura ───────────────────────────────────────────
    fig = plt.figure(figsize=(15, 11))
    fig.patch.set_facecolor(COLORS['bg'])

    # Axes principal
    ax = fig.add_axes([0.10, 0.15, 0.78, 0.68])
    ax.set_facecolor(COLORS['bg'])

    cell_w, cell_h = 1.0, 1.0

    # ── Dibujar celdas ───────────────────────────────────
    for col in range(n_cols):
        for row in range(n_rows):
            impact = row + 1
            prob = col_representative_prob[col]
            score = prob * impact
            color = risk_color(score)

            # Celda con bordes redondeados
            rect = mpatches.FancyBboxPatch(
                (col * cell_w + 0.03, row * cell_h + 0.03),
                cell_w - 0.06, cell_h - 0.06,
                boxstyle="round,pad=0.02",
                facecolor=color,
                edgecolor=COLORS['border'],
                linewidth=2,
                alpha=0.82
            )
            ax.add_patch(rect)

            # Score en esquina superior derecha (sutil)
            ax.text(
                col * cell_w + cell_w - 0.10,
                row * cell_h + cell_h - 0.08,
                str(score),
                fontsize=8, fontweight='bold', fontfamily='monospace',
                color='white', alpha=0.30,
                ha='right', va='top'
            )

            # Etiqueta de nivel en esquina inferior izquierda
            ax.text(
                col * cell_w + 0.10,
                row * cell_h + 0.10,
                risk_label(score),
                fontsize=6, fontweight='bold', fontfamily='monospace',
                color='white', alpha=0.25,
                ha='left', va='bottom'
            )

            # ── IDs de riesgo ────────────────────────────
            ids = grid.get((col, row), [])
            if ids:
                # Organizar en filas de max 2 IDs
                lines = []
                for i in range(0, len(ids), 2):
                    chunk = ids[i:i+2]
                    lines.append(',  '.join(chunk))
                text = '\n'.join(lines)

                fs = 11 if len(ids) <= 2 else 9.5 if len(ids) <= 4 else 8
                ax.text(
                    col * cell_w + cell_w / 2,
                    row * cell_h + cell_h / 2,
                    text,
                    fontsize=fs, fontweight='bold', fontfamily='monospace',
                    color='white', ha='center', va='center',
                    linespacing=1.4,
                    path_effects=[
                        pe.withStroke(linewidth=3, foreground='black', alpha=0.7)
                    ]
                )

    # ── Ejes ─────────────────────────────────────────────
    ax.set_xlim(0, n_cols * cell_w)
    ax.set_ylim(0, n_rows * cell_h)

    ax.set_xticks([i * cell_w + cell_w / 2 for i in range(n_cols)])
    ax.set_yticks([i * cell_h + cell_h / 2 for i in range(n_rows)])
    ax.set_xticklabels(col_labels, fontsize=14, fontweight='bold', color=COLORS['text'])
    ax.set_yticklabels(
        [str(i + 1) for i in range(n_rows)],
        fontsize=14, fontweight='bold', color=COLORS['text']
    )

    ax.set_xlabel(
        'PROBABILIDAD', fontsize=16, fontweight='bold',
        color=COLORS['text'], labelpad=15
    )
    ax.set_ylabel(
        'IMPACTO', fontsize=16, fontweight='bold',
        color=COLORS['text'], labelpad=15
    )

    ax.tick_params(colors=COLORS['text'], length=0)
    for spine in ax.spines.values():
        spine.set_color(COLORS['border'])
        spine.set_linewidth(2)

    # ── Titulo ───────────────────────────────────────────
    fig.suptitle(
        'Matriz de Riesgos — Portal Financiero XYZ',
        fontsize=22, fontweight='bold', color=COLORS['text'],
        y=0.92
    )
    fig.text(
        0.5, 0.875,
        'ISO 27005:2022  +  NIST SP 800-30 Rev. 1  |  Evaluacion de Seguridad Regional',
        ha='center', fontsize=11, color=COLORS['muted'], style='italic'
    )

    # ── Leyenda ──────────────────────────────────────────
    legend_items = [
        ('CRITICO  (Score >= 15)', COLORS['critical']),
        ('ALTO  (Score 9-14)',     COLORS['high']),
        ('MEDIO  (Score 5-8)',     COLORS['medium']),
        ('BAJO  (Score 1-4)',      COLORS['low']),
    ]
    patches = [
        mpatches.Patch(
            facecolor=c, edgecolor=COLORS['border'],
            linewidth=1.5, label=l
        )
        for l, c in legend_items
    ]
    leg = ax.legend(
        handles=patches, loc='upper left',
        fontsize=11, framealpha=0.95,
        facecolor=COLORS['card'], edgecolor=COLORS['border'],
        labelcolor=COLORS['text'], borderpad=0.8, handlelength=1.5
    )
    leg.get_frame().set_linewidth(2)

    # ── Barra de estadisticas ────────────────────────────
    stats = df.groupby('classification').size()
    total = len(df)
    crit = stats.get('CRITICAL', 0)
    high = stats.get('HIGH', 0)
    med = stats.get('MEDIUM', 0)
    low = stats.get('LOW', 0)

    bar_y = 0.055
    bar_h = 0.035
    bar_x = 0.10
    bar_w = 0.78

    # Fondo de la barra
    bar_bg = mpatches.FancyBboxPatch(
        (bar_x, bar_y), bar_w, bar_h,
        boxstyle="round,pad=0.005",
        transform=fig.transFigure, figure=fig,
        facecolor=COLORS['card'], edgecolor=COLORS['border'],
        linewidth=1.5
    )
    fig.patches.append(bar_bg)

    # Segmentos proporcionales
    segments = [
        (crit, COLORS['critical'], 'CRITICO'),
        (high, COLORS['high'], 'ALTO'),
        (med, COLORS['medium'], 'MEDIO'),
        (low, COLORS['low'], 'BAJO'),
    ]
    x_offset = bar_x + 0.005
    usable_w = bar_w - 0.01
    for count, color, label in segments:
        if count == 0:
            continue
        seg_w = (count / total) * usable_w
        seg = mpatches.FancyBboxPatch(
            (x_offset, bar_y + 0.004), seg_w - 0.003, bar_h - 0.008,
            boxstyle="round,pad=0.002",
            transform=fig.transFigure, figure=fig,
            facecolor=color, edgecolor='none', alpha=0.8
        )
        fig.patches.append(seg)
        if seg_w > 0.06:
            fig.text(
                x_offset + seg_w / 2, bar_y + bar_h / 2,
                f'{label}: {count}',
                ha='center', va='center',
                fontsize=9, fontweight='bold', color='white',
                fontfamily='monospace'
            )
        x_offset += seg_w

    fig.text(
        0.5, bar_y + bar_h + 0.012,
        f'Distribucion de {total} riesgos identificados',
        ha='center', fontsize=10, color=COLORS['muted']
    )

    # ── Footer ───────────────────────────────────────────
    fig.text(
        0.95, 0.015,
        'Amaris Consulting  ·  Febrero 2026',
        ha='right', fontsize=9, color=COLORS['muted']
    )

    # ── Guardar ──────────────────────────────────────────
    script_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(script_dir, output)
    plt.savefig(
        out_path, dpi=200, bbox_inches='tight',
        facecolor=fig.get_facecolor()
    )
    print(f"\n[+] Heatmap guardado: {out_path}")
    plt.close()
    return out_path


def print_summary(df):
    """Imprime resumen tabular de riesgos ordenados por score."""
    df_sorted = df.sort_values('risk_score', ascending=False)

    print("\n" + "=" * 95)
    print("  REGISTRO DE RIESGOS — Portal Financiero XYZ")
    print("=" * 95)
    print(f"  {'ID':<7} {'Riesgo':<38} {'Prob':>5} {'Imp':>5} {'Score':>6}   {'Nivel':<10}")
    print("  " + "-" * 91)

    colors = {
        'CRITICAL': '\033[91m', 'HIGH': '\033[93m',
        'MEDIUM': '\033[33m',   'LOW': '\033[92m'
    }

    for _, r in df_sorted.iterrows():
        c = colors.get(r['classification'], '')
        print(f"  {r['id']:<7} {r['name']:<38} {r['probability']:>5} "
              f"{r['impact']:>5} {r['risk_score']:>6}   "
              f"{c}{r['classification']:<10}\033[0m")

    print("  " + "-" * 91)

    # Resumen con pandas
    summary = df.groupby('classification').agg(
        count=('id', 'size'),
        avg_score=('risk_score', 'mean'),
        max_score=('risk_score', 'max')
    ).reindex(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']).fillna(0)

    print(f"\n  {'Nivel':<12} {'Cantidad':>10} {'Score Prom':>12} {'Score Max':>11}")
    print("  " + "-" * 47)
    for level, row in summary.iterrows():
        c = colors.get(level, '')
        print(f"  {c}{level:<12}\033[0m {int(row['count']):>10} "
              f"{row['avg_score']:>12.1f} {int(row['max_score']):>11}")

    print(f"\n  Total: {len(df)} riesgos | "
          f"CWEs: {df[df['cwe'] != 'N/A']['cwe'].nunique()} | "
          f"Funcionalidades: {df['functionality'].nunique()}")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Risk Matrix Heatmap — XYZ Financial Portal"
    )
    parser.add_argument("--register", default="risk_register.yaml",
                        help="Archivo YAML del registro de riesgos")
    parser.add_argument("--output", default="risk_heatmap.png",
                        help="Archivo de salida para el heatmap")
    args = parser.parse_args()

    df, register = load_risk_data(args.register)
    generate_heatmap(df, register, args.output)
    print_summary(df)
