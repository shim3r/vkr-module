import matplotlib.pyplot as plt
import numpy as np

# Данные
quarters = ['Q1 2024', 'Q2 2024', 'Q3 2024', 'Q4 2024', 'Q1 2025', 'Q2 2025', 'Q3 2025']
global_attacked = [24.4, 23.5, 22.0, 21.9, 21.9, 20.5, 20.1]

q_recent = quarters[-4:]
internet   = [9.98, 10.11, 9.76, 7.99]
email      = [2.72, 2.81, 3.06, 3.01]
removable  = [0.64, 0.52, 0.37, 0.33]
network    = [0.08, 0.07, 0.05, 0.04]

scripts    = [7.11, 7.16, 6.49, 6.79]
denylisted = [5.52, 5.12, 5.91, 4.01]
spyware    = [4.30, 4.20, 3.84, 4.04]

# ──────────────────────────────────────────────────────────────
plt.style.use('default')

fig = plt.figure(figsize=(15, 11.5))
fig.patch.set_facecolor('#f9fbfc')

# Главный график
ax1 = fig.add_subplot(2, 1, 1)
ax1.plot(quarters, global_attacked, marker='o', linewidth=3, markersize=10,
         color='#0066cc', label='Доля атакованных ICS-компьютеров')

ax1.fill_between(quarters, global_attacked, color='#0066cc', alpha=0.07)

ax1.set_title('Динамика атак на промышленные системы управления\n'
              '(Kaspersky ICS CERT, глобальные данные 2024–2025 гг.)',
              fontsize=17, fontweight='bold', pad=20)

ax1.set_ylabel('Доля атакованных компьютеров, %', fontsize=14)
ax1.set_ylim(18, 26)
ax1.set_yticks(np.arange(18, 27, 1))
ax1.grid(True, linestyle='--', alpha=0.35, color='gray')

ax1.tick_params(axis='both', labelsize=13)
ax1.spines['top'].set_visible(False)
ax1.spines['right'].set_visible(False)

ax1.legend(loc='upper right', fontsize=13, frameon=True, 
           edgecolor='lightgray', facecolor='white')

# Нижние графики с большими отступами
gs = fig.add_gridspec(2, 2, height_ratios=[3, 2.3],
                      top=0.84,      # ← больше места сверху
                      bottom=0.07,   # ↑ больше места снизу
                      left=0.07,     # ← больше слева
                      right=0.96,    # → больше справа
                      hspace=0.50,   # вертикальное расстояние между верхом и низом
                      wspace=0.35)   # горизонтальное расстояние между графиками

ax2 = fig.add_subplot(gs[1, 0])
ax3 = fig.add_subplot(gs[1, 1])

x = np.arange(len(q_recent))
width = 0.19

ax2.bar(x - 1.5*width, internet, width, label='Интернет', color='#e74c3c')
ax2.bar(x - 0.5*width, email,    width, label='Почта', color='#27ae60')
ax2.bar(x + 0.5*width, removable, width, label='Съёмные носители', color='#f39c12')
ax2.bar(x + 1.5*width, network,   width, label='Сетевые папки', color='#8e44ad')

ax2.set_title('Основные источники угроз (глобально)', fontsize=15, pad=18)
ax2.set_xticks(x)
ax2.set_xticklabels(q_recent, fontsize=12, rotation=15)
ax2.set_ylim(0, 12)
ax2.grid(axis='y', linestyle='--', alpha=0.3)
ax2.tick_params(labelsize=12)
ax2.legend(fontsize=11, ncol=2, loc='upper center', frameon=True, bbox_to_anchor=(0.5, -0.18))

ax3.plot(q_recent, scripts,    marker='o', label='Вредоносные скрипты', color='#e67e22', lw=2.5)
ax3.plot(q_recent, denylisted, marker='s', label='Запрещённые ресурсы', color='#3498db', lw=2.5)
ax3.plot(q_recent, spyware,    marker='^', label='Шпионское ПО', color='#c0392b', lw=2.5)

ax3.set_title('Ключевые категории угроз', fontsize=15, pad=18)
ax3.set_ylim(0, 9)
ax3.grid(axis='y', linestyle='--', alpha=0.3)
ax3.tick_params(labelsize=12)
ax3.legend(fontsize=11, ncol=1, loc='upper right', frameon=True)

# Главный общий заголовок — короче и выше
plt.suptitle('Ландшафт киберугроз для промышленных систем\n',
             fontsize=20, fontweight='bold', y=0.96)

# Финальная настройка отступов (самое важное)
fig.subplots_adjust(
    left=0.07,
    right=0.96,
    top=0.84,     # ← основной контроль отступа сверху
    bottom=0.07,
    wspace=0.35,
    hspace=0.50
)

plt.savefig('kaspersky_ics_threats_final_ru.png', dpi=400, bbox_inches='tight', facecolor=fig.get_facecolor())
plt.show()