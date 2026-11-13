#!/usr/bin/env python3
import argparse
import datetime
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
import generate_routeros_services as core

CATEGORY_NAMES = {
    'AI': 'AI',
    'Books': 'Книги',
    'Content': 'Контент',
    'Dev': 'Разработка',
    'Docs': 'Документация',
    'FPV': 'FPV и оборудование',
    'Gaming': 'Игры',
    'Messaging': 'Мессенджеры',
    'Music': 'Музыка',
    'Network': 'Сети',
    'News': 'Новости',
    'Other': 'Прочее',
    'Payment': 'Платежи',
    'Productivity': 'Работа и документы',
    'Security': 'Безопасность',
    'Social': 'Социальные сети',
    'Torrents': 'Торренты',
    'Video': 'Видео',
    'VPN': 'VPN',
}
EXPORT_ADDRESS = '/ip firewall address-list export terse where comment~"hynet:"'
EXPORT_DNS = '/ip dns static export terse where comment~"hynet:"'
MAX_SAFE_COMMANDS = 80


class ServiceManager(tk.Tk):
    def __init__(self, catalog_path, selection_path, rsh_path, target='rb4011'):
        super().__init__()
        self.title('MikroTik Service Manager')
        self.geometry('1240x780')
        self.minsize(980, 640)
        self.catalog_path = catalog_path
        self.selection_path = selection_path
        self.rsh_path = rsh_path
        self.catalog, self.services = core.load_catalog(catalog_path)
        self.checked = set(core.load_selection(selection_path, self.services))
        self.saved_checked = set(self.checked)
        self.current_text = ''
        self.current_static = set()
        self.current_fwd = set()
        self.current_a = set()
        self.current_source = ''
        self.diff_text = ''
        self.diff_summary = {}
        self.events = queue.Queue()
        self.busy = False
        self._closing = False
        self.search_var = tk.StringVar()
        self.filter_var = tk.StringVar(value='Все')
        self.target_var = tk.StringVar(value=target)
        self.summary_var = tk.StringVar()
        self.state_var = tk.StringVar(value='Состояние роутера не загружено')
        self._configure_style()
        self._build_ui()
        self._populate()
        self._show_placeholder()
        self.protocol('WM_DELETE_WINDOW', self._on_close)
        self.bind('<Control-s>', lambda event: self.save_selection())
        self.bind('<Control-Return>', lambda event: self.show_diff())
        self.bind('<F5>', lambda event: self.fetch_router())
        self.after(100, self._poll_events)

    def _configure_style(self):
        style = ttk.Style(self)
        if 'vista' in style.theme_names():
            style.theme_use('vista')
        style.configure('Treeview', rowheight=25, font=('Segoe UI', 10))
        style.configure('Treeview.Heading', font=('Segoe UI', 9, 'bold'))
        style.configure('Accent.TButton', font=('Segoe UI', 10, 'bold'))

    def _build_ui(self):
        outer = ttk.Frame(self, padding=8)
        outer.pack(fill='both', expand=True)
        toolbar = ttk.Frame(outer)
        toolbar.pack(fill='x', pady=(0, 6))
        ttk.Label(toolbar, text='Роутер:').pack(side='left')
        self.target_combo = ttk.Combobox(
            toolbar, textvariable=self.target_var, width=14,
            values=('rb4011', 'rb4011-zt', 'rb5009'),
        )
        self.target_combo.pack(side='left', padx=(4, 8))
        self.fetch_button = ttk.Button(toolbar, text='Получить состояние (F5)', command=self.fetch_router)
        self.fetch_button.pack(side='left')
        ttk.Button(toolbar, text='Импорт export', command=self.import_exports).pack(side='left', padx=4)
        ttk.Button(toolbar, text='Сохранить выбор (Ctrl+S)', command=self.save_selection).pack(side='left', padx=(16, 4))
        ttk.Button(toolbar, text='Полный RSC', command=self.export_full).pack(side='left', padx=4)
        ttk.Button(
            toolbar, text='Показать diff (Ctrl+Enter)', command=self.show_diff,
            style='Accent.TButton',
        ).pack(side='right')

        filters = ttk.Frame(outer)
        filters.pack(fill='x', pady=(0, 6))
        ttk.Label(filters, text='Поиск:').pack(side='left')
        search = ttk.Entry(filters, textvariable=self.search_var, width=28)
        search.pack(side='left', padx=(4, 10))
        search.bind('<KeyRelease>', lambda event: self._populate())
        ttk.Combobox(
            filters, textvariable=self.filter_var, state='readonly', width=18,
            values=('Все', 'Включённые', 'Выключенные', 'Изменённые'),
        ).pack(side='left')
        self.filter_var.trace_add('write', lambda *args: self._populate())
        ttk.Button(filters, text='Выбрать видимые', command=lambda: self._set_visible(True)).pack(side='left', padx=(12, 2))
        ttk.Button(filters, text='Снять видимые', command=lambda: self._set_visible(False)).pack(side='left', padx=2)
        ttk.Label(filters, textvariable=self.summary_var, foreground='#555').pack(side='right')

        pane = ttk.PanedWindow(outer, orient='horizontal')
        pane.pack(fill='both', expand=True)
        tree_frame = ttk.Frame(pane)
        pane.add(tree_frame, weight=3)
        self.tree = ttk.Treeview(
            tree_frame, columns=('check', 'fqdn', 'cidr', 'dns', 'state'),
            show='tree headings', selectmode='browse',
        )
        self.tree.heading('#0', text='Категория / сервис')
        self.tree.heading('check', text='✓')
        self.tree.heading('fqdn', text='FQDN')
        self.tree.heading('cidr', text='IPv4')
        self.tree.heading('dns', text='DNS')
        self.tree.heading('state', text='Состояние')
        self.tree.column('#0', width=330, anchor='w')
        self.tree.column('check', width=38, stretch=False, anchor='center')
        self.tree.column('fqdn', width=58, stretch=False, anchor='e')
        self.tree.column('cidr', width=58, stretch=False, anchor='e')
        self.tree.column('dns', width=52, stretch=False, anchor='e')
        self.tree.column('state', width=105, stretch=False, anchor='center')
        self.tree.tag_configure('category', background='#e9eef5', font=('Segoe UI', 10, 'bold'))
        self.tree.tag_configure('selected', background='#e2f3e3')
        self.tree.tag_configure('changed', background='#fff0d5')
        scroll = ttk.Scrollbar(tree_frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side='left', fill='both', expand=True)
        scroll.pack(side='right', fill='y')
        self.tree.bind('<Button-1>', self._on_tree_click)
        self.tree.bind('<<TreeviewSelect>>', self._on_select)
        self.tree.bind('<space>', self._on_space)

        details_frame = ttk.LabelFrame(pane, text=' Детали сервиса ')
        pane.add(details_frame, weight=2)
        self.details = scrolledtext.ScrolledText(
            details_frame, state='disabled', wrap='word', font=('Segoe UI', 10),
            relief='flat', padx=10, pady=10,
        )
        self.details.pack(fill='both', expand=True)
        self.details.tag_configure('h1', font=('Segoe UI', 14, 'bold'), spacing3=8)
        self.details.tag_configure('h2', font=('Segoe UI', 10, 'bold'), spacing1=10, spacing3=3)
        self.details.tag_configure('muted', foreground='#777')
        self.details.tag_configure('mono', font=('Consolas', 9))
        self.details.tag_configure('ok', foreground='#187718')
        self.details.tag_configure('warn', foreground='#9a5500')

        bottom = ttk.Frame(outer)
        bottom.pack(fill='x', pady=(6, 0))
        ttk.Label(bottom, textvariable=self.state_var, foreground='#555').pack(side='left')
        self.apply_button = ttk.Button(bottom, text='Применить diff…', command=self.apply_diff)
        self.apply_button.pack(side='right')

    def _visible_services(self):
        query = self.search_var.get().strip().lower()
        mode = self.filter_var.get()
        result = []
        for sid, service in self.services.items():
            if query and query not in f'{sid} {service["name"]}'.lower():
                continue
            selected = sid in self.checked
            if mode == 'Включённые' and not selected:
                continue
            if mode == 'Выключенные' and selected:
                continue
            if mode == 'Изменённые' and not self._service_changed(sid):
                continue
            result.append(sid)
        return result

    def _populate(self):
        if not hasattr(self, 'tree'):
            return
        selected_iid = self.tree.focus()
        self.tree.delete(*self.tree.get_children())
        visible = set(self._visible_services())
        categories = {}
        for sid in visible:
            service = self.services[sid]
            categories.setdefault(service.get('category', 'Other'), []).append(sid)
        for category in sorted(categories, key=lambda value: CATEGORY_NAMES.get(value, value)):
            cat_iid = f'cat:{category}'
            self.tree.insert(
                '', 'end', iid=cat_iid,
                text=f'{CATEGORY_NAMES.get(category, category)} ({len(categories[category])})',
                values=('', '', '', '', ''), tags=('category',), open=True,
            )
            for sid in categories[category]:
                service = self.services[sid]
                state = self._router_state(sid)
                tags = []
                if sid in self.checked:
                    tags.append('selected')
                if self._service_changed(sid):
                    tags.append('changed')
                self.tree.insert(
                    cat_iid, 'end', iid=f'svc:{sid}', text=service['name'],
                    values=(
                        '☑' if sid in self.checked else '☐',
                        len(core.service_fqdn(service)),
                        len(core.service_cidr(service)) + len(service.get('dns_a_overrides', {})),
                        len(service.get('dns_subdomains', [])) + len(service.get('dns_a_overrides', {})), state,
                    ), tags=tags,
                )
        changed = len(self.checked ^ self.saved_checked)
        self.summary_var.set(f'Выбрано: {len(self.checked)} из {len(self.services)}  ·  Несохранено: {changed}')
        if selected_iid and self.tree.exists(selected_iid):
            self.tree.focus(selected_iid)
            self.tree.selection_set(selected_iid)

    def _service_changed(self, sid):
        if (sid in self.checked) != (sid in self.saved_checked):
            return True
        if not self.current_text:
            return False
        return self._router_state(sid) not in ('', 'совпадает')

    def _router_state(self, sid):
        if not self.current_text:
            return ''
        selected = [sid] if sid in self.checked else []
        expected_static, expected_fwd, expected_a = core.desired_state(self.catalog, self.services, selected)
        expected_static = {item for item in expected_static if item[0] != 'healthcheck'}
        actual_static = {
            item for item in self.current_static
            if item[0] == sid and item[1] != self.catalog['healthcheck_fqdn']
        }
        actual_fwd = {item for item in self.current_fwd if item[0] == sid}
        actual_a = {item for item in self.current_a if item[0] == sid}
        if expected_static == actual_static and expected_fwd == actual_fwd and expected_a == actual_a:
            return 'совпадает'
        if not actual_static and not actual_fwd and not actual_a:
            return 'добавить'
        if not expected_static and not expected_fwd and not expected_a:
            return 'удалить'
        return 'изменить'

    def _on_tree_click(self, event):
        row = self.tree.identify_row(event.y)
        column = self.tree.identify_column(event.x)
        if row.startswith('svc:') and column in ('#0', '#1'):
            self._toggle(row[4:])
            return 'break'

    def _on_space(self, event):
        row = self.tree.focus()
        if row.startswith('svc:'):
            self._toggle(row[4:])
            return 'break'

    def _toggle(self, sid):
        if sid in self.checked:
            self.checked.remove(sid)
        else:
            self.checked.add(sid)
        self._populate()
        self._show_service(sid)

    def _set_visible(self, enabled):
        visible = self._visible_services()
        if enabled:
            self.checked.update(visible)
        else:
            self.checked.difference_update(visible)
        self._populate()

    def _on_select(self, event=None):
        row = self.tree.focus()
        if row.startswith('svc:'):
            self._show_service(row[4:])

    def _set_details(self, parts):
        self.details.configure(state='normal')
        self.details.delete('1.0', 'end')
        for text, tag in parts:
            self.details.insert('end', text, tag)
        self.details.configure(state='disabled')

    def _show_placeholder(self):
        self._set_details([
            ('MikroTik Service Manager\n', 'h1'),
            (f'Каталог: {len(self.services)} сервисов\n', 'muted'),
            ('\nОтметьте сервисы, сохраните выбор и получите состояние роутера.\n', ''),
            ('Diff формируется локально. Применение возможно только после явного подтверждения и создаёт backup.\n', 'muted'),
        ])

    def _show_service(self, sid):
        service = self.services[sid]
        selected = sid in self.checked
        parts = [
            (service['name'] + '\n', 'h1'),
            (f'{CATEGORY_NAMES.get(service.get("category"), service.get("category"))} · {sid}\n', 'muted'),
            (('\nВключён' if selected else '\nВыключен') + '\n', 'ok' if selected else 'warn'),
        ]
        if self.current_text:
            parts.append((f'Состояние: {self._router_state(sid)}\n', 'muted'))
        if service.get('description'):
            parts.append(('\n' + service['description'] + '\n', ''))
        for title, key, values in (
            ('FQDN', 'fqdn', core.service_fqdn(service)),
            ('IPv4 CIDR', 'cidr', core.service_cidr(service)),
            ('DNS FWD с поддоменами', 'dns', service.get('dns_subdomains', [])),
        ):
            parts.append((f'\n{title}: {len(values)}\n', 'h2'))
            parts.append(('\n'.join(values) + '\n' if values else 'Нет записей\n', 'mono'))
        overrides = service.get('dns_a_overrides', {})
        parts.append((f'\nDNS A-override: {len(overrides)}\n', 'h2'))
        parts.append((
            '\n'.join(f'{domain} -> {address}' for domain, address in overrides.items()) + '\n'
            if overrides else 'Нет записей\n', 'mono'
        ))
        upstream = service.get('upstream', [])
        parts.append((f'\nИсточники: {len(upstream)}\n', 'h2'))
        if upstream:
            for source in upstream:
                parts.append((f'{source.get("type", "?")}: {source.get("url", "")}\n', 'mono'))
        else:
            parts.append(('Только проверенный локальный список\n', 'muted'))
        parts.append(('\nUpstream не применяется автоматически. Поля fqdn_extra и ipv4_cidr_extra — локальные дополнения.\n', 'muted'))
        self._set_details(parts)

    def save_selection(self):
        lines = ['# Enabled services: one id per line. Managed by MikroTik Service Manager.']
        lines.extend(sid for sid in self.services if sid in self.checked)
        temporary = self.selection_path.with_suffix(self.selection_path.suffix + '.tmp')
        temporary.write_text('\n'.join(lines) + '\n', encoding='utf-8', newline='\n')
        os.replace(temporary, self.selection_path)
        self.saved_checked = set(self.checked)
        self.state_var.set(f'Выбор сохранён: {self.selection_path}')
        self._populate()
        return True

    def _ensure_saved(self):
        if self.checked == self.saved_checked:
            return True
        answer = messagebox.askyesnocancel('Несохранённый выбор', 'Сохранить выбор перед продолжением?', parent=self)
        return self.save_selection() if answer else answer is False

    def export_full(self):
        if not self._ensure_saved():
            return
        path = filedialog.asksaveasfilename(
            parent=self, title='Сохранить полный RouterOS-скрипт',
            initialfile='routeros-services.rsc', defaultextension='.rsc',
            filetypes=(('RouterOS script', '*.rsc'),),
        )
        if not path:
            return
        selected = [sid for sid in self.services if sid in self.checked]
        Path(path).write_text(core.render_full(self.catalog, self.services, selected), encoding='utf-8', newline='\n')
        self.state_var.set(f'Полный скрипт сохранён: {path}')

    def import_exports(self):
        address_path = filedialog.askopenfilename(
            parent=self, title='Export /ip firewall address-list',
            filetypes=(('RouterOS export', '*.rsc'), ('All files', '*.*')),
        )
        if not address_path:
            return
        dns_path = filedialog.askopenfilename(
            parent=self, title='Export /ip dns static',
            filetypes=(('RouterOS export', '*.rsc'), ('All files', '*.*')),
        )
        if not dns_path:
            return
        try:
            text = Path(address_path).read_text(encoding='utf-8') + '\n' + Path(dns_path).read_text(encoding='utf-8')
            self._load_current(text, f'{address_path} + {dns_path}')
        except (OSError, ValueError) as exc:
            messagebox.showerror('Ошибка импорта', str(exc), parent=self)

    def _load_current(self, text, source):
        static, fwd, a_records = core.parse_current(text, self.services)
        self.current_text = text
        self.current_static = static
        self.current_fwd = fwd
        self.current_a = a_records
        self.current_source = source
        self.diff_text = ''
        self.state_var.set(
            f'Состояние: {source} · записей: {len(static)} static, '
            f'{len(fwd)} FWD, {len(a_records)} A-override'
        )
        self._populate()

    def _make_diff(self):
        selected = [sid for sid in self.services if sid in self.checked]
        return core.render_diff(self.catalog, self.services, selected, self.current_text)

    def show_diff(self):
        if not self.current_text:
            messagebox.showinfo('Нет состояния роутера', 'Сначала получите состояние с MikroTik или импортируйте два export.', parent=self)
            return False
        if not self._ensure_saved():
            return False
        self.diff_text, self.diff_summary = self._make_diff()
        total = sum(len(values) for values in self.diff_summary.values())
        window = tk.Toplevel(self)
        window.title(f'Diff для {self.target_var.get()} · изменений: {total}')
        window.geometry('940x650')
        frame = ttk.Frame(window, padding=8)
        frame.pack(fill='both', expand=True)
        summary = '\n'.join(
            f'{label}: {len(self.diff_summary[key])}'
            for key, label in (
                ('add_static', 'Добавить FQDN/CIDR'), ('add_fwd', 'Добавить DNS FWD'),
                ('add_a', 'Добавить DNS A-override'),
                ('remove_static', 'Удалить FQDN/CIDR'), ('remove_fwd', 'Удалить DNS FWD'),
                ('remove_a', 'Удалить DNS A-override'),
            )
        )
        ttk.Label(frame, text=summary, font=('Segoe UI', 10, 'bold')).pack(anchor='w', pady=(0, 6))
        text = scrolledtext.ScrolledText(frame, wrap='none', font=('Consolas', 9))
        text.pack(fill='both', expand=True)
        text.insert('1.0', self.diff_text)
        text.configure(state='disabled')
        buttons = ttk.Frame(frame)
        buttons.pack(fill='x', pady=(6, 0))
        ttk.Button(buttons, text='Сохранить diff', command=self.save_diff).pack(side='left')
        ttk.Button(buttons, text='Закрыть', command=window.destroy).pack(side='right')
        return True

    def save_diff(self):
        if not self.diff_text:
            self.diff_text, self.diff_summary = self._make_diff()
        path = filedialog.asksaveasfilename(
            parent=self, title='Сохранить diff', initialfile='mikrotik-services-diff.rsc',
            defaultextension='.rsc', filetypes=(('RouterOS script', '*.rsc'),),
        )
        if path:
            Path(path).write_text(self.diff_text, encoding='utf-8', newline='\n')
            self.state_var.set(f'Diff сохранён: {path}')

    def _validate_target(self):
        target = self.target_var.get().strip()
        if not target or not all(ch.isalnum() or ch in '_-' for ch in target):
            raise ValueError('Некорректный alias роутера')
        if not self.rsh_path.is_file():
            raise FileNotFoundError(f'Не найден tools/rsh.py: {self.rsh_path}')
        return target

    def _run_rsh(self, arguments, timeout=120):
        env = dict(os.environ, MSYS_NO_PATHCONV='1', PYTHONUTF8='1')
        return subprocess.run(
            [sys.executable, str(self.rsh_path), *arguments],
            capture_output=True, text=True, encoding='utf-8', errors='replace',
            timeout=timeout, env=env, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
        )

    def _start_worker(self, function, on_success):
        if self.busy:
            messagebox.showinfo('Операция выполняется', 'Дождитесь завершения текущей операции.', parent=self)
            return
        self.busy = True
        self.fetch_button.configure(state='disabled')
        self.apply_button.configure(state='disabled')
        self.state_var.set('Операция выполняется…')
        def work():
            try:
                result = function()
                self.events.put(('success', on_success, result))
            except Exception as exc:
                self.events.put(('error', None, str(exc)))
        threading.Thread(target=work, daemon=True).start()

    def _poll_events(self):
        if self._closing:
            return
        try:
            while True:
                kind, callback, payload = self.events.get_nowait()
                self.busy = False
                self.fetch_button.configure(state='normal')
                self.apply_button.configure(state='normal')
                if kind == 'error':
                    self.state_var.set('Ошибка операции')
                    messagebox.showerror('MikroTik Service Manager', payload, parent=self)
                else:
                    callback(payload)
        except queue.Empty:
            pass
        self.after(100, self._poll_events)

    def fetch_router(self):
        try:
            target = self._validate_target()
        except (ValueError, FileNotFoundError) as exc:
            messagebox.showerror('Подключение', str(exc), parent=self)
            return
        def work():
            outputs = []
            for command in (EXPORT_ADDRESS, EXPORT_DNS):
                result = self._run_rsh([target, command], timeout=60)
                if result.returncode:
                    raise RuntimeError(result.stderr.strip() or f'rsh завершился с кодом {result.returncode}')
                outputs.append(result.stdout)
            return target, '\n'.join(outputs)
        self._start_worker(work, lambda payload: self._fetched(*payload))

    def _fetched(self, target, text):
        local = core.ROOT / '.local'
        local.mkdir(exist_ok=True)
        (local / f'{target}-manager-current.rsc').write_text(text, encoding='utf-8', newline='\n')
        self._load_current(text, target)
        self.show_diff()

    def apply_diff(self):
        try:
            target = self._validate_target()
        except (ValueError, FileNotFoundError) as exc:
            messagebox.showerror('Подключение', str(exc), parent=self)
            return
        if not self.current_text:
            messagebox.showinfo('Нет diff', 'Сначала получите состояние роутера.', parent=self)
            return
        if not self._ensure_saved():
            return
        self.diff_text, self.diff_summary = self._make_diff()
        total = sum(len(values) for values in self.diff_summary.values())
        if not total:
            messagebox.showinfo('Нет изменений', 'Конфигурация уже совпадает с выбором.', parent=self)
            return
        commands = [line for line in self.diff_text.splitlines() if line and not line.startswith('#')]
        if len(commands) > MAX_SAFE_COMMANDS:
            messagebox.showwarning(
                'Слишком большой diff',
                f'Изменений: {len(commands)}. За один Safe Mode сеанс разрешено не более {MAX_SAFE_COMMANDS}.\n\n'
                'Сохраните diff и примените его небольшими партиями через CLI.',
                parent=self,
            )
            return
        removals = sum(len(self.diff_summary[key]) for key in ('remove_static', 'remove_fwd', 'remove_a'))
        additions = sum(len(self.diff_summary[key]) for key in ('add_static', 'add_fwd', 'add_a'))
        answer = messagebox.askyesno(
            'Применить изменения?',
            f'Роутер: {target}\nДобавлений: {additions}\n'
            f'Удалений: {removals}\n\nПеред применением будет создан export.\n'
            'Изменения выполнятся через rsh.py --safe и будут откачены при ошибке.\n\nПродолжить?',
            icon='warning', parent=self,
        )
        if not answer:
            return
        diff_path = core.ROOT / '.local' / f'{target}-manager-diff.rsc'
        diff_path.parent.mkdir(exist_ok=True)
        diff_path.write_text(self.diff_text, encoding='utf-8', newline='\n')
        def work():
            stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
            backup = f'hynet-services-{stamp}'
            result = self._run_rsh([target, f'/export file={backup}'], timeout=90)
            if result.returncode:
                raise RuntimeError('Backup не создан. Изменения не применялись.\n' + result.stderr.strip())
            result = self._run_rsh(['--safe', '--script', str(diff_path), target], timeout=max(180, len(commands) * 35))
            output = result.stdout + ('\n' + result.stderr.strip() if result.stderr.strip() else '')
            if result.returncode != 0:
                raise RuntimeError(f'Safe Mode не подтвердил изменения (код {result.returncode}).\n{output}')
            return backup, output
        def done(payload):
            backup, output = payload
            self.state_var.set(f'Изменения применены. Backup: {backup}')
            messagebox.showinfo('Изменения применены', f'Backup на роутере: {backup}\n\n{output[-1500:]}', parent=self)
            self.fetch_router()
        self._start_worker(work, done)

    def _on_close(self):
        if self.checked != self.saved_checked:
            answer = messagebox.askyesnocancel('Несохранённый выбор', 'Сохранить выбор перед выходом?', parent=self)
            if answer is None:
                return
            if answer:
                self.save_selection()
        self._closing = True
        self.destroy()


def main():
    parser = argparse.ArgumentParser(description='Desktop service selector for MikroTik hynet steering')
    parser.add_argument('--catalog', type=Path, default=core.ROOT / 'config/services.json')
    parser.add_argument('--services', type=Path, default=core.ROOT / 'config/services.txt')
    parser.add_argument('--rsh', type=Path, default=core.ROOT.parent / 'tools/rsh.py')
    parser.add_argument('--target', default='rb4011')
    parser.add_argument('--smoke-test', action='store_true')
    args = parser.parse_args()
    app = ServiceManager(args.catalog, args.services, args.rsh, args.target)
    if args.smoke_test:
        app.after(300, app.destroy)
    app.mainloop()


if __name__ == '__main__':
    main()
