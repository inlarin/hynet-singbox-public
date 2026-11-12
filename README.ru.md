# hynet-singbox

[Read in English](README.md)

Самодостаточный контейнер с [sing-box](https://github.com/SagerNet/sing-box) — принимает URL подписки v2ray-формата и поднимает туннель на TUN внутри контейнера. Сделан под **MikroTik RouterOS containers** (RB4011 / RB5009 / hAP ax) — для случаев когда USB-флешка не подключена и нужно держать NAND-износ нулевым: всё runtime-состояние на tmpfs.

Заполняется любая комбинация `SUBSCRIPTION_1…5` и необязательных `HW_ID_1…5`; хотя бы одна подписка обязательна. Все провайдеры равноправны: контейнер независимо извлекает их серверы в единый пул, а healthcheck выбирает лучший выход. Base64 и вручную заданные VLESS-узлы не нужны.

## Что внутри

| Компонент | Назначение |
|---|---|
| [`sing-box`](https://github.com/SagerNet/sing-box) 1.15.0-alpha.13 (canary, slim, собирается из исходников в Dockerfile, `ARG SINGBOX_VERSION`) | Прокси-runtime, владеет TUN. Build tags: `with_quic,with_grpc,with_utls,with_clash_api,badlinkname,tfogo_checklinkname0`. Go 1.26.10, `CGO_ENABLED=0`, upstream release LDFLAGS + версия и strip-флаги. |
| `healthcheck render` (Go) | Разбор Base64 URI, Clash YAML, Xray JSON, SIP008 и sing-box outbounds от пяти независимых провайдеров. URL, UA и необязательный HWID сохраняются для каждого; при сбое остаются последние рабочие узлы. Один TUN, один `select` и отдельные probe-порты. |
| `entrypoint.sh` | Initial fetch+render, фоновое ежедневное обновление, foreground respawn-loop sing-box, ежечасное обслуживание логов и состояния. |
| `healthcheck refresh` (вызывается из `sub-refresh.sh`) | Dual-mirror fetch через direct WAN → convert/merge → `sing-box check` → atomic swap → SIGTERM. Восстанавливает `select.now`, откатывает конфиг если новый не запустился. |
| `healthcheck` (Go бинарь) | Демон real-data проб. Периодически качает 100 KB через каждый outbound пула, ранжирует по latency, авто-пинит самый быстрый живой, ротирует на падении. Ловит servers'ы которые проходят TLS-handshake но дропают данные — sing-box HEAD-probe такие пропускает. |

Runtime полностью на Go: Python, curl, jq, gcompat и полный iproute2 удалены. UPX-сжатие включено по умолчанию (`ENABLE_UPX=1`).

## Теги

| Тег | Архитектура | Железо RouterOS |
|---|---|---|
| `:armv7` | linux/arm/v7 | RB4011 (проверено), RB1100AHx4/Dx4 и прочие 32-bit ARM — `/system/resource/print` → `architecture-name: arm` |
| `:arm64` | linux/arm64 | RB5009 (проверено), hAP ax2/ax3, CCR2004, CCR2116 и прочие `architecture-name: arm64` |
| `:latest` | manifest arm/arm64 | Docker / RouterOS выбирают по host arch. **amd64-слоя нет** — на x86 не заработает без пересборки |

Для RouterOS лучше явный per-arch тег — на один round-trip меньше в `/container/add` и без сюрпризов с manifest-резолвом.
Архитектуру платы смотри в `/system/resource/print` (`architecture-name`), а не по названию: MIPS-платы (hEX S, hAP ac² и т.п.)
контейнеры не поддерживают вовсе — по докам Container package существует только для arm, arm64 и x86.

## Переменные окружения

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `REFRESH_INTERVAL` | `86400` | Секунды между авто-рефрешами подписки. |
| `TMPFS_SIZE` | `64M` | Размер `/tmp` в RAM; на слабых платах можно задать `16M` или `32M`. |
| `GOMEMLIMIT` | `96MiB` | Мягкий лимит Go heap на процесс healthcheck и sing-box; уменьшать только после замеров реального трафика. |
| `SINGBOX_TUN_NAME` | `opkgtun0` | Имя TUN-интерфейса в netns контейнера. |
| `TUN_ADDR` | `172.19.0.1` | IPv4-адрес TUN; в конфиг записывается `/30`. |
| `TUN_MTU` | `1420` | MTU TUN. |
| `SINGBOX_TUN_MULTI_QUEUE` | `0` | `1` включает multi-queue TUN на стеке sing-tun 1.15 для масштабирования по ядрам; сначала canary. |
| `INTERRUPT_EXIST_CONNECTIONS` | `0` | `0` сохраняет установленные inbound-соединения при смене сервера; `1` разрывает их. |
| `UDP_NAT_MAX` | `0` | Максимум UDP NAT-сессий; `0` — авто. На слабых платах используй `4096`. |
| `LOG_LEVEL` | `warn` | Уровень логов sing-box; `info`/`debug` только временно. |
| `SINGBOX_DNS_OPTIMISTIC` | *(пусто)* | TTL optimistic DNS cache, например `10m`. Пусто — выключен. |
| `SINGBOX_DNS_TIMEOUT` | *(пусто)* | Необязательный таймаут DNS-запроса, например `5s`. |
| `SINGBOX_DNS_CACHE_CAPACITY` | `0` | Ёмкость DNS LRU; минимум 1024, для малых плат 2048. |
| `SINGBOX_CACHE_BUFFER_SIZE` | *(пусто)* | Буфер записи cache-file, например `256KB` для малых плат. |
| `SINGBOX_API_ENABLED` | `0` | `1` включает нативную sing-box API и dashboard. Только с секретом и ограничением firewall. |
| `SINGBOX_API_LISTEN` / `SINGBOX_API_PORT` | `172.20.0.2` / `9091` | Адрес и порт нативной API. |
| `SINGBOX_DASHBOARD_PATH` | `/tmp/dashboard` | Каталог загрузки dashboard на tmpfs. |
| `SINGBOX_DASHBOARD_UPDATE_INTERVAL` | `7d` | Интервал обновления dashboard. |
| `PROBE_REAL_DATA` | `0` | `1` добавляет `healthcheck probe` проверку текущего выхода реальной загрузкой. |
| `SINGBOX_TUN_STACK` | `none` | Опустить `stack` и использовать собственный стек sing-tun 1.15. `system` — legacy kernel-вариант; gVisor-теги намеренно не собираются. |
| `CLASH_ADDR` | `172.20.0.2:9090` | listen-адрес Clash API только на изолированном veth, не `0.0.0.0`. |
| `CLASH_SECRET` | *(обязательная)* | Bearer-токен Clash API. |
| `SUBSCRIPTION_1` … `SUBSCRIPTION_5` | хотя бы одна обязательна | До пяти равноправных подписок. Пустые переменные пропускаются, оператор определяется по URL. |
| `HW_ID_1` … `HW_ID_5` | *(пусто)* | HWID соответствующей подписки. Пустое значение штатно: заголовок `x-hwid` не отправляется. |
| `UA_1` … `UA_5` | `ClashforAndroid/2.5.12` для №1, `sing-box` для остальных | Необязательный User-Agent для конкретной панели. |
| `SINGBOX_NODE_RESOLVER` | `172.20.0.1` | Прямой DNS для имён серверов подписок: RouterOS на `br-hynet`, без ненадёжного внешнего UDP/53. |
| `SINGBOX_UTLS_FINGERPRINT` | `chrome` | Нормализация uTLS fingerprint из подписок, которые новые версии sing-box отклоняют. |
| `EXCLUDE_AUTO_CC` | `RU` | Список country-кодов через запятую, исключаемых из `urltest-all` авто-пика И из probe-pool демона. Серверы остаются доступными вручную через Clash API / MetaCubeXD. Пустая строка отключает фильтр. |
| `HEALTHCHECK_ENABLED` | `1` | Запускать ли real-data healthcheck-демон. `0` отключает, остаётся только встроенный sing-box urltest (HEAD-probe, обманывается серверами с handshake-OK / data-reset). |
| `LIVENESS_URL` | `https://speed.cloudflare.com/__down?bytes=100000` | URL real-data probe — должен отдавать ровно `LIVENESS_BYTES`. Демон считает байты; partial = fail. |
| `LIVENESS_BYTES` | `100000` | Сколько байт демон ждёт от `LIVENESS_URL`. |
| `LIVENESS_INTERVAL` | `30s` | Каденция liveness-проб (Go duration: `30s`, `1m` и т.д.). |
| `RANK_INTERVAL` | `10m` | Каденция полных ranking-sweep'ов. Каждый outbound пробится через свой выделенный probe-port (`127.0.0.1:7900+N`), `select.now` при этом **не трогается** и user-трафик не страдает. Длительность sweep ≈ avg-RTT × pool-size; для ~40 outbounds — 3-6 мин. |
| `PROBE_TIMEOUT` | `12s` | Таймаут на одну пробу. С дефолтным 100 KB payload даёт неявный floor по скорости ≈8 KB/s. |
| `FAIL_THRESHOLD` | `2` | Сколько подряд liveness-fail'ов до ротации `select.now`. |
| `HYSTERESIS_PCT` | `15` | Минимальное улучшение времени ответа для переключения на более быстрый сервер. |
| `SEVERE_IMPROVE_PCT` | `50` | Улучшение, при котором свежий sweep переключает сервер без dwell и повторных подтверждений. |
| `FAILOVER_CANDIDATES` | `5` | Сколько лучших по рейтингу кандидатов заново измерить при аварийной ротации; выбирается быстрейший живой по свежим замерам. |
| `PROBE_CONCURRENCY` | `4` | Одновременных probe-запросов. Текущий сервер проверяется первым, рейтинг сохраняется после каждой пробы. |
| `MIN_SWITCH_INTERVAL` | `15m` | Минимальное удержание текущего сервера перед переключением ради более низкой задержки. На аварийную ротацию не влияет. |
| `IMPROVE_CONFIRMATIONS` | `2` | Сколько подряд sweep должно подтвердить улучшение перед переключением. |
| `AUTO_PIN` | `1` | `0` — демон продолжает проверки, но не меняет ручной выбор `select.now`. |
| `RANK_STALE_AFTER` | `25m` | Результаты рейтинга старше этого возраста не используются при выборе. |
| `TELEGRAM_HEALTHCHECK` | `1` | Общая проверка каждого кандидата: Telegram API + MTProto CONNECT, без отдельного Telegram-селектора. |
| `TELEGRAM_API_URL` / `MTPROTO_ADDRESS` | `https://api.telegram.org` / `149.154.167.50:80` | Цели Telegram-проверок общего пула. |
| `ROTATIONS_BEFORE_FORCE_SWEEP` | `3` | Сколько ротаций `select.now` подряд без успеха до форсированного полного sweep'а. |
| `STATE_DIR` / `PROBE_PORTS` | `/tmp/healthcheck` / `/tmp/probe_ports.json` | Пути состояния healthcheck на tmpfs. Telegram идёт через общий `select`; отдельный HY2-outbound не инжектируется. |

## Настройка RouterOS

Контейнер терминирует прокси-туннель на собственном TUN. RouterOS заворачивает выбранный трафик на veth-IP контейнера как next-hop; ядро контейнера форвардит в TUN, sing-box egress'ит обратно через veth → ROS WAN.

> **Перед тем как трогать удалённый продакшн-роутер — войди в Safe Mode.**
>
> SSH/WinBox внутрь, в CLI нажми **`Ctrl+X`** (или **`F4`**). Промт меняется на `[Safe Mode taken]` — теперь все изменения (твои и из любых других сессий, пока ты держишь safe mode) журналируются.
>
> Если SSH/WinBox-соединение оборвалось — TCP-таймаут (~9 минут) — RouterOS **автоматически откатит всё**, что было сделано с момента нажатия `Ctrl+X`. То есть если firewall-rule или маршрут заблокирует тебя самого — просто подожди, роутер сам себя восстановит.
>
> Когда работа закончена и убедился что всё ок — **`Ctrl+X`** второй раз для коммита (выходишь из safe mode, изменения становятся постоянными). Для ручного отката: **`Ctrl+D`** — отменяет всё и закрывает сессию. `/quit` НЕ откатывает — откат срабатывает только при abnormal exit / явном `Ctrl+D`. (По [Console docs](https://help.mikrotik.com/docs/spaces/ROS/pages/8978498/Console#Console-SafeMode), буфер safe-mode хранит до 100 действий; при переполнении тебя молча выкидывает из safe-mode с предупреждением. Дроби работу на маленькие батчи.)

### 0. Включить container-режим (одноразово)

Если подменю `/container` отсутствует, device-mode ещё не переключён:

```routeros
/system/device-mode/update container=yes
```

RouterOS ждёт физического подтверждения — нажми reset на корпусе в течение 5 минут (или cold-reboot на x86). После подтверждения **роутер перезагружается** (так по докам device-mode — планируй окно), затем `/container/*` становится доступным. Уже включено, если `/system/device-mode/print` показывает `container: yes`.

### 1. Сеть — bridge + veth

По каноничным примерам с официальной [Container](https://help.mikrotik.com/docs/spaces/ROS/pages/84901929/Container) страницы (Pi-hole, Postgres, HomeAssistant — все одинаково) роутерный IP вешается на **bridge**, а veth добавляется в этот bridge портом. `address=`/`gateway=` на `/interface/veth add` конфигурируют **контейнерную** сторону линка — это IP, который контейнерный `eth0` получит внутри своего netns'а, и его default route.

```routeros
/interface/bridge add name=br-hynet
/ip/address add address=172.20.0.1/30 interface=br-hynet
/interface/veth add name=veth-hynet address=172.20.0.2/30 gateway=172.20.0.1
/interface/bridge/port add bridge=br-hynet interface=veth-hynet
```

Итог: bridge `br-hynet` держит `172.20.0.1` (gateway со стороны RouterOS), `eth0` контейнера получает `172.20.0.2` и default route на `172.20.0.1`. Veth L2-bridg'нут в `br-hynet`, поэтому трафик с next-hop `172.20.0.2` доходит через ARP-резолв на `br-hynet`.

**Разрешить контейнеру доступ к самому роутеру.** В defconf RouterOS висит правило в input chain (`drop all not coming from LAN`). `br-hynet` намеренно НЕ держим в `interface-list=LAN` (иначе mangle-маркинг LAN-источников зацикливается через контейнер), но без явного accept'а контейнер не может сделать ни DNS-запрос, ни что-то ещё на router'е:

```routeros
/ip/firewall/filter add chain=input action=accept in-interface=br-hynet \
    comment="accept input from hynet container" \
    place-before=[find where comment="defconf: drop all not coming from LAN"]
```

Если comment'а у defconf-drop'а другой — подгони `[find]` под свою формулировку. Главное — `accept` ДО catch-all drop'а.

### 2. Контейнер — config, env, image

Выбери storage-устройство под image rootfs (~70 МБ). На большинстве MikroTik'ов это внутренняя flash (`disk1`) или USB (`usb1`) — смотри `/file/print`. `<storage>` ниже — плейсхолдер. Доки MikroTik рекомендуют внешний диск («not recommended to use internal storage for Containers») — здесь внутренняя flash используется сознательно: во flash пишется только rootfs при pull, всё runtime-состояние живёт на tmpfs (см. ниже).

```routeros
# registry-url — настройка router-wide; не трогай если уже стоит как надо
# или у тебя есть другие контейнеры с другим registry.
# tmpdir — куда распаковывается remote-image при pull; без него распаковка идёт
# в RAM (доки: "requires a lot of free space in main memory"). На живых боксах
# стоял всегда (RB4011: disk1/tmp).
/container/config/set registry-url=https://ghcr.io tmpdir=<storage>/tmp

# Сгенерировать random Clash API secret скриптом RouterOS (вывод вставить в CLASH_SECRET ниже):
:global hex "0123456789abcdef"; :global s ""; :for i from=1 to=48 do={ :set s ($s . [:pick $hex [:rndnum from=0 to=15]]) }; :put $s

/container/envs/add list=hynet key=SUBSCRIPTION_1 value="https://your-provider/sub?token=..."
/container/envs/add list=hynet key=HW_ID_1 value=""
/container/envs/add list=hynet key=CLASH_SECRET value="<вставить-48-hex-символов-сверху>"
# Дополнительные операторы; HW_ID можно оставить пустым:
/container/envs/add list=hynet key=SUBSCRIPTION_2 value="https://provider.example/second"
/container/envs/add list=hynet key=HW_ID_2 value="<hwid-или-пусто>"
/container/envs/add list=hynet key=SUBSCRIPTION_3 value="https://provider.example/third"
/container/envs/add list=hynet key=HW_ID_3 value="<hwid-или-пусто>"
# При смене оператора заменить URL через /container/envs/set [find where list=hynet and key=SUBSCRIPTION_2] value="https://new-url" и перезапустить контейнер.

# armv7 для RB4011 / hAP / hEX; используй :arm64 для RB5009 / CCR2004
#
# dns= ОБЯЗАТЕЛЕН — без него /etc/resolv.conf внутри контейнера пустой,
# первый же curl для SUBSCRIPTION_1 падает с "unable to resolve host",
# entrypoint бесконечно ретраит.
#
# Используй IP роутера на br-hynet (172.20.0.1) — самый надёжный путь.
# На live RB4011/7.21.2 видели: UDP/53 от контейнера к внешним резолверам
# (1.1.1.1, 8.8.8.8) тихо умирает — TCP по тому же пути работает, UDP нет.
# Через router-as-DNS трафик идёт input→accept (правило из секции 1)
# и остаётся внутри роутера, наружу UDP не выходит.
/container/add remote-image=ghcr.io/inlarin/hynet-singbox-public:armv7 \
    interface=veth-hynet envlist=hynet \
    root-dir=<storage>/containers/hynet \
    dns=172.20.0.1 \
    tmpfs=64M@/tmp shm-size=16MiB \
    memory-high=500MiB memory-max=600MiB \
    restart-policy=on-failure restart-max-count=5 restart-interval=5m \
    healthcheck-cmd="/usr/local/bin/healthcheck probe" \
    healthcheck-interval=30s healthcheck-timeout=10s healthcheck-start-period=30s \
    start-on-boot=yes logging=yes
```

> `/dev/net/tun` пробрасывается в контейнер автоматически — отдельный mount не нужен (устройство входит в дефолтный набор `/dev/` по [документации MikroTik](https://help.mikrotik.com/docs/spaces/ROS/pages/84901929/Container)).
>
> **Никакого host-side bind-маунта не нужно.** RouterOS монтирует `tmpfs` через свойство контейнера `tmpfs=64M@/tmp`, и весь runtime state (подписка, сгенерированный конфиг, country cache, рейтинги healthcheck'а, sing-box log) живёт в RAM. NAND wear на runtime: 0 записей. Entrypoint видит существующий mount и не повторяет его; на других container engines остаётся fallback-попытка с `WARN` при неудаче.
>
> **Лимиты памяти обязательны на проде.** TUN-inbound sing-box с `auto_route=true` ловит каждое connection в netns контейнера. Под нагрузкой per-connection state может разрастись. `memory-high` начинает тормозить процессы под давлением, `memory-max` останавливает контейнер до угрозы хосту. Если заданы лимиты и глобально, и на контейнере, побеждает меньший. Для малых плат используй профили ниже, swap на внутренней flash не включай.

#### Рекомендуемые профили

| Параметр | RB4011 / RB5009 | L009 | hAP ax lite, только canary |
|---|---:|---:|---:|
| `memory-high` | 500MiB | 220–250MiB | 100–120MiB |
| `memory-max` | 600MiB | 280–300MiB | 128–140MiB |
| `tmpfs` | 64M | 32M | 16M |
| `shm-size` | 16–32MiB | 16MiB | 8–16MiB |
| `GOMEMLIMIT` | 96MiB | 64–96MiB | 64MiB |
| `PROBE_CONCURRENCY` | 4 | 1–2 | 1 |
| `multi_queue` | canary | canary | сначала выключен |
| Нативная dashboard | опционально | выключена | выключена |
| Swap | выключен | выключен | выключен |

Используй `restart-policy=on-failure`, `restart-max-count=5`, `restart-interval=5m` и нативную `healthcheck probe`. `stop-on-unhealthy` пока не включай: временный WAN-сбой не должен без нужды останавливать контейнер. Topic `container` направляй в memory или remote-syslog, а не в disk action.

#### Совместимость с версиями RouterOS

| RouterOS | Статус |
|---|---|
| 7.13–7.21.x | ✓ работает |
| **7.22, 7.22.x** | ✓ работает (проверено end-to-end на RB4011iGS+5HacQ2HnD/7.22.2). Под капотом: `entrypoint.sh` детектит регрессию (MikroTik в 7.22 сменил дефолтные приоритеты `ip rule` внутри netns контейнера на 1/2/3 — это ломает любой TUN-прокси) и восстанавливает исторические 200/2147483646/2147483647 до старта sing-box. Если запускаешь sing-box руками без entrypoint на 7.22.x — фикс надо делать самому. |
| 7.23rc2+ | ✓ починили апстрим (release note: *"route — revert to old routing rule priorities for containers"*) |
| 7.23.2 | ✓ RB4011 + RB5009 работали на нём до 2026-08-31 (стек снят по решению владельца, не из-за проблем) |
| 7.24.x | не проверялось (changelog 7.24.1 по контейнерам: только *"improve host isolation when privileged=yes"*) |

### 3. Steering — что заворачивать в туннель

Два дополняющих друг друга механизма, оба наполняют один и тот же `address-list=hynet`:

#### 3a. Статические FQDN / CIDR

Для сервисов со стабильной инфрой — apex'ы у которых есть A-запись + raw-IP сервисы (Telegram MTProto). RouterOS принимает DNS-имена прямо в `/ip firewall address-list` и резолвит их периодически (по [Address-lists docs](https://help.mikrotik.com/docs/spaces/ROS/pages/130220135/Address-lists), поле `address` принимает `DNS Name | IP address/netmask | IP-IP`).

Bulk-импорт через `:foreach` массив-литерал — одна SSH-сессия, десятки записей:

```routeros
# Telegram FQDN apex'ы
:foreach d in={"t.me";"telegram.org";"telegram.me";"telegra.ph";"telesco.pe";"tdesktop.com";"web.telegram.org";"core.telegram.org";"api.telegram.org";"my.telegram.org"} do={
    /ip firewall address-list add list=hynet address=$d comment=telegram
}

# Telegram MTProto raw-IP CIDR (обязательно — клиенты ходят по голому IP, без DNS)
:foreach c in={"91.108.4.0/22";"91.108.8.0/22";"91.108.12.0/22";"91.108.16.0/22";"91.108.20.0/22";"91.108.56.0/22";"91.105.192.0/23";"149.154.160.0/20";"185.76.151.0/24"} do={
    /ip firewall address-list add list=hynet address=$c comment=telegram-mtproto
}
# Канонический список периодически обновляется: https://core.telegram.org/resources/cidr.txt

# Claude / Anthropic
:foreach d in={"claude.ai";"claude.com";"anthropic.com";"www.claude.ai";"cdn.claude.ai";"assets.claude.ai";"www.anthropic.com";"api.anthropic.com";"console.anthropic.com";"docs.anthropic.com";"support.anthropic.com";"status.anthropic.com";"claudeusercontent.com";"clau.de";"claudemcpclient.com";"servd-anthropic-website.b-cdn.net"} do={
    /ip firewall address-list add list=hynet address=$d comment=claude
}

# YouTube static apex'ы — полный канонический список в v2fly/domain-list-community/data/youtube
# (~180 записей в развёрнутом виде — добавляй сколько нужно)
:foreach d in={"youtube.com";"www.youtube.com";"m.youtube.com";"youtu.be";"ytimg.com";"i.ytimg.com";"s.ytimg.com";"googlevideo.com";"ggpht.com";"youtubei.googleapis.com"} do={
    /ip firewall address-list add list=hynet address=$d comment=youtube
}

# WhatsApp apex'ы (Meta-side CDN ловится regex'ом ниже)
:foreach d in={"wa.me";"whatsapp.com";"whatsapp.net";"whatsapp.org";"whatsapp.cc";"whatsapp.info";"whatsapp.tv";"whatsappbrand.com"} do={
    /ip firewall address-list add list=hynet address=$d comment=whatsapp
}
```

#### 3b. DNS-FWD-with-regex для CDN apex'ов без A-записи

Это часть, без которой не работает воспроизведение видео, превью картинок, аватарки. Несколько сервисов используют *random-subdomain CDN* — apex (`googlevideo.com`, `ytimg.com`, `ggpht.com` и т.п.) **вообще не имеет A-записи**, IP отдают только субдомены типа `r1---sn-aigl6n7l.googlevideo.com`. Положить apex в address-list бесполезно: RouterOS его резолвит, получает `dns name exists, but no appropriate record`, в hynet ничего не добавляется.

Решение: `/ip dns static type=FWD` с regex'ом матчащим субдомены + `address-list=hynet`. RouterOS перехватывает запрос когда клиент его делает, форвардит на upstream И добавляет резолвнутый IP в `hynet`, чтобы последующие connections к этому IP цеплял mangle.

```routeros
# YouTube CDN — видео-сегменты, превью, аватарки
/ip dns static add type=FWD regexp=".*\\.googlevideo\\.com\$"               address-list=hynet forward-to=<upstream-DNS> ttl=1d comment=youtube-cdn
/ip dns static add type=FWD regexp=".*\\.ytimg\\.com\$"                      address-list=hynet forward-to=<upstream-DNS> ttl=1d comment=youtube-cdn
/ip dns static add type=FWD regexp=".*\\.ggpht\\.com\$"                      address-list=hynet forward-to=<upstream-DNS> ttl=1d comment=youtube-cdn
/ip dns static add type=FWD regexp=".*\\.youtube\\.com\$"                    address-list=hynet forward-to=<upstream-DNS> ttl=1d comment=youtube-cdn
/ip dns static add type=FWD regexp="^yt[0-9]+\\.googleusercontent\\.com\$"   address-list=hynet forward-to=<upstream-DNS> ttl=1d comment=youtube-cdn

# WhatsApp media через Meta CDN — узкий regex (только префикс whatsapp- на fbcdn.net,
# обычные Facebook/Instagram scontent-* остаются как были)
/ip dns static add type=FWD regexp=".*\\.whatsapp\\.com\$"                   address-list=hynet forward-to=<upstream-DNS> ttl=1d comment=whatsapp
/ip dns static add type=FWD regexp=".*\\.whatsapp\\.net\$"                   address-list=hynet forward-to=<upstream-DNS> ttl=1d comment=whatsapp
/ip dns static add type=FWD regexp="^whatsapp-.*\\.fbcdn\\.net\$"            address-list=hynet forward-to=<upstream-DNS> ttl=1d comment=whatsapp

/ip dns cache flush
```

`<upstream-DNS>` — то что использует сам роутер (видно в `/ip dns print`, поле `servers=`). **Не используй** `1.1.1.1` / `8.8.8.8` напрямую — выбери из тех резолверов которые роутят твой провайдер или твои собственные. Не указывай LAN-IP самого роутера — будет петля.

> **regex vs `match-subdomain=yes`** — оба работают для catch'а субдоменов, но regex здесь предпочтительнее потому что может *исключить apex* (`.*\.X\.com$` требует ведущего `<что-то>.`, не матчит голый `X.com`). Apex не имеет A-записи, и его матчинг приводит к NXDOMAIN-ответам которые часть клиентов кэширует как "fail-fast" — плохо. По [DNS docs](https://help.mikrotik.com/docs/spaces/ROS/pages/37748767/DNS) regex matching "significantly slower than plain text entries" — на ~10 правил норм, на 50+ смотри CPU.

> **Caveat: нативные мобильные приложения могут обходить DNS роутера** через DoH или хардкоженые резолверы. Android-клиент YouTube и WhatsApp в основном используют системный DNS, но некоторые приложения ходят через Google DNS over QUIC. Если стиринг не работает для приложения — его браузерная версия обычно работает (там DNS через роутер).

### 4. Routing-mark + kill-switch

```routeros
/routing/table add name=via-hynet fib

# Сначала закрепить DHCP-аренду Tenda: все клиенты за её NAT имеют один source IP.
/ip dhcp-server lease make-static [find where address=<TENDA-NAT-IP> and mac-address=<TENDA-MAC>]
/ip firewall address-list add list=hynet-clients address=<TENDA-NAT-IP> comment="Tenda NAT"
:foreach c in={"10.0.0.0/8";"172.16.0.0/12";"192.168.0.0/16"} do={ /ip firewall address-list add list=hynet-direct address=$c comment="hynet:direct-private" }
/ip/firewall/mangle add chain=prerouting src-address-list=hynet-clients \
    dst-address-list=hynet-direct action=accept passthrough=yes
/ip/firewall/mangle add chain=prerouting src-address-list=hynet-clients \
    dst-address-type=local action=accept passthrough=yes
/ip/firewall/mangle add chain=prerouting src-address-list=hynet-clients \
    connection-state=new dst-address-list=hynet \
    action=mark-connection new-connection-mark=hynet-cm passthrough=yes
/ip/firewall/mangle add chain=prerouting src-address-list=hynet-clients \
    connection-mark=hynet-cm \
    action=mark-routing new-routing-mark=via-hynet passthrough=no

# Управление source-адресами без изменения mangle. Используются адреса, видимые
# RouterOS: отдельные устройства за одним нижестоящим NAT различить нельзя.
/ip firewall address-list add list=hynet-clients address=<CLIENT-IP> comment="<имя>"
/ip firewall address-list remove [find where list=hynet-clients and address=<CLIENT-IP>]

/ip/route add dst-address=0.0.0.0/0 gateway=172.20.0.2 routing-table=via-hynet \
    distance=1 check-gateway=ping comment="hynet container"
/ip/route add dst-address=0.0.0.0/0 blackhole          routing-table=via-hynet \
    distance=10                  comment="killswitch"

# MSS clamping — proxy добавляет TLS+protocol overhead к каждому TCP-сегменту,
# реальный inside-tunnel MSS получается ~40 байт ниже того что LAN-клиент
# успел согласовать. Без clamp'а большие сегменты тихо дропаются где-то в
# цепочке и YouTube/всё-остальное стартует мееедленно (PMTU black-holing).
# С этим правилом MikroTik переписывает MSS-опцию в SYN до того как пакет
# уйдёт в контейнер, и LAN→remote TCP-сессия использует безопасный размер
# сегмента end-to-end.
/ip firewall mangle add chain=forward action=change-mss new-mss=clamp-to-pmtu \
    protocol=tcp tcp-flags=syn out-interface=br-hynet \
    comment="hynet MSS clamp"

# FastTrack несовместим с routing-mark: по докам mangle "Do not apply any other
# routing marks besides main for the packets processed by FastTrack". На defconf-
# роутере правило `defconf: fasttrack` включено — после первого пакета помеченные
# соединения перестанут попадать в via-hynet. Исключи их из FastTrack (или выключи
# его целиком: ... disabled=yes). На боевых RB4011/RB5009 стиринг работал только
# потому, что fasttrack там отсутствовал / был выключен.
/ip firewall filter set [find where action=fasttrack-connection] connection-mark=no-mark

# ПРОВЕРКА (обязательно): в via-hynet должны быть ДВЕ строки — активный gateway
# 172.20.0.2 distance=1 и blackhole distance=10. На боевых боксах blackhole так и
# не был добавлен (замечено 2026-08-31): при падении контейнера трафик уходил бы
# в WAN открытым.
/ip route print detail where routing-table=via-hynet
```

Двухслойный fail-closed:

- **sing-box упал → TUN исчез → форвардовый пакет внутри netns'а контейнера получает ICMP-unreach → ROS видит unreach, дропает.**
- **Контейнер целиком сдох → veth остался без peer'а, `check-gateway=ping` фейлится, distance=1 маршрут гасится, blackhole с distance=10 берёт верх.**

Не добавляй `veth-hynet` или `br-hynet` в LAN list — это создаст routing-loop на egress контейнера.

### 5. Переключение стран / выбор конкретного сервера

Clash API на `:9090` экспонирует группу `select` со всеми распарсенными outbounds + per-country `urltest-<cc>` группы. Кинь [MetaCubeXD](https://metacubex.github.io/) куда-нибудь в LAN и нацель на `http://172.20.0.2:9090` с Clash secret'ом, либо дёргай API напрямую:

```bash
curl -H "Authorization: Bearer $CLASH_SECRET" \
     -X PUT -H 'Content-Type: application/json' \
     -d '{"name":"urltest-tr"}' \
     http://172.20.0.2:9090/proxies/select
```

**Auto-best vs ручной выбор:**

- `select` по умолчанию указывает на `urltest-all`. С включённым healthcheck-демоном (default) автопиком управляет **демон** через real-data пробы — он может переопределить выбор `urltest-all` (тот пробит HEAD-ом и иногда ошибается). С `HEALTHCHECK_ENABLED=0` всё отдаётся на откуп встроенного sing-box urltest: HEAD `/generate_204` каждые 3 мин, выбирает быстрейший. RU-серверы по умолчанию исключены из автопика (`EXCLUDE_AUTO_CC=RU`) — RU transit DPI глушит Telegram MTProto независимо от того через какой прокси-сервер ты в него заходишь. В дропдауне `select` RU остаются для ручного выбора (Яндекс / госуслуги).
- `urltest-<cc>` — per-country auto-best группы: `urltest-tr`, `urltest-nl`, `urltest-ru` и т.д. Выбирай в MetaCubeXD когда нужно auto-best внутри конкретной страны.
- Индивидуальные теги вида `sub1-vless-example` — для жёсткого пинна.

**Failover и real-data probing:**

В контейнере поднимается sidecar healthcheck-демон (Go, дочерний процесс `entrypoint.sh`), дополняющий встроенный sing-box urltest. Sing-box urltest пробит HEAD `/generate_204` — это ловит «сервер недоступен», но обманывается серверами которые проходят TLS handshake и потом молча дропают application-data. Демон закрывает эту дырку, **не трогая user-трафик**.

**Как устроен probe.** Конвертер генерит по одному localhost-only HTTP-proxy inbound на каждый non-excluded outbound (порт `7900 + N`), каждый статически роутится в свой outbound через sing-box route rule. Демон коннектится к `127.0.0.1:<port>` как HTTP-прокси и качает `LIVENESS_BYTES` с `LIVENESS_URL` — запрос идёт через нужный конкретный outbound. **`select.now` во время пробы не трогается**, user-трафик продолжает идти через то что выбрано пользователем или auto-pin'ом. Tag→port карта пишется в `/tmp/probe_ports.json` при каждом `sub-refresh`.

| Loop | Каденция | Что делает |
|---|---|---|
| Liveness | каждые `LIVENESS_INTERVAL` (30 с) | Резолвит `select.now` (рекурсивно проходя `urltest-*` группы), пробит этот конкретный outbound через выделенный probe-port и обновляет его запись в рейтинге. Real-data загрузка — partial response = fail. После `FAIL_THRESHOLD` (2) подряд fail'ов заново измеряет до `FAILOVER_CANDIDATES` лучших альтернатив и переключается на быстрейшую живую по свежим результатам. После `ROTATIONS_BEFORE_FORCE_SWEEP` (3) ротаций без успеха → форсированный полный sweep. |
| Ranking sweep | каждые `RANK_INTERVAL` (10 мин) | Пробит каждый outbound через его probe-port, до 4 параллельно. RU исключается по `/tmp/probe_countries.json`. Каждый результат сразу пишется в `/tmp/healthcheck/ranking.json`; старше `RANK_STALE_AFTER` игнорируется. **`select.now` во время измерений не переключается**. |
| Auto-pin | после первых проб и каждого sweep'а | `select.now` ← быстрейший живой сервер. Обычное улучшение ≥15% подтверждается `IMPROVE_CONFIRMATIONS` раз и только после `MIN_SWITCH_INTERVAL`. Улучшение ≥`SEVERE_IMPROVE_PCT` после свежего sweep обходит оба ограничения. Аварийная ротация немедленная и использует свежие замеры кандидатов. При `AUTO_PIN=0` ручной выбор не меняется. |

**`select.now` меняется при подтверждённом сбое текущего сервера, выраженном улучшении по свежему замеру или устойчивом, повторно подтверждённом обычном улучшении.** Telegram API и MTProto CONNECT входят в общую пробу каждого кандидата, отдельный Telegram-пул не создаётся.

Лог демона — `/tmp/healthcheck.log`, лог sing-box — `/tmp/sing-box.log` (level warn), конфиг — `/tmp/config.json` (всё на tmpfs контейнера, 64 МБ). Чтобы выключить демона — `HEALTHCHECK_ENABLED=0`, тогда auto-pick остаётся за встроенным sing-box urltest (без disruption тоже, но возвращается проблема handshake-OK / data-reset обмана).

## Standalone Docker (для тестов)

```bash
docker run --rm -it \
    --cap-add=NET_ADMIN --device /dev/net/tun \
    --tmpfs /tmp:rw,size=64M \
    -e SUBSCRIPTION_1='https://your-provider/sub' \
    -e CLASH_SECRET='replace-with-random' \
    -e CLASH_ADDR=0.0.0.0:9090 \
    -p 9090:9090 \
    ghcr.io/inlarin/hynet-singbox-public:armv7
```

Образ собирается только под arm/v7 и arm64 — на x86-хосте нужен QEMU (`docker run --platform linux/arm64 …`) или собери под amd64 сам (`--platform linux/amd64` в команде ниже).

## Сборка из исходников

```bash
git clone https://github.com/inlarin/hynet-singbox-public
cd hynet-singbox
docker buildx build --platform linux/arm/v7 --provenance=false --sbom=false --load -t hynet-singbox:armv7 .
```

UPX включён по умолчанию. Для несжатой отладочной сборки добавь `--build-arg ENABLE_UPX=0`.

## Расход ресурсов на RB4011

| Ресурс | Idle | Active (один TCP-стрим) |
|---|---|---|
| RAM (контейнер) | ~50 MB | ~90–140 MB |
| Образ на диске | rootfs ~22.6 MB (~19.5 MB сжатый Docker archive) | — |
| NAND-записей в день в runtime | **0** (всё state на tmpfs внутри контейнера) | — |

## Эксплуатационные заметки — рефреш, деплой, чтение здоровья

Острые углы, на которые натыкаешься на практике (оператор или автоматический агент).

### Фетч подписки — dual-mirror и прямой WAN

Каждый `sub1…sub5` обновляется независимо с собственными URL, UA и необязательным HWID. Для `hynet-connect.com`/`hynet.cloud` автоматически пробуется зеркало. Конвертер отклоняет HTML-заглушки, при сбое одного провайдера сохраняются его узлы из текущего рабочего конфига, остальные пулы обновляются. Ручных fallback-ссылок нет.

До старта sing-box fetch идёт через обычный default route контейнера. При активном TUN Go HTTP client использует localhost HTTP-inbound `refresh-direct` на `127.0.0.1:7899`, статически направленный в `direct` outbound. `route.auto_detect_interface=true` привязывает исходящие соединения к veth и исключает кольцо через TUN. Поэтому обновление не зависит от живого VPN-выхода и не требует host mount.

Контролировать нужно `/tmp/config.json`, `/tmp/sub-refresh.log`, `df /tmp` и память процессов, а не только `select.now`. Maintenance-loop раз в час оставляет последние 500 строк в `sing-box.log`, `healthcheck.log` и `sub-refresh.log`, выводит возраст конфига, tmpfs и RSS.

### Известные ограничения

- **Трафик проб ≈ 0.65 ГБ/сут при 25 нодах** (liveness 100 КБ каждые 30 с ≈ 288 МБ + sweep 25 × 100 КБ
  каждые 10 мин ≈ 360 МБ). На платном / LTE WAN уменьшай `LIVENESS_BYTES` (например `10000` с
  соответствующим `LIVENESS_URL`) или увеличивай `RANK_INTERVAL`.
- **Логи ограничиваются раз в час, не при каждой записи**: необычно шумный час всё ещё может заполнить 64 МБ tmpfs. При сбое refresh смотри maintenance-вывод и `df /tmp`.
- **Telegram IPv6 не покрыт**: стиринг работает только по `/ip`; IPv6-префиксы Telegram
  (`2001:b28:f23d::/48`, `2001:b28:f23f::/48`, `2001:67c:4e8::/48`, `2001:b28:f23c::/48`, `2a0a:f280::/32`)
  уйдут мимо туннеля, если в LAN раздаётся IPv6. IPv4-список в §3a сверен с
  `core.telegram.org/resources/cidr.txt` 2026-08-31 (9 префиксов, совпадает).
- **Geo-lookup ip-api.com идёт in-band**: при мёртвом туннеле новые серверы получают страну `ZZ`
  (видели 2026-07-06); смягчает seed-кэш `/etc/hynet/country_cache.json` в образе.
- **Динамические записи `created for …`** в `address-list=hynet` от FWD-правил на практике не истекали по
  TTL (2026-06-18) — при откате сервиса чистить руками: `/ip firewall address-list remove [find list=hynet dynamic=yes comment~"created"]`.

### Часть WAN-линий DPI-рвут зарубежный gRPC — эти мёртвые ноды бенайн

На отдельных линиях провайдера `*-2053-grpc` к *зарубежным* серверам падают: TCP-connect
проходит, а gRPC/REALITY-рукопожатие рвётся (падает даже крошечная проба — это **не** MTU).
У тех же серверов `:8444` vision / vmess / trojan / ss работают, и RU grpc работает. Это
**DPI конкретной линии, а не вина сервера или sing-box** — селектор просто никогда не выбирает
мёртвые grpc-ноды. Не перезапускай и не переконфигурируй из-за них.

### Go-only генерация и обновление

`healthcheck render` только записывает кандидатную конфигурацию. `healthcheck refresh` дополнительно проверяет её через `sing-box check`, пропускает неизменённый пул, сохраняет прежний конфиг, атомарно устанавливает кандидатный, перезапускает работающий sing-box, ждёт Clash API, восстанавливает `select.now`, а при неудачном запуске возвращает прежний конфиг.

```sh
/usr/local/bin/healthcheck refresh \
    --subscriptions-dir /tmp/sing-box/subscriptions.d \
    --active-config /tmp/config.json
```

Старый Python-пайплайн сверен с Go на локальных differential-фикстурах: пять провайдеров и сохранение узлов при отказе одного дали совпадающие JSON, карты стран и probe-порты; затем конфигурации прошли `sing-box check`. В образе остаётся только Go-путь, Python fallback удалён.

### Деплой правки скрипта в работающий контейнер

Правки `/usr/local/bin/*.sh` в живом контейнере переживают рестарт контейнера, но
**теряются при перетягивании образа** — долговечный путь = commit + пересборка образа через
CI. При заливке файла из Windows-checkout'а **сначала срежь CRLF** (`tr -d '\r'`): busybox-ash
падает с `syntax error: unexpected word (expecting "in")` на строке `case`/`for` с хвостовым
`\r`. Репозиторий форсит LF через `.gitattributes` (`*.sh text eol=lf`).

### Чтение здоровья

Read-only снимок штатными командами RouterOS (скилла `mikrotik-vpn-check` больше нет — удалён
2026-08-31 вместе со снятием стека; из проекта `monitoring` те же команды идут через `tools/rsh.py rb4011 "…"`):

```routeros
/container/print
/ip route print where routing-table=via-hynet
/ip firewall address-list print count-only where list=hynet
/container/shell [find where name~"hynet"] cmd="tail -20 /tmp/healthcheck.log"
/container/shell [find where name~"hynet"] cmd="ls -l /tmp/config.json; df /tmp"
```

Clash API с роутера или из LAN: `curl -H "Authorization: Bearer $CLASH_SECRET" http://172.20.0.2:9090/proxies/select`.

VPN **UP тогда и только тогда**, когда контейнер запущен, у `select.now` свежий delay, и маршрут
`via-hynet` активен — *независимо от числа мёртвых нод*. Мёртвые `*-grpc` могут быть benign DPI
конкретного WAN; не рестартовать только из-за числа мёртвых узлов. **Отдельно проверяй возраст
конфига** и `/tmp/sub-refresh.log`: повторные fetch/DNS/tmpfs ошибки означают сломанный refresh
даже при живом текущем выходе. Сначала запусти `sub-refresh.sh` вручную и прочитай ошибку, а не рестартуй вслепую.

## Лицензия

MIT.
