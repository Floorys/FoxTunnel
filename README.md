# FoxTunnel

**FoxTunnel** — расширение Firefox (WebExtension Manifest V2) с локальным помощником на Python (Native Messaging), которое запускает локальное ядро **sing-box** и направляет через него веб-трафик браузера.

> **Важно:** FoxTunnel **не является системным VPN** и не создаёт TUN-интерфейс. Он управляет только трафиком Firefox, доступным через API WebExtensions (`proxy.onRequest` и `webRequest`), и не перехватывает трафик других программ, системных служб ОС, внутренних служб Firefox и уже установленных соединений.

---

## Архитектура

```text
Firefox WebExtension (popup / options / background)
  ├── browser.webRequest.onBeforeRequest (блокировка и fail-closed kill switch)
  ├── browser.proxy.onRequest (SOCKS5 127.0.0.1:2080, proxyDNS: true / direct)
  └── browser.runtime.connectNative("io.foxtunnel.host")
        │  (4-байтный префикс длины + JSON через binary stdin/stdout)
        ▼
Python Native Messaging Host (native/host.py, только stdlib)
  ├── валидация outbound и правил маршрутизации
  ├── блокировка второго экземпляра (host.lock)
  ├── генерация временного конфига в %LOCALAPPDATA%\FoxTunnel
  ├── Windows Job Object (KILL_ON_JOB_CLOSE)
  └── запуск sing-box.exe run -c <temp_config.json>
        │
        ▼
Локальное ядро sing-box (1.14.4)
  ├── inbound: socks 127.0.0.1:<port>
  ├── DNS: local (bootstrap) и опционально DoH через detour -> proxy
  └── outbound: VLESS / VMess / Hysteria2 / Trojan / Shadowsocks / TUIC / AnyTLS / SOCKS / HTTP
```

### Почему ядро нельзя поместить прямо внутрь WebExtension

Расширения Firefox выполняются в изолированной браузерной песочнице (JavaScript/WebAssembly без доступа к произвольным TCP/UDP-сокетам ОС, QUIC/TLS-транспортам вроде Hysteria2/TUIC и без запуска бинарных файлов). Поэтому WebExtension общается со стандартным механизмом Firefox **Native Messaging**, который запускает локальный скрипт-помощник `native/host.py`, а тот — официальный бинарный файл `sing-box.exe`.

---

## Ограничения Firefox и модели работы

1. **Только трафик WebExtensions в Firefox.** Трафик других браузеров, приложений ОС, обновлений Windows, системных служб самого Firefox, страниц `about:*` / защищённых доменов Mozilla и соединений, открытых до включения VPN (WebSocket/HTTP3/keep-alive), не гарантируется к перехвату. После смены маршрута перезагрузите нужные вкладки или закройте старые.
2. **Нет системного прокси и нет TUN.** Системные настройки прокси Windows не изменяются.
3. **Нельзя гарантировать проверку удалённого сервера по одному лишь старту.** Статус «Работает» означает, что локальный `sing-box` запустился и отвечает на SOCKS5-рукопожатие на `127.0.0.1:<порт>`. Реальную доступность удалённого узла проверяйте открытием сайта в браузере (при включённом маршруте).
4. **Неподдерживаемые Xray-функции.** XHTTP (`splithttp`), KCP (`mkcp`), Xray TCP HTTP-camouflage (`headerType=http`), `flow=xtls-rprx-vision-udp443`, `pqv` и port hopping не конвертируются автоматически из URI — используйте стандартный JSON-объект `outbound` sing-box.

---

## Требования

- **Windows 10 / 11** (без прав администратора).
- **Firefox 140+** (в `manifest.json` указано `strict_min_version: "140.0"` для совместимости с `data_collection_permissions`; для локальной отладки на более старой версии Firefox временно удалите `data_collection_permissions` и снизьте `strict_min_version`).
- **Python 3.10+** (без сторонних pip-зависимостей).
- **sing-box 1.14.4** в `native/bin/sing-box.exe` (при клонировании из Git скачивается и проверяется по SHA-256 через `native\install.cmd -DownloadCore` или `native/download_core.py`).

---

## Установка и запуск (шаг за шагом)

### 1. Установка Native Messaging Host (без прав администратора)

Если вы скачали исходники с GitHub (без бинарника в `native/bin`), запустите из корня проекта:

```cmd
native\install.cmd -DownloadCore
```

Если `native/bin/sing-box.exe` уже лежит в папке (например, из готового архива релиза), достаточно:

```cmd
native\install.cmd
```

Или напрямую через PowerShell (в текущем процессе):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\native\install.ps1 -DownloadCore
```

Установщик:
- проверяет Python 3.10+ и `native/bin/sing-box.exe`;
- создаёт `native/host.cmd` (без вывода в stdout/stderr, с корректной обработкой пробелов и кириллицы в путях);
- создаёт `native/io.foxtunnel.host.json` (`allowed_extensions: ["foxtunnel@local"]`);
- регистрирует путь в реестре **только для текущего пользователя**: `HKCU\Software\Mozilla\NativeMessagingHosts\io.foxtunnel.host`;
- защищает от случайной перезаписи, если уже зарегистрирована другая установка FoxTunnel.

### 2. Загрузка временного расширения через `about:debugging`

1. Откройте Firefox и перейдите на страницу `about:debugging#/runtime/this-firefox`.
2. Нажмите **«Загрузить временное дополнение…»** (*Load Temporary Add-on…*).
3. Выберите файл `extension\manifest.json` из папки проекта.
4. Закрепите иконку FoxTunnel на панели инструментов Firefox.

> Для постоянного использования без `about:debugging` в релизном Firefox требуется подписанный на AMO пакет `.xpi` (см. раздел «Сборка XPI и подпись AMO»). В Firefox Developer Edition / Nightly можно отключить требование подписи через `xpinstall.signatures.required = false` в `about:config`.

---

## Добавление профиля

Откройте **Настройки** расширения:

- **Импорт ссылок или подписки:** поддерживаются `vless://`, `vmess://` (base64 JSON), `hysteria2://` / `hy2://`, `trojan://`, `ss://` (SIP002 и legacy base64), `tuic://`, `anytls://`, `socks://` / `socks5://`, `http://` / `https://`, а также base64-подписки. Импорт подписки атомарен: при ошибке в любой строке импорт отменяется целиком с указанием номера строки.
- **Обновляемые подписки:** при загрузке по HTTPS URL подписку можно сохранить (по умолчанию включено), после чего обновлять вручную кнопками **«Обновить»** / **«Обновить все»** (также есть кнопка в popup) или включить опциональное автообновление раз в 24 часа и при запуске. При обновлении заменяются только серверы этой подписки, а ручные профили не затрагиваются.
- **Ручной редактор JSON:** принимает один объект `outbound` sing-box (не полный конфиг Xray). Кнопка **«Проверить ядром»** запускает `sing-box check` для проверки синтаксиса.

Пример тестового JSON outbound (VLESS Reality, фиктивный адрес):

```json
{
  "type": "vless",
  "server": "192.0.2.11",
  "server_port": 443,
  "uuid": "00000000-0000-4000-8000-000000000001",
  "flow": "xtls-rprx-vision",
  "tls": {
    "enabled": true,
    "server_name": "www.example.com",
    "utls": { "enabled": true, "fingerprint": "chrome" },
    "reality": {
      "enabled": true,
      "public_key": "dGVzdC1yZWFsaXR5LXB1YmxpYy1rZXktMzItYnl0ZXM",
      "short_id": "0123abcd"
    }
  }
}
```

---

## Маршрутизация и Global Mode

Правила проверяются **сверху вниз**, побеждает **первое совпадение**:

- **Точный домен** (`domain`): точное совпадение хоста (`example.com`).
- **Домен и поддомены** (`suffix`): `example.com` и любые `*.example.com`.
- **Подстрока в домене** (`keyword`): вхождение строки в имя хоста.

Действия: **VPN** (`proxy`), **Напрямую** (`direct`), **Блокировать** (`block`).

### Примеры правил

1. Выборочный VPN:
   - Режим: **По правилам**, Без совпавшего правила: **Напрямую**.
   - `1. ads.example.invalid` (`suffix` → **Блокировать**)
   - `2. local-portal.example.invalid` (`domain` → **Напрямую**)
   - `3. target-site.example.invalid` (`suffix` → **VPN**)
2. **Global Mode («Весь веб-трафик»):**
   - Маршрут по умолчанию становится **VPN**, при этом локальные исключения (`localhost`, частные IP, `.local`, однословные имена при включённом `bypassLocal`) и ваши пользовательские правила (`direct`/`block`) продолжают действовать.

Примечание по безопасности маршрутов: Firefox передаёт в локальный SOCKS5-порт sing-box только запросы, которым назначен `proxy` (или резервный `block`). Правила `direct` выполняются самим Firefox и **не добавляются** в `sing-box`, поэтому `sing-box` физически не может отправить VPN-трафик напрямую.

---

## Kill Switch, WebRTC и DNS

### Kill Switch

- Действует **только для запросов, которым назначен VPN** (и при подключении, которое пользователь не отключил вручную).
- Правила `direct` и локальные исключения продолжают работать напрямую.
- Правила `block` блокируются в Firefox (`webRequest.onBeforeRequest`) и дублируются в `sing-box` (`action: "reject"`), не превращаясь в `direct` даже при падении ядра.
- Если ядро завершилось с ошибкой, в popup и в баннере страницы настроек появляется кнопка **«Отключить kill switch и вернуть прямой трафик»** для явного возврата к обычному соединению.

### WebRTC

При активном подключении и включённой опции «Ограничить непроксируемый UDP в WebRTC» расширение устанавливает `browser.privacy.network.webRTCIPHandlingPolicy = "disable_non_proxied_udp"` и отключает сетевую предзагрузку (`networkPredictionEnabled = false`). При ручном отключении вызывается `.clear({})`, возвращая исходные настройки браузера.

### DNS

Доступны два режима для VPN-назначений:

1. **SOCKS5 `proxyDNS` (по умолчанию):** Firefox передаёт имя домена в SOCKS5-запросе на `sing-box`, а `sing-box` передаёт домен удалённому прокси-серверу.
2. **DoH внутри `sing-box`:** `sing-box` разрешает домены через `https`-сервер (по IP, например `1.1.1.1`) с `detour: "proxy"` и правилом `action: "resolve"`.

Честные ограничения DNS:
- **Прямые правила** используют DNS Firefox и операционной системы.
- **Имя самого VPN-сервера** (если в профиле указан домен, а не IP) разрешается системным bootstrap-резолвером (`type: "local"`) до установки туннеля. Чтобы уменьшить bootstrap-утечку, укажите в профиле **IP-адрес сервера** и **TLS `server_name` (SNI)**.
- Рекурсивного DNS нет: bootstrap DoH указан по IP и не зависит сам от себя.

---

## Диагностика, проверка доступности и тема

- **Проверка доступности конфига («пинг»):** кнопка **«Проверить доступность конфига»** в popup, **«Проверить»** / **«Проверить все»** в списке профилей или **«Проверить связь»** в редакторе запускает изолированный временный экземпляр `sing-box` на свободном локальном порту (не затрагивая активное подключение) и выполняет реальный HTTPS/HTTP-запрос через туннель на настраиваемый URL (по умолчанию `https://cp.cloudflare.com/generate_204`), измеряя задержку и проверяя TLS/авторизацию.
- **Тёмная тема:** во вкладке **«Сеть и защита»** и в шапке настроек можно выбрать **Авто** (следует за темой системы/Firefox), **Светлую** или **Тёмную** тему.
- Во вкладке **«Диагностика»**:
  - **Проверить помощник:** показывает статус процесса, PID, порт, версию `sing-box`, путь к данным и уровни контроля `proxy.settings` / WebRTC в Firefox.
  - **Обновить журнал ядра:** показывает хвост `core.log` (очищается при каждом запуске ядра; размер ограничен 512 КБ).
  - **События расширения:** отображает локальные события запуска, ошибок и переключений.

---

## Сборка XPI и подпись AMO

Собрать неподписанный XPI-пакет:

```cmd
python scripts\build.py
```

Результат сохраняется в `dist\foxtunnel-<version>.xpi`.

Для установки в обычный релизный Firefox без `about:debugging` расширение нужно загрузить на [addons.mozilla.org (AMO)](https://addons.mozilla.org/developers/) (размещение в каталоге или Self-Distribution). После проверки и подписи Mozilla вернёт подписанный `.xpi`.

---

## Удаление и расположение данных

1. Отключите/удалите расширение в `about:addons` (или закройте временное дополнение в `about:debugging`).
2. Удалите регистрацию native host:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\native\uninstall.ps1
```

Скрипт удаления удаляет только ключ реестра `HKCU\Software\Mozilla\NativeMessagingHosts\io.foxtunnel.host` (если он указывает на текущую папку проекта) и сгенерированные `native/host.cmd` и `native/io.foxtunnel.host.json`. Пользовательские данные и бинарник не удаляются автоматически.

Расположение данных:
- Временные файлы и журнал ядра: `%LOCALAPPDATA%\FoxTunnel\` (`core.log`, `host.lock`, временный `config-*.json`, который перезаписывается и удаляется при остановке).
- Настройки и профили расширения: локальное хранилище Firefox (`browser.storage.local`).

> **Предупреждение о секретах:** профили (UUID, пароли, ключи Reality), `browser.storage.local`, экспортируемый `foxtunnel-backup.json` и временный конфиг ядра во время работы хранятся на диске **в открытом виде без шифрования**. Не публикуйте резервные копии, `core.log` и не передавайте ссылки подписок третьим лицам.

---

## Проверка проекта одной командой

Запуск всех автоматических проверок (синтаксис Python, unit-тесты, проверка всех 6 тестовых конфигов через `sing-box.exe check`, сборка и валидация `.xpi`, проверка framing stdout native host и JS-тесты при наличии Node.js):

```cmd
python scripts\verify.py
```

---

## Лицензия

Проект FoxTunnel распространяется под лицензией **GNU General Public License v3.0 (GPL-3.0)** — см. файл [LICENSE](LICENSE).

Ядро [SagerNet/sing-box](https://github.com/SagerNet/sing-box) распространяется отдельно под собственной лицензией GPL-3.0 (файл `native/bin/LICENSE` скачивается вместе с бинарником). FoxTunnel является независимым клиентским расширением и не аффилирован с проектом `sing-box`.


