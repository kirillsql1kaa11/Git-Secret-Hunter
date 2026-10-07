# Git Secret Hunter

Высокоскоростной инструмент аудита истории Git-репозиториев для выявления утечек API-ключей нейросетей, облачных токенов, приватных ключей и случайных секретов с высокой энтропией Шеннона. Оснащен интерактивным TUI-интерфейсом и модулем автоматического краулинга GitHub.

[![Release](https://img.shields.io/github/v/release/kirillsql1kaa11/Git-Secret-Hunter?style=flat-square)](https://github.com/kirillsql1kaa11/Git-Secret-Hunter/releases)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021-orange?style=flat-square)](Cargo.toml)

---

## Возможности

- **Анализ полной истории Git:** сканирование всех веток (`--all`), тегов, reflog и висячих объектов (dangling commits).
- **Дифференциальный поиск:** анализ исключительно добавленных строк (`diff -U0`), исключая повторные проверки неизмененного кода.
- **Многопоточная обработка:** параллельное сканирование коммитов на пуле потоков Rayon.
- **Zero-allocation энтропия:** расчет энтропии Шеннона на стеке без выделения памяти в куче.
- **Контекстный скоринг:** определение уровня достоверности (HIGH, NORMAL, LOW) с автоматическим подавлением фикстур, тестов и mock-данных.
- **Интерактивный TUI-инспектор:** терминальный интерфейс на базе Ratatui для просмотра коммитов, авторов, даты и контекста уязвимостей.
- **Автономный GitHub-краулер:** массовый поиск и аудит публичных репозиториев по поисковым запросам или случайной выборке.
- **Интеграция с CI/CD:** поддержка структурированного вывода JSON и возврата ненулевого кода при обнаружении критических утечек.

---

## Установка и запуск

### Вариант 1. Готовые бинарные файлы (Рекомендуется)

1. Перейдите на страницу [Релизов](https://github.com/kirillsql1kaa11/Git-Secret-Hunter/releases).
2. Скачайте архив для Windows: `git-secret-hunter-v0.1.0-windows-x64.zip`.
3. Распакуйте архив в любую удобную папку.
4. Запустите исполняемый файл через PowerShell или командную строку:

```powershell
.\git-secret-hunter.exe --help
```

> **Примечание для Windows:** Файл `libunwind.dll`, идущий в комплекте архива, должен находиться в одной папке с `git-secret-hunter.exe`.

### Вариант 2. Сборка из исходников

Для сборки требуется установленный компилятор [Rust](https://rustup.rs/) (версия 1.75+):

```bash
git clone https://github.com/kirillsql1kaa11/Git-Secret-Hunter.git
cd Git-Secret-Hunter
cargo build --release
```

Скомпилированный бинарный файл будет доступен по пути `target/release/git-secret-hunter.exe` (или `target/release/git-secret-hunter` на Linux/macOS).

---

## Примеры использования

### Быстрый аудит текущего репозитория

```powershell
git-secret-hunter
```

### Интерактивный TUI режим

Позволяет просматривать найденные уязвимости с деталями коммита и переключать их статус:

```powershell
git-secret-hunter --tui
```

### Сканирование определенной папки

```powershell
git-secret-hunter --path C:\Projects\MyRepo
```

### Поиск только ключей нейросетей (AI APIs)

```powershell
git-secret-hunter --ai-only
```

### Проверка перед коммитом (Staged changes)

Идеально подходит для pre-commit хуков:

```powershell
git-secret-hunter --staged
```

### Вывод в формате JSON для автоматизации

```powershell
git-secret-hunter --format json > report.json
```

### Массовый краулер публичных репозиториев GitHub

Аудит 50 случайных репозиториев:

```powershell
git-secret-hunter --crawl --crawl-limit 50 --crawl-depth 5
```

Краулинг репозиториев по поисковому запросу:

```powershell
git-secret-hunter --crawl --query "language:python bot openai" --crawl-limit 20
```

---

## Управление в TUI режиме

| Клавиша | Действие |
| :--- | :--- |
| `↑` / `k` | Переход к предыдущей записи |
| `↓` / `j` | Переход к следующей записи |
| `Space` / `m` | Переключение статуса (`ACTIVE RISK` / `RESOLVED`) |
| `q` / `Esc` | Выход из приложения |

---

## Поддерживаемые сигнатуры

### Ключи AI и языковых моделей
- OpenAI (`sk-proj-...`, `sk-admin-...`, `sk-...`)
- Anthropic Claude (`sk-ant-api03-...`, `sk-ant-admin01-...`)
- Google Gemini / Google AI Studio (`AIzaSy...`)
- DeepSeek API (`sk-[a-f0-9]{32}`)
- Together AI (`[a-f0-9]{64}`)
- Hugging Face Access Tokens (`hf_...`)
- Replicate API (`r8_...`)
- Groq Cloud API (`gsk_...`)
- OpenRouter API (`sk-or-v1-...`)
- Perplexity AI (`pplx-...`)
- Cohere AI API
- Mistral AI API

### Облачные платформы и авторизация
- AWS Access Key ID (`AKIA...`, `ASIA...`)
- GitHub Personal Access Tokens (`ghp_...`, `github_pat_...`)
- GitLab Personal Access Tokens (`glpat-...`)
- JSON Web Tokens (JWT)
- Приватные ключи (RSA, EC, DSA, OPENSSH)
- Slack Bot / User Tokens (`xoxb-...`, `xoxp-...`)
- Stripe Secret Keys (`sk_live_...`, `rk_live_...`)

### Анализ энтропии Шеннона
- Детекция токенов с энтропией $H \ge 4.5$ для поиска секретов нестандартных форматов.
- Фильтрация Git-хэшей, UUID и шаблонов заглушек.

---

## Параметры командной строки

| Опция | Описание | Значение по умолчанию |
| :--- | :--- | :--- |
| `-p, --path <PATH>` | Путь к целевому Git-репозиторию | `.` |
| `--tui` | Запуск интерактивного терминального интерфейса | `false` |
| `--ai-only` | Поиск исключительно токенов AI-сервисов | `false` |
| `--include-dangling` | Включать проверку удаленных и висячих коммитов | `false` |
| `--no-entropy` | Отключить расчет энтропии Шеннона | `false` |
| `--entropy-threshold <VAL>` | Порог энтропии Шеннона | `4.5` |
| `--format <FORMAT>` | Формат вывода (`text` или `json`) | `text` |
| `--staged` | Проверять только подготовленные к коммиту файлы | `false` |
| `--crawl` | Запустить автономный GitHub-краулер | `false` |
| `--crawl-limit <NUM>` | Количество репозиториев для краулинга | `100` |
| `--crawl-depth <NUM>` | Глубина коммитов на репозиторий в краулере | `10` |
| `--github-token <TOKEN>` | Персональный токен GitHub для обхода rate limit | - |
| `--query <QUERY>` | Поисковый запрос для поиска репозиториев | - |

---

## Лицензия

Проект распространяется под лицензией [MIT](LICENSE).
