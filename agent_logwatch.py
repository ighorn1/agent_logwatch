#!/usr/bin/env python3
"""
Agent LogWatch — Analyse de logs multi-machines avec fenêtre horaire programmée.

Les machines distantes envoient leurs logs via MQTT vers agents/logwatch/<hostname>/logs.
L'agent pré-filtre (sans LLM), stocke en SQLite, puis analyse avec le LLM
pendant les créneaux horaires configurés.
"""
import json
import logging
import os
import re
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

from agents_core import BaseAgent, AgentContext, Message, MessageType

logger = logging.getLogger(__name__)

# ─── Pré-filtres sans LLM ────────────────────────────────────────────────────

FILTER_PATTERNS = [
    re.compile(r'\b(ERROR|CRITICAL|FATAL|PANIC|EMERG|ALERT|CRIT)\b'),
    re.compile(r'\bException\b|\bTraceback\b|\bTraceback \(most recent'),
    re.compile(r'\bsegfault\b|\bSegmentation fault\b', re.IGNORECASE),
    re.compile(r'\bout of memory\b|\bOOM killer\b|\bOOM-killer\b', re.IGNORECASE),
    re.compile(r'\b(failed|failure)\b', re.IGNORECASE),
    re.compile(r'\bkilled\b', re.IGNORECASE),
    re.compile(r'\b(BUG|Oops):\s'),
    re.compile(r'<[0-3]>'),          # syslog priorities 0=emerg, 1=alert, 2=crit, 3=err
    re.compile(r'\bcore dumped\b', re.IGNORECASE),
    re.compile(r'\bpanic\b', re.IGNORECASE),
    re.compile(r'\bdenied\b.*\bpermission\b|\bpermission\b.*\bdenied\b', re.IGNORECASE),
    re.compile(r'\bauthentication failure\b|\bfailed login\b|\bfailed password\b', re.IGNORECASE),
    re.compile(r'\bdisk full\b|\bno space left\b', re.IGNORECASE),
    re.compile(r'\bconnection refused\b|\bconnection timed out\b', re.IGNORECASE),
    re.compile(r'\bssh.*invalid user\b|\binvalid user.*ssh\b', re.IGNORECASE),
]

SEVERITY_RANK = {
    'EMERG': 0, 'ALERT': 1, 'CRIT': 2, 'CRITICAL': 2, 'FATAL': 2, 'PANIC': 2,
    'ERROR': 3, 'ERR': 3,
    'FAILED': 4, 'FAILURE': 4, 'DENIED': 4,
    'EXCEPTION': 5, 'TRACEBACK': 5,
    'KILLED': 6, 'OOM': 6, 'SEGFAULT': 6, 'CORE': 6,
}

CHUNK_SIZE = 150  # lignes envoyées au LLM par appel


def _detect_severity(line: str) -> str:
    line_up = line.upper()
    for kw, _ in sorted(SEVERITY_RANK.items(), key=lambda x: x[1]):
        if kw in line_up:
            return kw
    return 'ERROR'


class LogWatchAgent(BaseAgent):
    AGENT_TYPE   = "logwatch"
    DESCRIPTION  = (
        "Analyse de logs multi-machines. Reçoit les logs des machines distantes via MQTT, "
        "pré-filtre les erreurs, les analyse avec le LLM pendant les créneaux programmés, "
        "envoie des rapports par XMPP. Gestion de file de machines, round-robin, "
        "reprise sur interruption et analyse à la demande."
    )
    DEFAULT_CONFIG_PATH = "/opt/agent_logwatch/config/config.json"

    def get_skills_dir(self) -> str:
        return os.path.join(os.path.dirname(__file__), "skills")

    # ─── Init ─────────────────────────────────────────────────────────────────

    def __init__(self, config_path=None):
        super().__init__(config_path)
        self.db_path = Path(self.config.get("db_path", "/opt/agent_logwatch/data/logwatch.db"))
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db_lock = threading.Lock()
        self._init_db()

        # Scheduler APScheduler
        try:
            from apscheduler.schedulers.background import BackgroundScheduler
            self._scheduler = BackgroundScheduler(timezone="Europe/Paris")
        except ImportError:
            logger.error("apscheduler non installé — `pip install apscheduler`")
            self._scheduler = None

        # État analyse
        self._analysis_thread    = None
        self._analysis_stop      = threading.Event()
        self._slot_end_time      = None

        # Extension demandée
        self._pending_extension  = None    # dict: {machine_id, hostname}
        self._extension_event    = threading.Event()
        self._extension_granted  = False

    # ─── DB ───────────────────────────────────────────────────────────────────

    def _get_db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_db() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS machines (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname        TEXT    UNIQUE NOT NULL,
                    registered_at   TEXT    NOT NULL,
                    last_log_at     TEXT,
                    last_analyzed_at TEXT,
                    queue_position  INTEGER DEFAULT 0,
                    active          INTEGER DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS filtered_logs (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    machine_id  INTEGER NOT NULL,
                    log_line    TEXT    NOT NULL,
                    severity    TEXT,
                    received_at TEXT    NOT NULL,
                    analyzed    INTEGER DEFAULT 0,
                    FOREIGN KEY (machine_id) REFERENCES machines(id)
                );

                CREATE INDEX IF NOT EXISTS idx_fl_machine_analyzed
                    ON filtered_logs(machine_id, analyzed);

                CREATE TABLE IF NOT EXISTS analysis_sessions (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    machine_id   INTEGER NOT NULL,
                    slot_date    TEXT    NOT NULL,
                    status       TEXT    DEFAULT 'pending',
                    started_at   TEXT,
                    completed_at TEXT,
                    last_log_id  INTEGER DEFAULT 0,
                    UNIQUE(machine_id, slot_date),
                    FOREIGN KEY (machine_id) REFERENCES machines(id)
                );

                CREATE TABLE IF NOT EXISTS agent_config (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                INSERT OR IGNORE INTO agent_config VALUES ('analysis_start',      '02:00');
                INSERT OR IGNORE INTO agent_config VALUES ('analysis_end',        '04:00');
                INSERT OR IGNORE INTO agent_config VALUES ('max_overage_minutes', '30');
                INSERT OR IGNORE INTO agent_config VALUES ('enabled',             '1');
                INSERT OR IGNORE INTO agent_config VALUES ('log_retention_days',  '7');
                INSERT OR IGNORE INTO agent_config VALUES ('local_collect_time',  '');
            """)

    def _cfg(self, key: str, default: str = '') -> str:
        with self._get_db() as conn:
            row = conn.execute("SELECT value FROM agent_config WHERE key=?", (key,)).fetchone()
            return row['value'] if row else default

    def _set_cfg(self, key: str, value: str):
        with self._get_db() as conn:
            conn.execute("INSERT OR REPLACE INTO agent_config VALUES (?,?)", (key, value))

    # ─── Démarrage ────────────────────────────────────────────────────────────

    def on_start(self):
        # Souscriptions MQTT pour recevoir les logs des machines distantes
        self.mqtt.subscribe("agents/logwatch/+/logs",    self._on_log_received)
        self.mqtt.subscribe("agents/logwatch/register",  self._on_machine_register)

        # Démarrage du scheduler
        if self._scheduler:
            self._reload_schedule()
            self._scheduler.start()
            logger.info("Scheduler APScheduler démarré.")

        # Nettoyage des vieux logs au démarrage
        self._cleanup_old_logs()

        logger.info("Agent LogWatch démarré. En attente de logs sur agents/logwatch/+/logs")

    def setup_extra_subscriptions(self):
        pass  # tout est dans on_start

    # ─── Réception des logs ──────────────────────────────────────────────────

    def _on_machine_register(self, msg, topic: str):
        """Enregistrement explicite d'une machine via MQTT."""
        payload = msg.payload if hasattr(msg, 'payload') else str(msg)
        try:
            data     = json.loads(payload) if isinstance(payload, str) else payload
            hostname = str(data.get('hostname', '')).strip()
            if hostname:
                self._register_machine(hostname)
        except Exception as e:
            logger.error(f"[register] {e}")

    def _on_log_received(self, msg, topic: str):
        """
        Reçoit des logs bruts depuis une machine distante.
        Topic : agents/logwatch/<hostname>/logs
        Payload JSON : {"lines": [...]} ou {"log": "..."} ou texte brut multiligne
        """
        payload = msg.payload if hasattr(msg, 'payload') else str(msg)
        try:
            parts    = topic.split('/')
            hostname = parts[2] if len(parts) >= 4 else 'unknown'

            # Parser le payload
            if isinstance(payload, str):
                try:
                    data = json.loads(payload)
                    if isinstance(data, dict):
                        lines = data.get('lines') or data.get('logs') or []
                        if isinstance(lines, str):
                            lines = lines.splitlines()
                        if not lines and 'log' in data:
                            lines = str(data['log']).splitlines()
                    elif isinstance(data, list):
                        lines = data
                    else:
                        lines = payload.splitlines()
                except json.JSONDecodeError:
                    lines = payload.splitlines()
            elif isinstance(payload, bytes):
                lines = payload.decode('utf-8', errors='replace').splitlines()
            else:
                lines = []

            if not lines:
                return

            machine_id = self._register_machine(hostname)
            filtered   = self._prefilter(lines)

            if filtered:
                now = datetime.now().isoformat()
                with self._get_db() as conn:
                    conn.executemany(
                        "INSERT INTO filtered_logs (machine_id, log_line, severity, received_at) VALUES (?,?,?,?)",
                        [(machine_id, line, sev, now) for line, sev in filtered]
                    )
                    conn.execute(
                        "UPDATE machines SET last_log_at=? WHERE id=?",
                        (now, machine_id)
                    )
                logger.info(f"[{hostname}] {len(filtered)}/{len(lines)} lignes filtrées conservées")

        except Exception as e:
            logger.error(f"[_on_log_received] {e}", exc_info=True)

    def _prefilter(self, lines: list) -> list:
        """Filtre les lignes, retourne [(line, severity)]."""
        result = []
        for line in lines:
            line = str(line).strip()
            if not line:
                continue
            for pat in FILTER_PATTERNS:
                if pat.search(line):
                    result.append((line, _detect_severity(line)))
                    break
        return result

    def _register_machine(self, hostname: str) -> int:
        """Enregistre ou met à jour une machine, retourne son id."""
        with self._get_db() as conn:
            row = conn.execute("SELECT id FROM machines WHERE hostname=?", (hostname,)).fetchone()
            if row:
                return row['id']
            max_pos = conn.execute(
                "SELECT COALESCE(MAX(queue_position), 0) FROM machines"
            ).fetchone()[0]
            cur = conn.execute(
                "INSERT INTO machines (hostname, registered_at, queue_position) VALUES (?,?,?)",
                (hostname, datetime.now().isoformat(), max_pos + 1)
            )
            logger.info(f"Nouvelle machine enregistrée: {hostname} (pos={max_pos+1})")
            return cur.lastrowid

    # ─── Scheduler ────────────────────────────────────────────────────────────

    def _reload_schedule(self):
        """(Re)programme les jobs APScheduler selon la config DB."""
        if not self._scheduler:
            return
        for job_id in ('_slot_start', '_slot_end', '_local_collect'):
            try:
                self._scheduler.remove_job(job_id)
            except Exception:
                pass

        if self._cfg('enabled') != '1':
            logger.info("Analyse automatique désactivée.")
            return

        start_str = self._cfg('analysis_start', '02:00')
        end_str   = self._cfg('analysis_end',   '04:00')
        try:
            sh, sm = map(int, start_str.split(':'))
            eh, em = map(int, end_str.split(':'))
        except ValueError:
            logger.error(f"Format horaire invalide: {start_str}/{end_str}")
            return

        self._scheduler.add_job(
            self._start_slot, 'cron', hour=sh, minute=sm, id='_slot_start'
        )
        self._scheduler.add_job(
            self._signal_slot_end, 'cron', hour=eh, minute=em, id='_slot_end'
        )

        # Job de collecte locale (séparé, configurable indépendamment)
        local_collect = self._cfg('local_collect_time', '')
        if local_collect:
            try:
                lh, lm = map(int, local_collect.split(':'))
                self._scheduler.add_job(
                    self._collect_local_logs, 'cron',
                    hour=lh, minute=lm, id='_local_collect'
                )
                logger.info(f"Collecte locale programmée: {local_collect}")
            except ValueError:
                logger.error(f"Format local_collect_time invalide: {local_collect}")

        logger.info(f"Analyse programmée: {start_str} → {end_str}")

    def _start_slot(self):
        """Démarre la fenêtre d'analyse (appelé par APScheduler)."""
        end_str = self._cfg('analysis_end', '04:00')
        eh, em  = map(int, end_str.split(':'))
        now     = datetime.now()
        self._slot_end_time = now.replace(hour=eh, minute=em, second=0, microsecond=0)
        if self._slot_end_time <= now:
            self._slot_end_time += timedelta(days=1)

        self._analysis_stop.clear()
        self._analysis_thread = threading.Thread(
            target=self._analysis_loop, daemon=True, name="logwatch-analysis"
        )
        self._analysis_thread.start()
        logger.info(f"Créneau d'analyse démarré → fin à {self._slot_end_time.strftime('%H:%M')}")

    def _signal_slot_end(self):
        """Signale la fin du créneau (appelé par APScheduler)."""
        logger.info("Fin de créneau signalée.")
        self._analysis_stop.set()

    # ─── Collecte locale ─────────────────────────────────────────────────────

    def collect_local_logs(self, since: str = 'yesterday') -> str:
        """
        Collecte les logs de la machine locale via journalctl et les pré-filtre.
        Appelé automatiquement au début de chaque créneau, ou manuellement.
        Retourne un résumé de ce qui a été collecté.
        """
        import subprocess
        import socket

        local_hostname = self.config.get('local_hostname') or socket.getfqdn()
        units          = self.config.get('local_log_units', [])   # [] = tous les services
        since_str      = since or self.config.get('local_log_since', 'yesterday')

        cmd = ['journalctl', '--no-pager', '--output=short-iso', f'--since={since_str}']
        for unit in units:
            cmd += ['-u', unit]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60
            )
            raw_lines = result.stdout.splitlines()
        except subprocess.TimeoutExpired:
            logger.error("[local_logs] journalctl timeout")
            return "Erreur: journalctl timeout (60s)"
        except FileNotFoundError:
            logger.warning("[local_logs] journalctl non disponible sur cette machine")
            return "journalctl non disponible."
        except Exception as e:
            logger.error(f"[local_logs] {e}")
            return f"Erreur collecte locale: {e}"

        if not raw_lines:
            return f"Aucun log local depuis '{since_str}'."

        machine_id = self._register_machine(local_hostname)
        filtered   = self._prefilter(raw_lines)

        if filtered:
            now = datetime.now().isoformat()
            with self._get_db() as conn:
                conn.executemany(
                    "INSERT INTO filtered_logs (machine_id, log_line, severity, received_at) VALUES (?,?,?,?)",
                    [(machine_id, line, sev, now) for line, sev in filtered]
                )
                conn.execute(
                    "UPDATE machines SET last_log_at=? WHERE id=?",
                    (now, machine_id)
                )

        msg = (
            f"[local] {local_hostname}: {len(filtered)}/{len(raw_lines)} lignes filtrées"
            + (f" ({', '.join(units)})" if units else " (tous services)")
        )
        logger.info(msg)
        return msg

    def _collect_local_logs(self):
        """Wrapper silencieux appelé au début du slot."""
        try:
            self.collect_local_logs()
        except Exception as e:
            logger.error(f"[_collect_local_logs] {e}")

    # ─── Boucle d'analyse ────────────────────────────────────────────────────

    def _analysis_loop(self):
        """Thread principal d'analyse, tourne pendant le créneau."""
        try:
            machines = self._get_active_machines()
            if not machines:
                self._notify_admin("📭 LogWatch: aucune machine enregistrée à analyser.")
                return

            start_idx = self._find_resume_index(machines)
            total     = len(machines)

            for i in range(total):
                idx     = (start_idx + i) % total
                machine = machines[idx]
                mid     = machine['id']
                host    = machine['hostname']

                # Vérifier si le créneau est terminé avant de commencer une machine
                if self._analysis_stop.is_set():
                    overage_min = self._overage_minutes()
                    max_ov      = int(self._cfg('max_overage_minutes', '30'))

                    if overage_min > max_ov:
                        # Demander extension
                        if not self._ask_extension(mid, host, overage_min):
                            # Refusée ou timeout → pause
                            self._set_session_status(mid, 'paused')
                            self._notify_admin(
                                f"⏸️ LogWatch: analyse de **{host}** reportée au prochain créneau."
                            )
                            break

                self._analyze_machine(mid, host)

            else:
                # Boucle complète sans interruption
                self._notify_admin(
                    f"✅ LogWatch: analyse complète de {total} machine(s) terminée."
                )

        except Exception as e:
            logger.error(f"[analysis_loop] {e}", exc_info=True)
            self._notify_admin(f"❌ LogWatch: erreur dans la boucle d'analyse: {e}")

    def _get_active_machines(self) -> list:
        with self._get_db() as conn:
            rows = conn.execute(
                "SELECT id, hostname, queue_position FROM machines "
                "WHERE active=1 ORDER BY queue_position ASC"
            ).fetchall()
        return [dict(r) for r in rows]

    def _find_resume_index(self, machines: list) -> int:
        """Trouve l'index de la machine à reprendre (paused) ou commence à 0."""
        today = datetime.now().strftime('%Y-%m-%d')
        with self._get_db() as conn:
            row = conn.execute("""
                SELECT machine_id FROM analysis_sessions
                WHERE slot_date=? AND status='paused'
                ORDER BY id DESC LIMIT 1
            """, (today,)).fetchone()
        if not row:
            return 0
        paused_id = row['machine_id']
        for i, m in enumerate(machines):
            if m['id'] == paused_id:
                return i
        return 0

    def _overage_minutes(self) -> float:
        """Retourne les minutes de dépassement (positif = dépassement)."""
        if not self._slot_end_time:
            return 0.0
        delta = (datetime.now() - self._slot_end_time).total_seconds() / 60
        return max(0.0, delta)

    def _ask_extension(self, machine_id: int, hostname: str, overage: float) -> bool:
        """
        Demande à l'admin une extension du créneau.
        Attend la réponse (max 10 min).
        Retourne True si extension accordée.
        """
        max_ov = int(self._cfg('max_overage_minutes', '30'))
        self._pending_extension = {'machine_id': machine_id, 'hostname': hostname}
        self._extension_event.clear()
        self._extension_granted = False

        self._notify_admin(
            f"⏰ LogWatch: créneau terminé (dépassement {overage:.0f} min > max {max_ov} min).\n"
            f"Analyse en cours: **{hostname}** non terminée.\n"
            f"Tapez `/extend` pour accorder +{max_ov} min supplémentaires, "
            f"ou `/skip` pour reporter au prochain créneau."
        )

        # Attendre la réponse max 10 minutes
        answered = self._extension_event.wait(timeout=600)
        self._pending_extension = None

        if not answered:
            self._notify_admin(
                f"⏰ LogWatch: pas de réponse après 10 min → analyse de **{hostname}** reportée."
            )
            return False

        return self._extension_granted

    # ─── Analyse d'une machine ───────────────────────────────────────────────

    def _analyze_machine(self, machine_id: int, hostname: str):
        """Analyse les logs filtrés d'une machine avec le LLM."""
        today = datetime.now().strftime('%Y-%m-%d')

        # Créer ou récupérer la session d'analyse
        with self._get_db() as conn:
            session = conn.execute(
                "SELECT id, last_log_id FROM analysis_sessions "
                "WHERE machine_id=? AND slot_date=? AND status IN ('pending','paused')",
                (machine_id, today)
            ).fetchone()

            if session:
                session_id  = session['id']
                last_log_id = session['last_log_id']
                conn.execute(
                    "UPDATE analysis_sessions SET status='in_progress', started_at=? WHERE id=?",
                    (datetime.now().isoformat(), session_id)
                )
            else:
                # Vérifier si déjà 'done' aujourd'hui
                done = conn.execute(
                    "SELECT id FROM analysis_sessions WHERE machine_id=? AND slot_date=? AND status='done'",
                    (machine_id, today)
                ).fetchone()
                if done:
                    logger.info(f"[{hostname}] déjà analysée aujourd'hui.")
                    return

                conn.execute(
                    "INSERT INTO analysis_sessions (machine_id, slot_date, status, started_at) VALUES (?,?,?,?)",
                    (machine_id, today, 'in_progress', datetime.now().isoformat())
                )
                session_id  = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
                last_log_id = 0

        # Récupérer les logs filtrés non encore analysés
        with self._get_db() as conn:
            logs = conn.execute(
                "SELECT id, log_line, severity, received_at FROM filtered_logs "
                "WHERE machine_id=? AND id > ? AND analyzed=0 ORDER BY id ASC",
                (machine_id, last_log_id)
            ).fetchall()

        if not logs:
            logger.info(f"[{hostname}] Aucun log filtré à analyser.")
            self._set_session_status(machine_id, 'done', session_id=session_id)
            return

        self._notify_admin(
            f"🔍 LogWatch: analyse de **{hostname}** ({len(logs)} erreurs filtrées)…"
        )

        all_reports   = []
        last_id       = last_log_id
        logs_list     = [dict(r) for r in logs]

        for chunk_start in range(0, len(logs_list), CHUNK_SIZE):
            # Vérifier dépassement dans la boucle de chunks
            if self._analysis_stop.is_set():
                overage = self._overage_minutes()
                max_ov  = int(self._cfg('max_overage_minutes', '30'))
                if overage > max_ov:
                    # Sauvegarder le point de reprise
                    with self._get_db() as conn:
                        conn.execute(
                            "UPDATE analysis_sessions SET status='paused', last_log_id=? WHERE id=?",
                            (last_id, session_id)
                        )
                    self._notify_admin(
                        f"⏸️ LogWatch: pause mid-analyse de **{hostname}** "
                        f"(dépassement {overage:.0f} min). Reprise au prochain créneau."
                    )
                    return

            chunk     = logs_list[chunk_start:chunk_start + CHUNK_SIZE]
            chunk_txt = '\n'.join(
                f"[{r['received_at'][:19]}][{r['severity']}] {r['log_line']}"
                for r in chunk
            )

            prompt = (
                f"Tu analyses des logs d'erreurs de la machine **{hostname}**.\n"
                f"Synthétise les problèmes importants : type d'erreur, criticité (critique/haute/moyenne), "
                f"fréquence, cause probable, action recommandée.\n"
                f"Ne répète pas chaque ligne individuellement. Groupe les erreurs similaires.\n"
                f"Format de réponse : 🔴/🟠/🟡 Problème → Cause → Action\n\n"
                f"Logs ({chunk_start+1}–{min(chunk_start+CHUNK_SIZE, len(logs_list))}):\n{chunk_txt}"
            )

            report_chunk = self._call_llm(prompt)
            if report_chunk:
                all_reports.append(report_chunk)

            # Marquer comme analysés + mise à jour offset
            ids = [r['id'] for r in chunk]
            last_id = ids[-1]
            with self._get_db() as conn:
                conn.execute(
                    f"UPDATE filtered_logs SET analyzed=1 WHERE id IN ({','.join('?'*len(ids))})",
                    ids
                )
                conn.execute(
                    "UPDATE analysis_sessions SET last_log_id=? WHERE id=?",
                    (last_id, session_id)
                )

        # Rapport final
        if all_reports:
            report = (
                f"📊 **Rapport LogWatch — {hostname}**\n"
                f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M')} | "
                f"{len(logs_list)} erreurs analysées\n"
                f"{'─'*40}\n\n"
            )
            report += '\n\n'.join(all_reports)
            self._notify_admin(report)
        else:
            self._notify_admin(f"ℹ️ LogWatch: **{hostname}** — LLM n'a pas retourné de rapport.")

        # Marquer la session comme terminée
        with self._get_db() as conn:
            conn.execute(
                "UPDATE analysis_sessions SET status='done', completed_at=?, last_log_id=? WHERE id=?",
                (datetime.now().isoformat(), last_id, session_id)
            )
            conn.execute(
                "UPDATE machines SET last_analyzed_at=? WHERE id=?",
                (datetime.now().isoformat(), machine_id)
            )

    def _set_session_status(self, machine_id: int, status: str, session_id: int = None):
        today = datetime.now().strftime('%Y-%m-%d')
        with self._get_db() as conn:
            if session_id:
                conn.execute(
                    "UPDATE analysis_sessions SET status=? WHERE id=?",
                    (status, session_id)
                )
            else:
                conn.execute(
                    "UPDATE analysis_sessions SET status=? WHERE machine_id=? AND slot_date=?",
                    (status, machine_id, today)
                )

    # ─── LLM ─────────────────────────────────────────────────────────────────

    def _call_llm(self, prompt: str) -> str:
        """Appelle le LLM en respectant le lock BaseAgent."""
        lock = getattr(self, '_llm_lock', None)
        acquired = False
        try:
            if lock:
                acquired = lock.acquire(timeout=300)
                if not acquired:
                    return "(LLM indisponible après 5 min d'attente)"
            self.llm.reset_history()
            return self.llm.chat(prompt)
        except Exception as e:
            logger.error(f"[LLM] {e}")
            return f"(Erreur LLM: {e})"
        finally:
            if acquired and lock:
                lock.release()

    # ─── XMPP helpers ────────────────────────────────────────────────────────

    def _notify_admin(self, message: str):
        """Envoie un message à tous les admins XMPP."""
        try:
            if self.xmpp:
                self.xmpp.send_to_all_admins(message)
        except Exception as e:
            logger.error(f"[notify_admin] {e}")

    # ─── Commandes custom (/extend, /skip, /update) ──────────────────────────

    def handle_custom_command(self, cmd: str, args: str, source_msg=None):
        cmd_lower = cmd.lower()

        # Réponse à une demande d'extension de créneau
        if self._pending_extension:
            if cmd_lower == 'extend':
                self._extension_granted = True
                self._extension_event.set()
                max_ov = self._cfg('max_overage_minutes', '30')
                return f"⏱️ Extension accordée (+{max_ov} min). L'analyse continue."
            if cmd_lower == 'skip':
                self._extension_granted = False
                self._extension_event.set()
                return "⏸️ Analyse reportée au prochain créneau."

        # Dispatch direct vers les skills métier (contourne le LLM)
        if cmd_lower in ('logwatch', 'machine'):
            ctx = AgentContext(self)
            return self.skills.run(cmd_lower, args, ctx)

        if cmd_lower == 'update':
            return self._self_update()

        return f"Commande inconnue : /{cmd}"

    def on_broadcast(self, msg: Message):
        pass

    def _self_update(self) -> str:
        import subprocess
        try:
            out = subprocess.check_output(
                "cd /opt/agent_logwatch && git pull",
                shell=True, text=True, stderr=subprocess.STDOUT
            )
            subprocess.Popen(["systemctl", "restart", "agent_logwatch"])
            return f"Mise à jour:\n{out}\nRedémarrage…"
        except subprocess.CalledProcessError as e:
            return f"Erreur mise à jour: {e.output}"

    # ─── Nettoyage ────────────────────────────────────────────────────────────

    def _cleanup_old_logs(self):
        """Supprime les logs filtrés plus vieux que log_retention_days."""
        days = int(self._cfg('log_retention_days', '7'))
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        with self._get_db() as conn:
            cur = conn.execute(
                "DELETE FROM filtered_logs WHERE received_at < ? AND analyzed=1",
                (cutoff,)
            )
            if cur.rowcount:
                logger.info(f"Nettoyage: {cur.rowcount} logs anciens supprimés.")


if __name__ == "__main__":
    LogWatchAgent().run()
