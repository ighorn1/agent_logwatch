"""
Skill LOGWATCH — contrôle de l'agent : schedule, analyse à la demande, statut.

Usage LLM :
  SKILL:logwatch ARGS:status
  SKILL:logwatch ARGS:schedule show
  SKILL:logwatch ARGS:schedule set <HH:MM-HH:MM>
  SKILL:logwatch ARGS:schedule enable
  SKILL:logwatch ARGS:schedule disable
  SKILL:logwatch ARGS:overage <minutes>
  SKILL:logwatch ARGS:analyze <hostname>
  SKILL:logwatch ARGS:analyze_all
  SKILL:logwatch ARGS:retention <jours>
  SKILL:logwatch ARGS:logs <hostname> [N]
  SKILL:logwatch ARGS:reset <hostname>
"""
import threading
from datetime import datetime, timedelta

DESCRIPTION = "Contrôle LogWatch : schedule, analyse à la demande, statut, logs en attente, collecte locale"
USAGE = (
    "SKILL:logwatch ARGS:status\n"
    "SKILL:logwatch ARGS:schedule show\n"
    "SKILL:logwatch ARGS:schedule set <HH:MM-HH:MM>\n"
    "SKILL:logwatch ARGS:schedule enable|disable\n"
    "SKILL:logwatch ARGS:overage <minutes>\n"
    "SKILL:logwatch ARGS:analyze <hostname>\n"
    "SKILL:logwatch ARGS:analyze_all\n"
    "SKILL:logwatch ARGS:collect [since]\n"
    "SKILL:logwatch ARGS:retention <jours>\n"
    "SKILL:logwatch ARGS:logs <hostname> [N]\n"
    "SKILL:logwatch ARGS:reset <hostname>"
)


def _db(context):
    return context.agent._get_db()


def _cfg(context, key, default=''):
    return context.agent._cfg(key, default)


def _set_cfg(context, key, value):
    context.agent._set_cfg(key, value)


def run(args: str, context) -> str:
    parts  = args.strip().split(None, 1)
    action = parts[0].lower() if parts else 'status'
    rest   = parts[1].strip() if len(parts) > 1 else ''

    # ── status ────────────────────────────────────────────────────────────────
    if action == 'status':
        agent = context.agent
        today = datetime.now().strftime('%Y-%m-%d')

        enabled   = _cfg(context, 'enabled', '1') == '1'
        start     = _cfg(context, 'analysis_start', '02:00')
        end       = _cfg(context, 'analysis_end',   '04:00')
        max_ov    = _cfg(context, 'max_overage_minutes', '30')
        retention = _cfg(context, 'log_retention_days', '7')

        is_running = (
            agent._analysis_thread is not None and
            agent._analysis_thread.is_alive()
        )

        with _db(context) as conn:
            nb_machines = conn.execute(
                "SELECT COUNT(*) FROM machines WHERE active=1"
            ).fetchone()[0]
            nb_pending  = conn.execute(
                "SELECT COUNT(*) FROM filtered_logs WHERE analyzed=0"
            ).fetchone()[0]
            today_sessions = conn.execute(
                "SELECT COUNT(*) as cnt, status FROM analysis_sessions "
                "WHERE slot_date=? GROUP BY status",
                (today,)
            ).fetchall()

        schedule_status = f"{'✅ activé' if enabled else '❌ désactivé'} ({start} → {end})"
        analysis_status = "🔄 en cours" if is_running else "⏸️ idle"

        lines = [
            "── Statut LogWatch ────────────────────────────",
            f"  Analyse auto  : {schedule_status}",
            f"  Analyse actuel: {analysis_status}",
            f"  Dépassement   : max {max_ov} min",
            f"  Rétention logs: {retention} jours",
            f"  Machines activ: {nb_machines}",
            f"  Logs en attent: {nb_pending} erreurs filtrées",
            f"  Auj. ({today}):",
        ]
        for s in today_sessions:
            lines.append(f"    {s['status']}: {s['cnt']} machine(s)")

        if agent._pending_extension:
            host = agent._pending_extension.get('hostname', '?')
            lines.append(f"  ⏰ Extension en attente pour: {host}")

        return "\n".join(lines)

    # ── schedule ──────────────────────────────────────────────────────────────
    if action == 'schedule':
        sub_parts = rest.split(None, 1)
        sub       = sub_parts[0].lower() if sub_parts else 'show'
        sub_rest  = sub_parts[1].strip() if len(sub_parts) > 1 else ''

        if sub == 'show':
            start   = _cfg(context, 'analysis_start', '02:00')
            end     = _cfg(context, 'analysis_end',   '04:00')
            enabled = _cfg(context, 'enabled', '1') == '1'
            return (
                f"Créneau d'analyse : {start} → {end}\n"
                f"État : {'activé ✅' if enabled else 'désactivé ❌'}"
            )

        if sub == 'set':
            # Format : HH:MM-HH:MM
            if '-' not in sub_rest:
                return "Format: schedule set HH:MM-HH:MM  (ex: 02:00-04:00)"
            try:
                start_s, end_s = sub_rest.split('-', 1)
                # Validation
                sh, sm = map(int, start_s.strip().split(':'))
                eh, em = map(int, end_s.strip().split(':'))
                if not (0 <= sh < 24 and 0 <= sm < 60 and 0 <= eh < 24 and 0 <= em < 60):
                    return "Heures invalides."
            except ValueError:
                return "Format: HH:MM-HH:MM"
            _set_cfg(context, 'analysis_start', start_s.strip())
            _set_cfg(context, 'analysis_end',   end_s.strip())
            context.agent._reload_schedule()
            return f"✅ Créneau mis à jour : {start_s.strip()} → {end_s.strip()}"

        if sub in ('enable', 'disable'):
            val = '1' if sub == 'enable' else '0'
            _set_cfg(context, 'enabled', val)
            context.agent._reload_schedule()
            return f"✅ Analyse automatique {'activée' if val=='1' else 'désactivée'}."

        return "Sub-commande inconnue. Utilise : show, set <HH:MM-HH:MM>, enable, disable"

    # ── overage ───────────────────────────────────────────────────────────────
    if action == 'overage':
        try:
            minutes = int(rest)
            if minutes < 0:
                return "La valeur doit être >= 0."
        except ValueError:
            return "Format: overage <minutes>"
        _set_cfg(context, 'max_overage_minutes', str(minutes))
        return f"✅ Dépassement max : {minutes} min."

    # ── retention ─────────────────────────────────────────────────────────────
    if action == 'retention':
        try:
            days = int(rest)
            if days < 1:
                return "Minimum 1 jour."
        except ValueError:
            return "Format: retention <jours>"
        _set_cfg(context, 'log_retention_days', str(days))
        return f"✅ Rétention logs : {days} jours."

    # ── analyze <hostname> ────────────────────────────────────────────────────
    if action == 'analyze':
        hostname = rest.strip()
        if not hostname:
            return "Format: analyze <hostname>"

        with _db(context) as conn:
            row = conn.execute(
                "SELECT id FROM machines WHERE hostname=? AND active=1", (hostname,)
            ).fetchone()
        if not row:
            return f"Machine '{hostname}' introuvable ou inactive."

        machine_id = row['id']

        def _run_now():
            agent = context.agent
            # Créneau fictif généreux pour l'analyse à la demande
            agent._slot_end_time = datetime.now() + timedelta(hours=4)
            agent._analysis_stop.clear()
            agent._analyze_machine(machine_id, hostname)

        t = threading.Thread(target=_run_now, daemon=True, name=f"logwatch-demand-{hostname}")
        t.start()
        return f"🚀 Analyse de **{hostname}** lancée (arrière-plan)."

    # ── analyze_all ───────────────────────────────────────────────────────────
    if action == 'analyze_all':
        agent = context.agent
        if agent._analysis_thread and agent._analysis_thread.is_alive():
            return "⚠️ Une analyse est déjà en cours."

        def _run_all():
            agent._slot_end_time = datetime.now() + timedelta(hours=8)
            agent._analysis_stop.clear()
            agent._analysis_loop()

        t = threading.Thread(target=_run_all, daemon=True, name="logwatch-demand-all")
        t.start()
        return "🚀 Analyse complète de toutes les machines lancée (arrière-plan)."

    # ── logs <hostname> [N] ───────────────────────────────────────────────────
    if action == 'logs':
        p        = rest.split(None, 1)
        hostname = p[0].strip() if p else ''
        try:
            limit = int(p[1]) if len(p) > 1 else 20
        except ValueError:
            limit = 20

        if not hostname:
            return "Format: logs <hostname> [N]"

        with _db(context) as conn:
            m = conn.execute(
                "SELECT id FROM machines WHERE hostname=?", (hostname,)
            ).fetchone()
            if not m:
                return f"Machine '{hostname}' introuvable."
            rows = conn.execute(
                "SELECT log_line, severity, received_at, analyzed "
                "FROM filtered_logs WHERE machine_id=? ORDER BY id DESC LIMIT ?",
                (m['id'], limit)
            ).fetchall()

        if not rows:
            return f"Aucun log filtré pour {hostname}."

        lines = [f"── {limit} derniers logs filtrés de {hostname} ──"]
        for r in rows:
            ana = "✓" if r['analyzed'] else "○"
            lines.append(
                f"  {ana} [{r['received_at'][:16]}][{r['severity']:8s}] {r['log_line'][:120]}"
            )
        return "\n".join(lines)

    # ── collect [since] ───────────────────────────────────────────────────────
    if action == 'collect':
        since = rest.strip() or 'yesterday'
        result = context.agent.collect_local_logs(since=since)
        return f"✅ Collecte locale terminée:\n{result}"

    # ── reset <hostname> ──────────────────────────────────────────────────────
    if action == 'reset':
        hostname = rest.strip()
        if not hostname:
            return "Format: reset <hostname>"
        with _db(context) as conn:
            m = conn.execute(
                "SELECT id FROM machines WHERE hostname=?", (hostname,)
            ).fetchone()
            if not m:
                return f"Machine '{hostname}' introuvable."
            # Réinitialise les sessions et marque les logs comme non-analysés
            conn.execute(
                "DELETE FROM analysis_sessions WHERE machine_id=?", (m['id'],)
            )
            conn.execute(
                "UPDATE filtered_logs SET analyzed=0 WHERE machine_id=?", (m['id'],)
            )
            conn.execute(
                "UPDATE machines SET last_analyzed_at=NULL WHERE id=?", (m['id'],)
            )
        return f"✅ {hostname} réinitialisée — tous les logs seront ré-analysés."

    return (
        "Action inconnue. Disponible : status, schedule, overage, retention, "
        "analyze, analyze_all, logs, reset"
    )
