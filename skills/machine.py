"""
Skill MACHINE — gestion des machines qui envoient leurs logs.

Usage LLM :
  SKILL:machine ARGS:list
  SKILL:machine ARGS:queue
  SKILL:machine ARGS:add <hostname>
  SKILL:machine ARGS:remove <hostname>
  SKILL:machine ARGS:status <hostname>
  SKILL:machine ARGS:reorder <hostname> <position>
  SKILL:machine ARGS:activate <hostname>
  SKILL:machine ARGS:deactivate <hostname>
"""
from datetime import datetime

DESCRIPTION = "Gestion des machines enregistrées : liste, file d'attente, ajout, suppression, statut"
USAGE = (
    "SKILL:machine ARGS:list\n"
    "SKILL:machine ARGS:queue\n"
    "SKILL:machine ARGS:add <hostname>\n"
    "SKILL:machine ARGS:remove <hostname>\n"
    "SKILL:machine ARGS:status <hostname>\n"
    "SKILL:machine ARGS:reorder <hostname> <position>\n"
    "SKILL:machine ARGS:activate <hostname>\n"
    "SKILL:machine ARGS:deactivate <hostname>"
)


def _db(context):
    return context.agent._get_db()


def run(args: str, context) -> str:
    parts  = args.strip().split(None, 1)
    action = parts[0].lower() if parts else 'list'
    rest   = parts[1].strip() if len(parts) > 1 else ''

    # ── list ──────────────────────────────────────────────────────────────────
    if action == 'list':
        with _db(context) as conn:
            rows = conn.execute(
                "SELECT hostname, active, last_log_at, last_analyzed_at, queue_position "
                "FROM machines ORDER BY queue_position ASC"
            ).fetchall()
        if not rows:
            return "Aucune machine enregistrée."
        lines = ["── Machines enregistrées ─────────────────────"]
        for r in rows:
            status   = "🟢 actif" if r['active'] else "🔴 inactif"
            last_log = r['last_log_at'][:16] if r['last_log_at'] else "jamais"
            last_ana = r['last_analyzed_at'][:16] if r['last_analyzed_at'] else "jamais"
            lines.append(
                f"  [{r['queue_position']:2d}] {r['hostname']:<30s} {status}\n"
                f"       Dernier log: {last_log}  |  Dernière analyse: {last_ana}"
            )
        return "\n".join(lines)

    # ── queue ─────────────────────────────────────────────────────────────────
    if action == 'queue':
        today = datetime.now().strftime('%Y-%m-%d')
        with _db(context) as conn:
            rows = conn.execute(
                "SELECT m.hostname, m.queue_position, m.active, "
                "       COALESCE(s.status, 'pending') as session_status "
                "FROM machines m "
                "LEFT JOIN analysis_sessions s "
                "       ON s.machine_id=m.id AND s.slot_date=? "
                "ORDER BY m.queue_position ASC",
                (today,)
            ).fetchall()
        if not rows:
            return "Aucune machine dans la file."
        icons = {'done': '✅', 'in_progress': '🔄', 'paused': '⏸️', 'pending': '⏳'}
        lines = [f"── File d'analyse — {today} ─────────────────"]
        for r in rows:
            active = "" if r['active'] else " [inactif]"
            icon   = icons.get(r['session_status'], '⏳')
            lines.append(
                f"  {r['queue_position']:2d}. {icon} {r['hostname']}{active} "
                f"({r['session_status']})"
            )
        return "\n".join(lines)

    # ── add ───────────────────────────────────────────────────────────────────
    if action == 'add':
        hostname = rest.strip()
        if not hostname:
            return "Format: machine add <hostname>"
        with _db(context) as conn:
            existing = conn.execute(
                "SELECT id FROM machines WHERE hostname=?", (hostname,)
            ).fetchone()
            if existing:
                return f"Machine '{hostname}' déjà enregistrée."
            max_pos = conn.execute(
                "SELECT COALESCE(MAX(queue_position), 0) FROM machines"
            ).fetchone()[0]
            conn.execute(
                "INSERT INTO machines (hostname, registered_at, queue_position) VALUES (?,?,?)",
                (hostname, datetime.now().isoformat(), max_pos + 1)
            )
        return f"✅ Machine '{hostname}' enregistrée (position {max_pos + 1})."

    # ── remove ────────────────────────────────────────────────────────────────
    if action == 'remove':
        hostname = rest.strip()
        if not hostname:
            return "Format: machine remove <hostname>"
        with _db(context) as conn:
            cur = conn.execute("DELETE FROM machines WHERE hostname=?", (hostname,))
            if cur.rowcount == 0:
                return f"Machine '{hostname}' introuvable."
        return f"🗑️ Machine '{hostname}' supprimée."

    # ── status ────────────────────────────────────────────────────────────────
    if action == 'status':
        hostname = rest.strip()
        if not hostname:
            return "Format: machine status <hostname>"
        with _db(context) as conn:
            m = conn.execute(
                "SELECT * FROM machines WHERE hostname=?", (hostname,)
            ).fetchone()
            if not m:
                return f"Machine '{hostname}' introuvable."
            # Logs filtrés en attente
            pending_logs = conn.execute(
                "SELECT COUNT(*) as cnt FROM filtered_logs WHERE machine_id=? AND analyzed=0",
                (m['id'],)
            ).fetchone()['cnt']
            # Sessions récentes
            sessions = conn.execute(
                "SELECT slot_date, status, started_at, completed_at, last_log_id "
                "FROM analysis_sessions WHERE machine_id=? ORDER BY slot_date DESC LIMIT 5",
                (m['id'],)
            ).fetchall()

        active  = "actif" if m['active'] else "inactif"
        lines   = [
            f"── Statut de {hostname} ──────────────────────",
            f"  Statut      : {active}",
            f"  Position    : {m['queue_position']}",
            f"  Enregistrée : {m['registered_at'][:16]}",
            f"  Dernier log : {m['last_log_at'][:16] if m['last_log_at'] else 'jamais'}",
            f"  Dernière ana: {m['last_analyzed_at'][:16] if m['last_analyzed_at'] else 'jamais'}",
            f"  Logs en att.: {pending_logs}",
        ]
        if sessions:
            lines.append("  Sessions récentes:")
            for s in sessions:
                lines.append(
                    f"    {s['slot_date']} : {s['status']} "
                    f"(offset log #{s['last_log_id']})"
                )
        return "\n".join(lines)

    # ── reorder ───────────────────────────────────────────────────────────────
    if action == 'reorder':
        p = rest.split(None, 1)
        if len(p) < 2:
            return "Format: machine reorder <hostname> <nouvelle_position>"
        hostname = p[0].strip()
        try:
            new_pos = int(p[1].strip())
        except ValueError:
            return "La position doit être un entier."
        with _db(context) as conn:
            cur = conn.execute(
                "UPDATE machines SET queue_position=? WHERE hostname=?",
                (new_pos, hostname)
            )
            if cur.rowcount == 0:
                return f"Machine '{hostname}' introuvable."
        return f"✅ {hostname} déplacée en position {new_pos}."

    # ── activate / deactivate ─────────────────────────────────────────────────
    if action in ('activate', 'deactivate'):
        hostname = rest.strip()
        if not hostname:
            return f"Format: machine {action} <hostname>"
        val = 1 if action == 'activate' else 0
        with _db(context) as conn:
            cur = conn.execute(
                "UPDATE machines SET active=? WHERE hostname=?", (val, hostname)
            )
            if cur.rowcount == 0:
                return f"Machine '{hostname}' introuvable."
        verb = "activée" if val else "désactivée"
        return f"✅ Machine '{hostname}' {verb}."

    return (
        "Action inconnue. Disponible : list, queue, add, remove, status, "
        "reorder, activate, deactivate"
    )
