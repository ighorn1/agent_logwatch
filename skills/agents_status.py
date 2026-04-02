"""
Skill AGENTS_STATUS — afficher le statut en temps réel de tous les agents.

Usage LLM : SKILL:agents_status ARGS:
"""
DESCRIPTION = "Afficher le statut en temps réel de tous les agents (online/offline)"
USAGE = "SKILL:agents_status ARGS:(aucun argument)"


def run(args: str, context) -> str:
    with context.agent._online_lock:
        online = set(context.agent._online_agents)

    all_caps = context.registry.all_agents()

    if not all_caps:
        return "Aucun agent connu dans le registre."

    lines = ["── Statut des agents ──────────────────"]
    for caps in sorted(all_caps, key=lambda c: c.agent_id):
        if caps.agent_id == context.agent_id:
            continue  # Ne pas s'afficher soi-même
        icon = "🟢" if caps.agent_id in online else "🔴"
        label = "en ligne" if caps.agent_id in online else "hors ligne"
        lines.append(f"  {icon} {caps.agent_id} [{caps.agent_type}] — {label}")
        lines.append(f"     {caps.description}")

    return "\n".join(lines) if len(lines) > 1 else "Aucun autre agent connu."
