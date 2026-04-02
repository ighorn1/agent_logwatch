"""
Skill MUC_SEND — envoyer un message dans le groupe XMPP des agents.

Le groupe est agents@muc.xmpp.ovh (configuré dans config.json).

Usage LLM : SKILL:muc_send ARGS:<message>
"""
DESCRIPTION = "Envoyer un message dans le groupe XMPP des agents (MUC)"
USAGE = "SKILL:muc_send ARGS:<message à envoyer dans le groupe>"


def run(args: str, context) -> str:
    message = args.strip()
    if not message:
        return "Message vide."

    if not context.xmpp:
        return "XMPP non configuré sur cet agent."

    if not context.xmpp.muc_room:
        return "Aucun groupe MUC configuré."

    context.xmpp.send_to_group(message)
    return f"Message envoyé dans le groupe {context.xmpp.muc_room}."
