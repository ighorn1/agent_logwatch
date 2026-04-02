"""
Skill MQTT_SUBSCRIBE — s'abonner dynamiquement à un topic MQTT.

Les messages reçus sont transmis via XMPP (admin) et loggés.

Usage LLM :
  SKILL:mqtt_subscribe ARGS:subscribe | <topic>
  SKILL:mqtt_subscribe ARGS:unsubscribe | <topic>
  SKILL:mqtt_subscribe ARGS:list
"""
import logging

DESCRIPTION = "S'abonner / se désabonner dynamiquement d'un topic MQTT et recevoir les messages"
USAGE = "SKILL:mqtt_subscribe ARGS:subscribe|<topic>  ou  unsubscribe|<topic>  ou  list"

logger = logging.getLogger(__name__)

# Stockage des souscriptions dynamiques : {topic: callback}
_dynamic_subs: dict = {}


def run(args: str, context) -> str:
    parts = [p.strip() for p in args.split("|", 1)]
    action = parts[0].lower()

    if action == "list":
        if not _dynamic_subs:
            return "Aucun topic MQTT surveillé."
        return "Topics surveillés :\n" + "\n".join(f"  • {t}" for t in _dynamic_subs)

    if len(parts) < 2 or not parts[1]:
        return "Format : subscribe|<topic>  ou  unsubscribe|<topic>  ou  list"

    topic = parts[1]

    if action == "unsubscribe":
        if topic in _dynamic_subs:
            del _dynamic_subs[topic]
            return f"Désabonné du topic '{topic}'."
        return f"Pas abonné à '{topic}'."

    if action == "subscribe":
        if topic in _dynamic_subs:
            return f"Déjà abonné à '{topic}'."

        agent_id = context.agent_id

        def _on_message(msg, t):
            payload = msg.payload if hasattr(msg, "payload") else str(msg)
            text = f"[MQTT:{t}] {payload}"
            logger.info(f"[mqtt_subscribe] {text}")
            if context.xmpp:
                context.xmpp.send_to_all_admins(text)

        _dynamic_subs[topic] = _on_message
        context.mqtt.subscribe(topic, _on_message)
        return f"Abonné au topic '{topic}'. Les messages seront transmis via XMPP."

    return f"Action inconnue '{action}'. Utilise : subscribe, unsubscribe, list."
