"""
Skill MQTT_SEND — publier un message sur n'importe quel topic MQTT.
Permet à l'agent de communiquer proactivement avec d'autres agents.

Usage LLM : SKILL:mqtt_send ARGS:<topic> | <message>
"""
DESCRIPTION = "Publier un message sur un topic MQTT (communication inter-agents)"
USAGE = "SKILL:mqtt_send ARGS:<topic> | <message>"


def run(args: str, context) -> str:
    if "|" not in args:
        return "Format : SKILL:mqtt_send ARGS:<topic> | <message>"

    topic, message = args.split("|", 1)
    topic   = topic.strip()
    message = message.strip()

    if not topic:
        return "Topic vide."

    context.mqtt.publish_raw(topic, message)
    return f"Message publié sur '{topic}'."
