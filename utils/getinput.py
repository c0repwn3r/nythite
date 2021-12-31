from pynput import keyboard


def yninput(default=True):
    with keyboard.Events() as events:
        event = events.get(1e6)
        if event.key == keyboard.KeyCode.from_char('y'):
            return True
        elif event.key == keyboard.KeyCode.from_char('n'):
            return False
        else:
            return default
