"""Helper for driving dfcollect interactive TUI inside tmux in NixOS VM tests."""
import time


class TuiDriver:
    def __init__(self, machine, session="tui", width=80, height=24):
        self.machine = machine
        self.session = session
        self.width = width
        self.height = height

    def start(self, cmd="dfcollect", env=None):
        prefix = ""
        if env:
            prefix = " ".join(f"{k}='{v}'" for k, v in env.items()) + " "
        self.machine.succeed(
            f"tmux new-session -d -s {self.session} -x {self.width} -y {self.height} '{prefix}{cmd}'"
        )
        self.machine.succeed(f"tmux set-option -t {self.session} history-limit 10000")

    def send_keys(self, *keys):
        for k in keys:
            self.machine.succeed(f"tmux send-keys -t {self.session} {k}")

    def type_string(self, text):
        escaped = text.replace("'", "'\\''")
        self.machine.succeed(f"tmux send-keys -t {self.session} -l '{escaped}'")

    def capture(self, full_history=False):
        flag = "-S -" if full_history else ""
        return self.machine.succeed(f"tmux capture-pane -p {flag} -t {self.session}")

    def wait_for_text(self, needle, timeout=30, interval=0.25):
        start = time.time()
        last_screen = ""
        while time.time() - start < timeout:
            last_screen = self.capture()
            if needle in last_screen:
                return last_screen
            time.sleep(interval)
        raise TimeoutError(
            f"Timed out waiting for {needle!r} in tmux session {self.session!r} after {timeout}s.\n"
            f"Last screen capture:\n{last_screen}"
        )

    def wait_for_exit(self, timeout=30, interval=0.25):
        start = time.time()
        while time.time() - start < timeout:
            code, _ = self.machine.execute(f"tmux has-session -t {self.session} 2>/dev/null")
            if code != 0:
                return
            time.sleep(interval)
        last_screen = self.capture()
        raise TimeoutError(
            f"Timed out waiting for tmux session {self.session!r} to exit after {timeout}s.\n"
            f"Last screen capture:\n{last_screen}"
        )

    def focus_field(self, label, max_steps=40):
        target = f"▸ {label}"
        for _ in range(max_steps):
            screen = self.capture()
            if any(target in line for line in screen.splitlines()):
                return
            self.send_keys("Down")
            time.sleep(0.05)
        last_screen = self.capture()
        raise TimeoutError(
            f"Could not focus field {label!r} in tmux session {self.session!r}.\n"
            f"Last screen capture:\n{last_screen}"
        )

    def type_field(self, text):
        self.send_keys("C-u")
        self.type_string(text)
        self.send_keys("Enter")
        time.sleep(0.05)

    def fill_field(self, label, text):
        self.focus_field(label)
        self.type_field(text)

    def cycle_field(self, label, target_value, max_steps=10):
        self.focus_field(label)
        target = f"▸ {label}"
        for _ in range(max_steps):
            screen = self.capture()
            for line in screen.splitlines():
                if target in line and target_value.lower() in line.lower():
                    return
            self.send_keys("Space")
            time.sleep(0.05)
        last_screen = self.capture()
        raise TimeoutError(
            f"Could not cycle field {label!r} to {target_value!r}.\n"
            f"Last screen capture:\n{last_screen}"
        )

    def kill(self):
        self.machine.execute(f"tmux kill-session -t {self.session} 2>/dev/null")
