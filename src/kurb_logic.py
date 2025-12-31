import json
import time
from datetime import datetime


class KurbSimulator:
    """
    Logic-only simulator for Kurb schedule, unlock rules, and battery behavior.
    This does NOT do BLE – it's just to test rules and state transitions.
    """

    def __init__(self):
        # 1 = locked, 0 = unlocked
        self.lock_state = 1
        self.fail_open = False
        self.battery = 100

        # schedule-related
        self.schedule = None  # full JSON dict
        self.remaining_unlocks = None  # for daily_limit
        self.used_window_today = False  # for time_window

    # ---------- Helpers for printing state ----------

    def print_state(self):
        print("---- CURRENT STATE ----")
        print(f"Lock state    : {'LOCKED' if self.lock_state else 'UNLOCKED'}")
        print(f"Fail-open     : {self.fail_open}")
        print(f"Battery       : {self.battery}%")
        print(f"Schedule mode : {self.schedule.get('mode') if self.schedule else 'NONE'}")
        print(f"Remaining unlocks (daily_limit): {self.remaining_unlocks}")
        print(f"Window used today (time_window): {self.used_window_today}")
        print("------------------------\n")

    # ---------- Schedule setup ----------

    def set_daily_limit_schedule(self, max_unlocks=3, reset_time_local="00:00"):
        self.schedule = {
            "mode": "daily_limit",
            "tz_offset_minutes": 0,
            "daily_limit": {
                "max_unlocks": max_unlocks,
                "reset_time_local": reset_time_local
            }
        }
        self.remaining_unlocks = max_unlocks
        print(f"[SCHEDULE] Set daily_limit with {max_unlocks} unlocks per day.\n")

    def set_time_window_schedule(self, windows):
        self.schedule = {
            "mode": "time_window",
            "tz_offset_minutes": 0,
            "windows": windows
        }
        self.used_window_today = False
        print(f"[SCHEDULE] Set time_window from {start_ts} to {end_ts}.\n")

    # ---------- Battery behavior ----------

    def set_battery(self, percent):
        self.battery = percent
        print(f"[BATTERY] Set battery to {percent}%")

        if percent <= 3:
            # Enter fail-open
            if not self.fail_open:
                self.fail_open = True
                self.lock_state = 0
                print("[EVENT] BatteryCritical -> EmergencyUnlock fired.")
                print("[STATE] Device is now UNLOCKED and in FAIL-OPEN mode.\n")
        elif percent <= 10:
            print("[EVENT] BatteryCritical (no emergency unlock yet).\n")
        elif percent <= 20:
            print("[EVENT] BatteryLow.\n")
        else:
            print("[BATTERY] Normal range.\n")

    # ---------- Unlock logic ----------

    def attempt_unlock(self):
        print("[COMMAND] Unlock requested.")

        if self.fail_open:
            print("[EVENT] EmergencyUnlock (fail-open mode already). Device stays UNLOCKED.\n")
            self.lock_state = 0
            return

        if not self.schedule:
            print("[ERROR] No schedule set. Unlock denied.\n")
            return

        mode = self.schedule["mode"]

        if mode == "daily_limit":
            self._unlock_daily_limit()
        elif mode == "time_window":
            self._unlock_time_window()
        else:
            print(f"[ERROR] Unknown schedule mode: {mode}\n")

    def _unlock_daily_limit(self):
        if self.remaining_unlocks is None:
            self.remaining_unlocks = self.schedule["daily_limit"]["max_unlocks"]

        if self.remaining_unlocks > 0:
            self.remaining_unlocks -= 1
            self.lock_state = 0
            print(f"[EVENT] Unlocked. Remaining unlocks today: {self.remaining_unlocks}\n")
        else:
            print("[EVENT] GenericError: No remaining unlocks for today.\n")

    def _unlock_time_window(self):
        windows = self.schedule.get("windows", [])
        now_ts = int(time.time())
        print(f"[DEBUG] Now ts: {now_ts}")

        allowed = False
        for w in windows:
            if w["start"] <= now_ts <= w["end"]:
                if not self.used_window_today:
                    allowed = True
                    break

        if allowed:
            self.used_window_today = True
            self.lock_state = 0
            print("[EVENT] Unlocked within time window. Window now marked as used.\n")
        else:
            print("[EVENT] GenericError: Not in valid window or already used.\n")

    # ---------- Lock logic ----------

    def close_device(self):
        """
        Simulate closing lid / inserting vape.
        """
        if self.fail_open:
            print("[STATE] Fail-open mode: closing device does NOT lock. Stays UNLOCKED.\n")
            self.lock_state = 0
            return

        self.lock_state = 1
        print("[EVENT] Locked (physical closure).\n")


def main():
    sim = KurbSimulator()
    print("Kurb Logic Simulator")
    print("This does NOT use BLE; it's just logic testing.\n")

    while True:
        print("Select an option:")
        print("1) Show state")
        print("2) Set DAILY LIMIT schedule")
        print("3) Set TIME WINDOW schedule (next 60 seconds)")
        print("4) Attempt UNLOCK")
        print("5) Close device (lock)")
        print("6) Set battery level")
        print("0) Exit")
        choice = input("> ").strip()

        if choice == "0":
            break

        if choice == "1":
            sim.print_state()

        elif choice == "2":
            max_u = input("Max unlocks per day (default 3): ").strip()
            max_u = int(max_u) if max_u else 3
            sim.set_daily_limit_schedule(max_unlocks=max_u)

        elif choice == "3":
            now = int(time.time())
            start = now
            end = now + 60
            sim.set_time_window_schedule(start, end)
            print(f"Time window set from now ({start}) to +60s ({end}).\n")

        elif choice == "4":
            sim.attempt_unlock()

        elif choice == "5":
            sim.close_device()

        elif choice == "6":
            lvl = input("Battery %: ").strip()
            try:
                lvl = int(lvl)
                sim.set_battery(lvl)
            except ValueError:
                print("Invalid number.\n")

        else:
            print("Invalid choice.\n")


if __name__ == "__main__":
    main()
