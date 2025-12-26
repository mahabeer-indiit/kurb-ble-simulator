import asyncio
import logging
import uuid
import sys
import os
import threading
import json
import time
from datetime import datetime, timedelta
from typing import Optional

# Ensure we can import ble_constants
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

try:
    import ble_constants
except ImportError:
    # Fallback if running from root
    from src import ble_constants

from winsdk.windows.devices.bluetooth.genericattributeprofile import (
    GattServiceProvider,
    GattServiceProviderAdvertisingParameters,
    GattLocalCharacteristicParameters,
    GattCharacteristicProperties,
    GattProtectionLevel,
    GattWriteOption
)
from winsdk.windows.storage.streams import DataWriter, DataReader
from kurb_logic import KurbSimulator
from battery_engine import classify_battery

# -------------------------------------------------
# Config
# -------------------------------------------------

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger("ble-simulator")

# -------------------------------------------------
# BLE Pairing Advertiser (Class)
# -------------------------------------------------
class WindowsBLEPairingAdvertiser:
    def __init__(self):
        self.provider: Optional[GattServiceProvider] = None
        self._running = False
        self.chars = {} # UUID -> Characteristic object
        self.sim = KurbSimulator()  # Source of truth for device state
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._console_thread: Optional[threading.Thread] = None
        self._stop_console = False
        self._last_lock_state= self.sim.lock_state
        self._last_battery=self.sim.battery
        self._open_too_long_task: Optional[asyncio.Task] = None
        self._subscribed_clients = set()
        self._last_schedule_state = None
        # Schedule stream state for reassembling chunks
        self._schedule_expected_len: Optional[int] = None
        self._schedule_buf: bytes = b""

    def _calculate_next_unlock_time(self) -> int:
        """
        Calculate the next unlock time based on the current schedule.
        
        Returns:
            int: 4-byte UNIX timestamp (UTC seconds), or 0 if no upcoming unlock window
        """
        if not self.sim.schedule:
            return 0
        
        mode = self.sim.schedule.get("mode")
        now_ts = int(time.time())
        
        if mode == "daily_limit":
            if self.sim.remaining_unlocks is None or self.sim.remaining_unlocks <= 0:
                # No remaining unlocks
                return int(0)
            else:
                # Remaining unlocks available -
                return int(self.sim.remaining_unlocks)
        
        elif mode == "time_window":
            # For time_window mode: return window start if window is available and not used
            windows = self.sim.schedule.get("windows", [])
            if not windows:
                return 0
            
            upcoming_window =None;
            for w in windows:
                if  now_ts <= w["start"]:
                    upcoming_window = w
                    break
            
            if upcoming_window:
                return int(upcoming_window["start"])
            else:
                return 0
        # Unknown mode
        return 0
        
    async def start(self):
        log.info("Starting Windows BLE Simulator")

        # Create GATT service
        service_uuid = uuid.UUID(ble_constants.SERVICE_UUID)
        result = await GattServiceProvider.create_async(service_uuid)
        self.provider = result.service_provider

        if not self.provider:
            raise RuntimeError("Failed to create GATT service provider")

        # Cache running loop for cross-thread callback scheduling
        self._loop = asyncio.get_running_loop()

        # Helper to create characteristic
        async def create_char(uuid_str, properties, protection=GattProtectionLevel.PLAIN):
            params = GattLocalCharacteristicParameters()
            params.characteristic_properties = properties
            params.read_protection_level = protection
            params.write_protection_level = protection
            
            char_result = await self.provider.service.create_characteristic_async(
                uuid.UUID(uuid_str),
                params
            )
            return char_result.characteristic

        # 2. Event Characteristic (Notify)
        self.chars[ble_constants.CHAR_EVENT] = await create_char(
            ble_constants.CHAR_EVENT,
            GattCharacteristicProperties.NOTIFY
        )
        self.chars[ble_constants.CHAR_EVENT].add_subscribed_clients_changed(self._on_subscribed_clients_changed)
        log.info(f"Created Event Char: {ble_constants.CHAR_EVENT}")

        # 3. Lock State (Read | Notify)
        self.chars[ble_constants.CHAR_LOCK_STATE] = await create_char(
            ble_constants.CHAR_LOCK_STATE,
            GattCharacteristicProperties.READ | GattCharacteristicProperties.NOTIFY
        )
        self.chars[ble_constants.CHAR_LOCK_STATE].add_read_requested(self._on_read_generic)
        log.info(f"Created Lock State Char: {ble_constants.CHAR_LOCK_STATE}")

        # 4. Lock Command (Write)
        self.chars[ble_constants.CHAR_LOCK_COMMAND] = await create_char(
            ble_constants.CHAR_LOCK_COMMAND,
            GattCharacteristicProperties.WRITE
        )
        self.chars[ble_constants.CHAR_LOCK_COMMAND].add_write_requested(self._on_write_generic)
        log.info(f"Created Lock Command Char: {ble_constants.CHAR_LOCK_COMMAND}")

        # 5. Battery (Read | Notify)
        self.chars[ble_constants.CHAR_BATTERY] = await create_char(
            ble_constants.CHAR_BATTERY,
            GattCharacteristicProperties.READ | GattCharacteristicProperties.NOTIFY
        )
        self.chars[ble_constants.CHAR_BATTERY].add_read_requested(self._on_read_generic)
        log.info(f"Created Battery Char: {ble_constants.CHAR_BATTERY}")

        # 6. Schedule (Read | Write)
        self.chars[ble_constants.CHAR_SCHEDULE] = await create_char(
            ble_constants.CHAR_SCHEDULE,
            GattCharacteristicProperties.READ | GattCharacteristicProperties.WRITE
        )
        self.chars[ble_constants.CHAR_SCHEDULE].add_read_requested(self._on_read_generic)
        self.chars[ble_constants.CHAR_SCHEDULE].add_write_requested(self._on_write_generic)
        log.info(f"Created Schedule Char: {ble_constants.CHAR_SCHEDULE}")

        # 7. TimeSync (Read | Write)
        self.chars[ble_constants.CHAR_TIMESYNC] = await create_char(
            ble_constants.CHAR_TIMESYNC,
            GattCharacteristicProperties.READ | GattCharacteristicProperties.WRITE
        )
        self.chars[ble_constants.CHAR_TIMESYNC].add_read_requested(self._on_read_generic)
        self.chars[ble_constants.CHAR_TIMESYNC].add_write_requested(self._on_write_generic)
        log.info(f"Created TimeSync Char: {ble_constants.CHAR_TIMESYNC}")

        # 8. Next Unlock (Read)
        self.chars[ble_constants.CHAR_NEXT_UNLOCK] = await create_char(
            ble_constants.CHAR_NEXT_UNLOCK,
             GattCharacteristicProperties.READ | GattCharacteristicProperties.NOTIFY
        )
        self.chars[ble_constants.CHAR_NEXT_UNLOCK].add_read_requested(self._on_read_generic)
        log.info(f"Created Next Unlock Char: {ble_constants.CHAR_NEXT_UNLOCK}")

        # 9. Device ID (Read)
        self.chars[ble_constants.CHAR_DEVICE_ID] = await create_char(
            ble_constants.CHAR_DEVICE_ID,
            GattCharacteristicProperties.READ
        )
        self.chars[ble_constants.CHAR_DEVICE_ID].add_read_requested(self._on_read_generic)
        log.info(f"Created Device ID Char: {ble_constants.CHAR_DEVICE_ID}")

        # 10. Protocol Version (Read)
        self.chars[ble_constants.CHAR_PROTOCOL_VERSION] = await create_char(
            ble_constants.CHAR_PROTOCOL_VERSION,
            GattCharacteristicProperties.READ
        )
        self.chars[ble_constants.CHAR_PROTOCOL_VERSION].add_read_requested(self._on_read_generic)
        log.info(f"Created Protocol Version Char: {ble_constants.CHAR_PROTOCOL_VERSION}")


        # 12. Protocol (Read) - Assuming this is different from Version? Or maybe Type?
        self.chars[ble_constants.CHAR_PROTOCOL] = await create_char(
            ble_constants.CHAR_PROTOCOL,
            GattCharacteristicProperties.READ
        )
        self.chars[ble_constants.CHAR_PROTOCOL].add_read_requested(self._on_read_generic)
        log.info(f"Created Protocol Char: {ble_constants.CHAR_PROTOCOL}")

        # 13. Firmware Version (Read)
        self.chars[ble_constants.CHAR_FIRMWARE] = await create_char(
            ble_constants.CHAR_FIRMWARE,
            GattCharacteristicProperties.READ
        )
        self.chars[ble_constants.CHAR_FIRMWARE].add_read_requested(self._on_read_generic)
        log.info(f"Created Firmware Char: {ble_constants.CHAR_FIRMWARE}")

        # Start advertising
        adv = GattServiceProviderAdvertisingParameters()
        adv.is_connectable = True
        adv.is_discoverable = True

        self.provider.start_advertising(adv)
        self._running = True

        log.info("Advertising started")
        log.info("• Connectable & Discoverable")
        self._start_console()

    def is_connected(self) -> bool:
        return len(self._subscribed_clients) > 0

    def _on_subscribed_clients_changed(self, sender, args):
        log.info(f"Subscribed Clients Changed. Count: {len(sender.subscribed_clients)}")
        self._subscribed_clients = {
            client.session.device_id for client in sender.subscribed_clients
        }

        for client in sender.subscribed_clients:
             log.info(f"Client Session: {client.session.device_id}")

    def _on_read_generic(self, sender, args):
        deferral = args.get_deferral()
        if self._loop and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(
                self._handle_read_generic(sender, args, deferral),
                self._loop
            )
        else:
            try:
                self._handle_read_generic(sender, args, deferral)
            except Exception as e:
                log.error(f"_on_read_generic fallback error: {e}")

    async def _handle_read_generic(self, sender, args, deferral):
        try:
            log.info(f"Read Request: {sender.uuid}")
            writer = DataWriter()
            
            if sender.uuid == uuid.UUID(ble_constants.CHAR_LOCK_STATE):
                writer.write_byte(self.sim.lock_state)
            elif sender.uuid == uuid.UUID(ble_constants.CHAR_BATTERY):
                writer.write_byte(int(self.sim.battery))
            elif sender.uuid == uuid.UUID(ble_constants.CHAR_DEVICE_ID):
                writer.write_string("KURB-VK-2501-0001")
            elif sender.uuid == uuid.UUID(ble_constants.CHAR_PROTOCOL_VERSION):
                writer.write_byte(1)
            elif sender.uuid == uuid.UUID(ble_constants.CHAR_FIRMWARE):
                writer.write_string("FIRMWARE-1.0.0")
            elif sender.uuid == uuid.UUID(ble_constants.CHAR_PROTOCOL):
                writer.write_string("PROTO-1.0.0")
            elif sender.uuid == uuid.UUID(ble_constants.CHAR_NEXT_UNLOCK):
                next_unlock_ts = self._calculate_next_unlock_time()
                writer.write_uint32(next_unlock_ts)
            elif sender.uuid == uuid.UUID(ble_constants.CHAR_SCHEDULE):
                try:
                    schedule_json = json.dumps(self.sim.schedule) if self.sim.schedule else "{}"
                    writer.write_string(schedule_json)
                except Exception:
                    writer.write_string("{}")
            elif sender.uuid == uuid.UUID(ble_constants.CHAR_TIMESYNC):
                writer.write_uint32(0)
            else:
                writer.write_byte(0x00) # Default

            request = await args.get_request_async()
            request.respond_with_value(writer.detach_buffer())
        except Exception as e:
            log.error(f"Error reading {sender.uuid}: {e}")
        finally:
            deferral.complete()

    def _on_write_generic(self, sender, args):
        deferral = args.get_deferral()
        asyncio.run_coroutine_threadsafe(
            self._handle_write_generic(sender, args, deferral),
            self._loop
        )

    async def _handle_write_generic(self, sender, args, deferral):
        try:
            req = await args.get_request_async()
            reader = DataReader.from_buffer(req.value)
            buffer_length = reader.unconsumed_buffer_length
            if buffer_length > 0:
                # Read bytes from DataReader
                # Windows WinRT DataReader.read_bytes() may return IBuffer, not bytes
                # So we read byte-by-byte which is guaranteed to work
                data = bytearray(buffer_length)
                for i in range(buffer_length):
                    data[i] = reader.read_byte()
                data = bytes(data)
            else:
                data = b''

            u = sender.uuid
            u_str = str(u).lower()

            log.info(f"[BLE Write] {u_str}: {data.hex()}")

            # -------- LOCK COMMAND --------
            if u == uuid.UUID(ble_constants.CHAR_LOCK_COMMAND):
                asyncio.run_coroutine_threadsafe(
                    self._handle_unlock_command(data), self._loop
                )

            # -------- SCHEDULE (streamed) --------
            elif u == uuid.UUID(ble_constants.CHAR_SCHEDULE):
                asyncio.run_coroutine_threadsafe(
                    self._handle_schedule_stream(data), self._loop
                )

            # -------- TIMESYNC --------
            elif u == uuid.UUID(ble_constants.CHAR_TIMESYNC):
                asyncio.run_coroutine_threadsafe(
                    self._handle_timesync(data), self._loop
                )

            if req.option == GattWriteOption.WRITE_WITH_RESPONSE:
                req.respond()

        except Exception as e:
            log.error(f"Write error: {e}")
            await self._notify(
                ble_constants.CHAR_EVENT,
                ble_constants.EV_GENERIC_ERROR
            )
        finally:
            deferral.complete()

    # -----------------------------------------------------------------
    # Logic handlers
    # -----------------------------------------------------------------

    async def _handle_unlock_command(self, data: bytes):
        """Handle lock command write."""
        log.info("[WRAPPER] Processing Unlock Command")

        if(self.sim.remaining_unlocks<=0):
            await self._notify(
                ble_constants.CHAR_EVENT,
                ble_constants.EV_GENERIC_ERROR
            )
        elif self.sim.lock_state==0:
            await self._notify(
                ble_constants.CHAR_EVENT,
                ble_constants.EV_GENERIC_ERROR
            )
        else :    
            self.sim.attempt_unlock()

    async def _handle_schedule_stream(self, chunk: bytes):
        """
        Reassembles streamed schedule writes.

        Protocol:
        - First 2 bytes (little-endian) = payload length
        - Remaining bytes = payload (opaque to this function)
        """
        # ---------- First chunk: read length ----------
        if self._schedule_expected_len is None:
            if len(chunk) < 2:
                log.warning("[ScheduleStream] Chunk < 2 bytes, waiting for length")
                return

            self._schedule_expected_len = int.from_bytes(chunk[:2], "little")
            self._schedule_buf = b""

            # Append any payload bytes present in this chunk
            remainder = chunk[2:]
            if remainder:
                self._schedule_buf += remainder

            log.info(
                f"[ScheduleStream] Started, expecting "
                f"{self._schedule_expected_len} bytes"
            )

        # ---------- Continuation chunks ----------
        else:
            self._schedule_buf += chunk

        log.debug(
            f"[ScheduleStream] Progress: "
            f"{len(self._schedule_buf)}/{self._schedule_expected_len}"
        )

        # ---------- Completion ----------
        if (
            self._schedule_expected_len is not None
            and len(self._schedule_buf) >= self._schedule_expected_len
        ):
            payload = self._schedule_buf[: self._schedule_expected_len]

            # Reset stream state FIRST
            self._schedule_buf = b""
            self._schedule_expected_len = None

            log.info("[ScheduleStream] Payload fully received")

            # Hand off raw payload for further processing
            await self._handle_schedule(payload)

    async def _handle_schedule(self, payload: bytes):
        """
        Handles a fully reassembled schedule payload.

        payload = raw JSON bytes (NO length header)
        """
        log.info("[Logic] Processing Schedule update")

        try:
            json_str = payload.decode("utf-8")
            schedule = json.loads(json_str)

            mode = schedule.get("mode")

            if mode == "daily_limit":
                dl = schedule.get("daily_limit", {})
                self.sim.set_daily_limit_schedule(
                    max_unlocks=dl.get("max_unlocks", 3),
                    reset_time_local=dl.get("reset_time_local", "00:00"),
                )

            elif mode == "time_window":
                windows = schedule.get("windows", [])
                if windows:
                    w = windows[0]
                    self.sim.set_time_window_schedule(
                        w.get("start", 0),
                        w.get("end", 0),
                    )

            else:
                log.warning(f"[Logic] Unknown schedule mode: {mode}")

        except json.JSONDecodeError as e:
            log.error(f"[Logic] Invalid JSON schedule: {e}")
            await self._notify(
                ble_constants.CHAR_EVENT,
                ble_constants.EV_GENERIC_ERROR
            )

        except Exception as e:
            log.error(f"[Logic] Schedule handling failed: {e}")
            await self._notify(
                ble_constants.CHAR_EVENT,
                ble_constants.EV_GENERIC_ERROR
            )

    async def _handle_timesync(self, data: bytes):
        """Handle timesync write."""
        if len(data) >= 4:
            # Read uint32 timestamp (little-endian)
            timestamp = int.from_bytes(data[:4], "little")
            log.info(f"[Logic] TimeSync received: {timestamp}")
            # In a real device, this would sync the device clock
            # For simulator, we just acknowledge it
        else:
            log.warning(f"[Logic] TimeSync payload too short: {len(data)} bytes")

    async def stop(self):
        if self.provider:
            self.provider.stop_advertising()
            log.info("Advertising stopped")
        self._running = False
        self._stop_console = True

    async def run_forever(self):
        try:
            while self._running:
                await asyncio.sleep(1)

                if(self.sim.lock_state != self._last_lock_state):
                    self._last_lock_state = self.sim.lock_state
                    if not self.is_connected():
                        log.info("No connected clients. Skipping lock state update.")
                        continue    
                    await self._notify(ble_constants.CHAR_LOCK_STATE,bytes([self.sim.lock_state]))
                    if self.sim.lock_state == 0:
                        self._schedule_open_too_long()
                    else:
                        self._cancel_open_too_long()
                if(self.sim.battery != self._last_battery):
                    self._last_battery = self.sim.battery
                    if not self.is_connected():
                        log.info("No connected clients. Skipping battery update.")
                        continue 
                    await self._notify(ble_constants.CHAR_BATTERY,bytes([self.sim.battery]))
                    batteryState = classify_battery(self.sim.battery)
                    if batteryState != "normal":
                        match batteryState:
                            case "low":
                                if not self.is_connected():
                                    log.info("No connected clients. Skipping battery low update.")
                                    continue 
                                await self._notify(ble_constants.CHAR_BATTERY,ble_constants.EV_BATTERY_LOW)
                            case "critical":
                                if not self.is_connected():
                                    log.info("No connected clients. Skipping battery critical update.")
                                    continue 
                                await self._notify(ble_constants.CHAR_BATTERY,ble_constants.EV_BATTERY_CRITICAL)
                            case "emergency":
                                if not self.is_connected():
                                    log.info("No connected clients. Skipping emergency unlock update.")
                                    continue 
                                await self._notify(ble_constants.CHAR_BATTERY,ble_constants.EV_EMERGENCY_UNLOCK)
                if(self.sim.schedule != self._last_schedule_state):
                    self._last_schedule_state = self.sim.schedule
                    if not self.is_connected():
                        log.info("No connected clients. Skipping schedule state update.")
                        continue 
                    await self._notify(ble_constants.CHAR_EVENT,ble_constants.EV_SCHEDULE_UPDATED)

        except asyncio.CancelledError:
            pass

    def _start_console(self):
        if self._console_thread and self._console_thread.is_alive():
            return
        self._console_thread = threading.Thread(target=self._console_loop, daemon=True)
        self._console_thread.start()

    def _console_loop(self):
        def show_menu():
            print("")
            print("[menu] l=lock, u=unlock, b <0-100>=battery, e<1-9>=event, q=exit")
            print("> ", end="", flush=True)
        show_menu()
        while not self._stop_console:
            try:
                line = sys.stdin.readline()
                if not line:
                    break
                cmd = line.strip().lower()
                if cmd in ("q", "quit", "exit", "eit"):
                    if self._loop and self._loop.is_running():
                        asyncio.run_coroutine_threadsafe(self.stop(), self._loop)
                    self._stop_console = True
                    break
                if self._loop and self._loop.is_running():
                    asyncio.run_coroutine_threadsafe(self._handle_menu_command(cmd), self._loop)
                show_menu()
            except Exception as e:
                print(f"[menu] error: {e}")
                show_menu()

    async def _notify(self, uuid_str, value_byte):
        log.info(f"Notify {uuid_str} with {value_byte}")
        try:
            if uuid_str not in self.chars:
                return
            writer = DataWriter()
            if isinstance(value_byte, (bytes, bytearray)):
                if len(value_byte) >= 1:
                    writer.write_byte(value_byte[0])
            elif isinstance(value_byte, int):
                writer.write_byte(value_byte)
            else:
                return
            await self.chars[uuid_str].notify_value_async(writer.detach_buffer())
        except Exception as e:
            log.warning(f"Notify failed for {uuid_str}: {e}")

    async def _handle_menu_command(self, cmd):
        tokens = cmd.split()
        if not tokens:
            return
        if tokens[0] == "l":
            log.info("MENU: lock")
            self.sim.lock_state=1
            self._cancel_open_too_long()
            return
        if tokens[0] == "u":
            log.info("MENU: unlock")
            self.sim.lock_state=0
            self._schedule_open_too_long()
            return
        if tokens[0] == "b":
                if len(tokens) < 2:
                    return
                val = int(tokens[1])
                val = max(0, min(100, val))
                self.sim.set_battery(val)
                log.info(f"MENU: battery={val}")
                return
        if cmd.startswith("e"):
            try:
                num = int(cmd[1:])

                mapping = {
                    1: ble_constants.EV_LOCKED,
                    2: ble_constants.EV_UNLOCKED,
                    4: ble_constants.EV_OPEN_TOO_LONG,
                    5: ble_constants.EV_BATTERY_LOW,
                    6: ble_constants.EV_BATTERY_CRITICAL,
                    7: ble_constants.EV_SCHEDULE_UPDATED,
                    8: ble_constants.EV_GENERIC_ERROR,
                    9: ble_constants.EV_EMERGENCY_UNLOCK,
                }
                ev = mapping.get(num)
                if ev:
                    log.info(f"MENU: event e{num}")
                    await self._notify(ble_constants.CHAR_EVENT, ev)
                else:
                    log.error("MENU: invalid event number")
            except Exception:
                log.error("MENU: invalid event number")
            return

    def _schedule_open_too_long(self):
        self._cancel_open_too_long()
        try:
            self._open_too_long_task = asyncio.create_task(self._open_too_long_countdown())
        except Exception:
            self._open_too_long_task = None

    def _cancel_open_too_long(self):
        if self._open_too_long_task and not self._open_too_long_task.done():
            self._open_too_long_task.cancel()
        self._open_too_long_task = None

    async def _open_too_long_countdown(self):
        try:
            await asyncio.sleep(60)
            if self.sim.lock_state == 0:
                if not self.is_connected():
                    return
                await self._notify(ble_constants.CHAR_EVENT, ble_constants.EV_OPEN_TOO_LONG)
        except asyncio.CancelledError:
            return

async def main():
    ble = WindowsBLEPairingAdvertiser()
    await ble.start()
    try:
        await ble.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        await ble.stop()

if __name__ == "__main__":
    asyncio.run(main())
