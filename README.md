📘 Kurb BLE Simulator — README (v1.0)

A complete logic + BLE wrapper simulator for the Kurb device ecosystem

🧭 Overview

This repository contains the official Kurb BLE Simulator, a development tool for the Kurb mobile app team. It allows the team to test:

Device logic (unlock rules, schedules, battery behavior)

App UI/UX flows

App → Device → App communication patterns

BLE communication flows (once wrapper implemented)

This simulator does NOT require actual hardware.
It is used during Phase 1 QA to validate all app-side behavior before the ESP32-S3 firmware is ready.

The simulator consists of two layers:

🔷 1. Logic Layer (COMPLETE)

The logic layer replicates the internal “brains” of the Kurb device:

✔ Implemented Logic

Daily-limit schedule mode

Time-window schedule mode

Unlock-allowed / unlock-denied behavior

State machine (locked, unlocked)

Battery behavior

Low battery

Critical battery

Auto-unlock fail-open mode

Error handling

JSON schedule parsing

Tracking remaining unlocks

Window consumption

Device closure simulation

The logic layer is fully functional and testable today, with no BLE required.

🔷 2. BLE Wrapper Layer (NOT IMPLEMENTED YET)

The BLE wrapper exposes the logic layer as a BLE peripheral and handles:

Advertising

GATT service creation

Characteristic read/write

Notifications and event emissions

Pairing flow (passkey)

Connection lifecycle

Because BLE peripheral behavior differs on Windows vs Linux, the India dev team must complete this layer using platform APIs (WinRT or BlueZ).

A full BLE wrapper scaffold is provided in:

src/ble_wrapper_stub.py

📁 Repository Structure
kurb-ble-simulator/
│
├── README.md
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
│
├── src/
│   ├── main.py
│   ├── kurb_logic.py
│   ├── ble_wrapper_stub.py
│   ├── ble_constants.py
│   ├── schedule_engine.py
│   ├── battery_engine.py
│   ├── state_machine.py
│   └── utils.py
│
├── tests/
│   ├── test_daily_limit.py
│   ├── test_time_window.py
│   ├── test_fail_open.py
│   ├── test_schedule_json.py
│   └── test_state_machine.py
│
└── tools/
    ├── cli_debugger.py
    └── sample_schedules/

🚀 Getting Started

To run the simulator:

1. Install Python 3.11+

Check version:

python --version

2. Install dependencies
pip install -r requirements.txt

3. Run the Logic Simulator
python src/main.py


You will see:

Kurb Logic Simulator
This is the logic-only device core. No BLE enabled.


Use the menu to test:

Unlock behavior

Schedules

Battery

Fail-open mode

🔌 BLE Integration (For App Dev Team)

The BLE wrapper (peripheral mode) must be implemented using:

✔ Windows

WinRT BluetoothLEAdvertisementPublisher + GATT Service Provider

✔ Linux

BlueZ (via python-dbus or pydbus)

✖ macOS

Cannot simulate BLE peripherals — OS limitation.

BLE Responsibilities (app dev team)
Implement BLE advertising

Name: Kurb_V1_Sim

Service UUID:
e1b10000-1234-4abc-a001-1234567890ab

Create the required GATT characteristics

Defined in:

src/ble_constants.py

Map BLE writes → logic engine methods

Examples:

BLE Write	Logic Method
LockCommand (0x02)	sim.attempt_unlock()
LockCommand (0x20)	sim._reset()
ScheduleConfig JSON	sim.on_write_schedule()
TimeSync	sim.on_write_timesync()
Map logic events → BLE notifications

Logic event → BLE characteristic:

Logic Event	BLE Notification
Unlocked	EventNotification=0x02 + LockState=0x00
Locked	EventNotification=0x01 + LockState=0x01
BatteryLow	EventNotification=0x05
BatteryCritical	EventNotification=0x06
EmergencyUnlock	EventNotification=0x09
GenericError	EventNotification=0x08

The BLE wrapper stub already includes function placeholders:

on_write_lock_command()
on_write_schedule()
on_logic_event()
on_read()
send_notification()
start_advertising()


Developers only need to fill in OS-specific BLE server code.

🧪 Phase 1 QA (Can be done now)

Without hardware, QA can test:

Correct/incorrect unlock attempts

Daily-limit countdown

Time-window matching

Battery low/critical behavior

Fail-open auto unlock

Schedule parsing

Error messaging flows

Lock state transitions

App handling of event codes

🧪 Phase 2 QA (After BLE wrapper or hardware)

Once BLE is added:

Full app → BLE → simulator integration

UI feedback timing

Connection/disconnection states

Passkey pairing flow

GATT read/write behavior

Notification subscription handling

🐳 Docker Support

You can run the simulator inside Docker:

docker-compose up --build


This ensures:

Identical environment for all devs

Avoids Python dependency issues

Prepares for CI/CD integration

📝 Contributing Guidelines

All new modules should:

Follow PEP8

Use async where applicable

Keep BLE logic separate from device logic

Include unit tests under /tests

Document new UUIDs or events in ble_constants.py

🛠 Future Enhancements

The following optional enhancements can be added later:

Multi-device simulation

BLE connection reliability testing

Stress-test automation

Randomized event generation

OTA update simulation

Full cloud backend integration stubs
