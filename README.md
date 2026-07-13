# Offloaded Kyber on ESP8266

This repository contains the source code developed for a master's thesis on
local and offloaded execution of Kyber on ESP8266 devices using MQTT.

## Project structure

- `single-node`: Local execution on one ESP8266 node
- `mainnode`: Main node of the offloaded implementation
- `helper1`: Helper node responsible for computing `b`
- `helper2`: Helper node responsible for computing `v`

## Requirements

- ESP8266 development boards
- Arduino IDE
- ESP8266 board package
- MQTT broker
- Wi-Fi network

## Configuration

Before compiling the distributed nodes, replace the following values in each
`.ino` file:

```cpp
static const char* WIFI_SSID = "YOUR_WIFI_NAME";
static const char* WIFI_PASS = "YOUR_WIFI_PASSWORD";
Replace MQTT_HOST with the IP address of the device running the MQTT broker.

## Execution order
Start the MQTT broker.
Upload the helper1 code to the first ESP8266.
Upload the helper2 code to the second ESP8266.
Upload the mainnode code to the main ESP8266.
Open the serial monitor at 115200 baud.

## Single-node execution

Upload the code inside the single-node directory to one ESP8266 board.

## Notice

This implementation was developed for academic experimentation and performance
evaluation. It has not undergone an independent security audit.
