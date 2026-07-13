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
