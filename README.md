# node-red-contrib-motionblinds

Node-RED nodes for **Motion Blinds** (Coulisse B.V.) Wi-Fi bridges — and the many rebrands that share the same protocol (Brel Home, Bloc Blinds, Dooya, 3 Day Blinds, Alta/Bliss, Gaviota, etc.).

This is a pure-JavaScript port of the excellent [starkillerOG/motion-blinds](https://github.com/starkillerOG/motion-blinds) Python library, built directly against the official MOTION Blinds WLAN Integration Guide (v1.02). **Zero runtime dependencies** — everything uses Node.js built-ins (`dgram`, `crypto`, `events`).

## Nodes

| Node | Purpose |
| --- | --- |
| `motion-gateway` | Config node: holds the gateway IP + app KEY, owns the shared multicast listener. |
| `motion-blind` | Send commands (open/close/stop/position/angle) to one blind; emit status on ack and on multicast push. |
| `motion-discover` | Broadcast `GetDeviceList` on the LAN to find gateways and child-device MACs. |

## Install

From your Node-RED user directory:

```bash
cd ~/.node-red
npm install /path/to/node-red-contrib-motionblinds
node-red-restart   # or however you restart your instance
```

Or drop the folder into `~/.node-red/node_modules/` directly.

## Get your app KEY

Open the **Motion Blinds** app (or the matching rebrand — Bloc Blinds, 3 Day Blinds, AMP, Connector, etc.):

1. Tap the three-dot / hamburger menu.
2. Go to **Settings → Motion APP About** (or the equivalent "About" page).
3. Tap the Motion icon / logo **5 times** quickly.
4. A popup shows a 16-character key like `12ab345c-d67e-8f`. **Include the dashes** when you paste it into the gateway config.

## Quick start

1. Drag a `motion-discover` node into a flow, wire an `inject` and a `debug` to it, deploy and inject. The debug output will show your gateway IP and a `data` array of blind MACs.
2. Create a `motion-gateway` config with that IP + your app KEY.
3. Drop a `motion-blind`, pick the gateway, paste a blind MAC.
4. Wire an inject set to `string` / `"open"` (or `"close"`, `"stop"`, `"position:50"`, etc.) into the blind node.

## Command syntax

The `motion-blind` node is tolerant about how you send commands:

```javascript
// msg.payload as string
msg.payload = "open";           // or "close", "stop", "status"
msg.payload = "position:50";    // set position 0–100
msg.payload = "angle:90";       // set angle 0–180

// msg.payload as number (shortcut for set-position)
msg.payload = 75;

// msg.payload as object
msg.payload = { action: "position", value: 50 };
msg.payload = { position: 50 };
msg.payload = { angle: 45 };

// Top-level fields
msg.action   = "open";
msg.position = 50;
msg.angle    = 90;
msg.motor    = "T";             // TDBU only: 'T', 'B', or 'C'
msg.mac      = "…0002";         // override the configured MAC for this message
```

Aliases: `up` = `open`, `down` = `close`, `query`/`read` = `status`.

## Output

```javascript
{
  topic:   "open",              // the action performed (or "status" for pushes)
  payload: {
    mac: "b4e62db27481001f",
    blindType: "RollerBlind",
    status: "Stopped",
    position: 50,
    angle: 180,
    limitStatus: "Limits",
    batteryVoltage: 11.95,      // volts
    batteryLevel: 70,           // percent 0–100 (linear: 10.4 V = 0%, 12.6 V = 100%)
    isCharging: false,
    batteryRaw: 1195,           // raw protocol value (centivolts)
    voltageMode: "DC",
    wirelessMode: "BiDirection",
    RSSI: -68,
    available: true,
    lastUpdate: "2026-04-23T20:37:33.855Z",
    lastError: null
  },
  ack: { /* raw ack JSON from gateway */ },
  _source: "ack"                // or "push" when from multicast
}
```

### Battery level

The gateway reports battery as a raw voltage (in centivolts: `1195` → `11.95 V`). This node splits that into three fields:

- **`batteryVoltage`** — volts, 0.01 precision.
- **`batteryLevel`** — percentage 0–100, computed linearly: `10.4 V = 0%`, `12.6 V = 100%`. These defaults match the Home Assistant integration and the scale starkillerOG documents in home-assistant/core#76527. Override per-gateway in the config node's **Battery scale** section if your specific motor's battery pack is different (some Coulisse CMD-02-P motors max around 12.1 V — see HA issue #125070).
- **`isCharging`** — true when voltage is at or above the charging threshold (default 12.6 V), which corresponds to USB-C power being applied.
- **`batteryRaw`** — the original centivolt reading, preserved for debugging.

AC-powered blinds (those with `voltageMode: "AC"`) return `null` for all four battery fields rather than a bogus 0%. For TDBU blinds each battery field is a `{ T, B }` object with independent readings per motor.

## TDBU (Top-Down-Bottom-Up) blinds

Set the node's **Type** to `10000001`. `position`, `angle`, `status`, and `limitStatus` become objects with `T` and `B` keys. Specify `msg.motor` (`T`, `B`, or `C` for combined) on each command.

## Protocol notes

- Commands go to `gateway_ip:32100` via UDP unicast.
- Heartbeat and Report pushes arrive on `238.0.0.18:32101` via UDP multicast (requires IGMP on your LAN — disable IGMP-snooping / "multicast enhancement" on Ubiquiti gear if pushes don't arrive).
- The `AccessToken` is derived automatically: AES-128-ECB encrypt the gateway's 16-byte `token` under the 16-byte app `KEY`, hex-encoded uppercase.
- `msgID` is a millisecond-resolution timestamp plus a counter to guarantee strict monotonicity across rapid bursts.

## Homelab-specific note

This runs fine on ARM64 Raspberry Pi — there are no native bindings, just the Node.js standard library. If you run Node-RED on a Pi and the gateway is on a VLAN reachable across a Cisco Meraki, make sure UDP 32100/32101 and multicast to `238.0.0.18` are allowed, or set the gateway config's **Multicast** to off and enable **Auto-refresh** to fall back to polling.

## Credits

- [starkillerOG/motion-blinds](https://github.com/starkillerOG/motion-blinds) — the reference Python implementation that this port follows.
- MOTION Blinds WLAN Integration Guide v1.02 — Coulisse B.V. (public PDF).

## License

MIT
