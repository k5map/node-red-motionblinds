/**
 * motion-blinds.js — Node.js client for the Motion Blinds WLAN protocol
 *
 * Ported from the starkillerOG/motion-blinds Python library and the
 * official "MOTION Blinds WLAN Integration Guide" (v1.02).
 *
 * Protocol summary:
 *   - UDP unicast to gateway on port 32100 for commands (WriteDevice/ReadDevice/GetDeviceList)
 *   - UDP multicast 238.0.0.18:32101 for Heartbeat and Report (status push)
 *   - AccessToken = AES-128-ECB(token, KEY) encoded as uppercase hex
 *       token : 16-byte ASCII string from GetDeviceListAck / Heartbeat
 *       KEY   : 16-byte ASCII string from Motion app (dashes included)
 *   - msgID must be a strictly increasing timestamp-ish string
 */

'use strict';

const dgram = require('dgram');
const crypto = require('crypto');
const EventEmitter = require('events');

const SEND_PORT = 32100;
const RECV_PORT = 32101;
const MULTICAST_ADDR = '238.0.0.18';

// ---------- Enums / lookup tables (mirrors Python lib) ----------

const DeviceType = {
    GATEWAY: '02000001',
    GATEWAY_V2: '02000002',
    BLIND: '10000000',
    TDBU: '10000001',
    DOOYA_GATEWAY: '02000005',
};

const BlindType = {
    1: 'RollerBlind',
    2: 'VenetianBlind',
    3: 'RomanBlind',
    4: 'HoneycombBlind',
    5: 'ShangriLaBlind',
    6: 'RollerShutter',
    7: 'RollerGate',
    8: 'Awning',
    9: 'TopDownBottomUp',
    10: 'DayNightBlind',
    11: 'DimmingBlind',
    12: 'Curtain',
    13: 'CurtainLeft',
    14: 'CurtainRight',
    42: 'SkylightBlind',
};

const BlindStatus = {
    0: 'Closing',
    1: 'Opening',
    2: 'Stopped',
    3: 'StatusQuery',
};

const LimitStatus = {
    0: 'NoLimits',
    1: 'TopLimit',
    2: 'BottomLimit',
    3: 'Limits',
    4: 'Limit3rd',
};

const VoltageMode = { 0: 'AC', 1: 'DC' };

const WirelessMode = {
    0: 'UniDirection',
    1: 'BiDirection',
    2: 'BiDirectionMechanicalLimits',
    3: 'Other',
};

const GatewayStatus = { 1: 'Working', 2: 'Pairing', 3: 'Updating' };

// operation values used on the wire
const Operation = {
    CLOSE: 0,
    OPEN: 1,
    STOP: 2,
    STATUS_QUERY: 5,
};

// Battery scale — matches what the Python lib / HA integration use.
// Source: starkillerOG in home-assistant/core#76527 ("The battery level in
// HomeAssistant is calculated using 12.6 V as 100% and 10.4 V as 0%").
// Individual motors vary (some max around 12.1 V per HA issue #125070),
// so these defaults can be overridden per-gateway via the `batteryScale`
// option. Setting `null` disables percentage derivation and only reports
// the raw voltage.
const DEFAULT_BATTERY_MIN_V = 10.4;
const DEFAULT_BATTERY_MAX_V = 12.6;
// Above this voltage the motor is assumed to be on USB-C charging power
// rather than running on battery alone — matches the Python `is_charging`
// heuristic (>= fully-charged voltage).
const DEFAULT_CHARGING_THRESHOLD_V = 12.6;

/**
 * Convert a raw `batteryLevel` protocol field into a percentage 0–100.
 * The raw value is the battery voltage in centivolts (e.g. 1195 => 11.95 V).
 * Values of 0 (AC motors, missing data) return null instead of a bogus 0%.
 *
 * @param {number} raw           — centivolt reading from the gateway
 * @param {number} minV          — voltage considered 0%
 * @param {number} maxV          — voltage considered 100%
 * @returns {number|null}        — integer percentage, or null if not applicable
 */
function batteryPercent(raw, minV = DEFAULT_BATTERY_MIN_V, maxV = DEFAULT_BATTERY_MAX_V) {
    if (typeof raw !== 'number' || raw <= 0) return null;
    const volts = raw / 100;
    if (!(maxV > minV)) return null;
    const pct = ((volts - minV) / (maxV - minV)) * 100;
    // Clamp to 0–100. Some charged motors report above 12.6 V and this
    // prevents the "107 %" / "-2 %" readings seen in HA issues.
    return Math.max(0, Math.min(100, Math.round(pct)));
}

/** Centivolt reading → volts, rounded to 2 decimals. Returns null for 0/missing. */
function centivoltsToVolts(raw) {
    if (typeof raw !== 'number' || raw <= 0) return null;
    return Math.round(raw) / 100;
}

// ---------- Helpers ----------

/** Build a timestamp msgID: YYYYMMDDHHMMSSmmm plus a counter to guarantee monotonicity. */
let _msgIdCounter = 0;
function makeMsgId() {
    const d = new Date();
    const pad = (n, w = 2) => String(n).padStart(w, '0');
    const base =
        d.getUTCFullYear().toString() +
        pad(d.getUTCMonth() + 1) +
        pad(d.getUTCDate()) +
        pad(d.getUTCHours()) +
        pad(d.getUTCMinutes()) +
        pad(d.getUTCSeconds()) +
        pad(d.getUTCMilliseconds(), 3);
    _msgIdCounter = (_msgIdCounter + 1) % 1000;
    return base + pad(_msgIdCounter, 3);
}

/**
 * Compute the AccessToken.
 *   token and key are both 16-byte ASCII strings.
 *   Result is the AES-128-ECB encryption of `token` under `key`, as uppercase hex.
 * Note: we disable PKCS padding because the plaintext is exactly one 16-byte block.
 */
function computeAccessToken(token, key) {
    if (!token || !key) throw new Error('computeAccessToken requires both token and key');
    const keyBuf = Buffer.from(key, 'utf8');
    const tokenBuf = Buffer.from(token, 'utf8');
    if (keyBuf.length !== 16) {
        throw new Error(`KEY must be 16 bytes (got ${keyBuf.length}). Include dashes, e.g. "12ab345c-d67e-8f".`);
    }
    if (tokenBuf.length !== 16) {
        throw new Error(`token must be 16 bytes (got ${tokenBuf.length}).`);
    }
    const cipher = crypto.createCipheriv('aes-128-ecb', keyBuf, null);
    cipher.setAutoPadding(false);
    const encrypted = Buffer.concat([cipher.update(tokenBuf), cipher.final()]);
    return encrypted.toString('hex').toUpperCase();
}

// ---------- Gateway ----------

/**
 * MotionGateway — one instance per physical Wi-Fi bridge.
 *
 * Events emitted:
 *   'update'         (gatewayStatusObject)
 *   'blind-update'   (mac, blindStateObject)
 *   'error'          (err)
 *   'raw'            (parsedJson, rinfo)   // every inbound packet
 */
class MotionGateway extends EventEmitter {
    /**
     * @param {object} opts
     * @param {string} opts.ip    — gateway IP address
     * @param {string} opts.key   — 16-byte Motion app KEY (dashes included)
     * @param {MotionMulticast} [opts.multicast] — optional shared listener for push updates
     * @param {number} [opts.timeout=3000] — per-request timeout (ms)
     * @param {number} [opts.retries=3]    — request retries on timeout
     * @param {object} [opts.logger]       — optional { debug, info, warn, error } sink
     */
    constructor(opts) {
        super();
        if (!opts || !opts.ip) throw new Error('MotionGateway: ip is required');
        if (!opts.key) throw new Error('MotionGateway: key is required');
        this.ip = opts.ip;
        this.key = opts.key;
        this.timeout = opts.timeout || 3000;
        this.retries = opts.retries || 3;
        this.log = opts.logger || { debug() {}, info() {}, warn() {}, error() {} };

        // Battery voltage-to-percent scale. Defaults are the same ones the
        // Python library / HA integration use. Pass { min, max, charging }
        // to override, or { min: null, max: null } to disable percentages
        // entirely and emit only raw voltage.
        const bs = opts.batteryScale || {};
        this.batteryScale = {
            min:      bs.min      !== undefined ? bs.min      : DEFAULT_BATTERY_MIN_V,
            max:      bs.max      !== undefined ? bs.max      : DEFAULT_BATTERY_MAX_V,
            charging: bs.charging !== undefined ? bs.charging : DEFAULT_CHARGING_THRESHOLD_V,
        };

        this.mac = null;
        this.deviceType = null;
        this.protocol = null;
        this.token = null;
        this.accessToken = null;
        this.status = null;
        this.numDevices = null;
        this.rssi = null;
        this.firmware = null;
        this.devices = new Map(); // mac -> MotionBlind

        this._pending = new Map(); // msgID -> { resolve, reject, timer }
        this._closed = false;

        this.multicast = opts.multicast || null;
        if (this.multicast) this._bindMulticast(this.multicast);

        // Start a dedicated unicast listener on port 32101. The Motion Blinds
        // protocol sends ReadDeviceAck and status Reports to Client_IP:32101
        // — which is the SAME port the multicast listener uses. On LANs where
        // IGMP snooping / multicast is disabled or blocked, the multicast
        // listener never sees packets, but unicast to the host's own IP on
        // 32101 still works. A plain UDP bind on 0.0.0.0:32101 catches both.
        //
        // If a MotionMulticast listener is provided, we rely on it to catch
        // multicast traffic and skip the unicast fallback (which would
        // otherwise receive the same packets a second time and force dedup
        // to do extra work). The fallback is only useful when multicast is
        // disabled entirely.
        if (!this.multicast) {
            this._startUnicastListener();
        }
    }

    _startUnicastListener() {
        if (this._unicastListener) return;
        const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
        sock.on('error', (err) => {
            this.log.warn(`unicast listener error on :${RECV_PORT}: ${err.message}`);
            this._unicastListener = null;
        });
        // Tag this socket's deliveries so _handleIncoming can identify them
        // correctly (sender port won't tell us — a multicast packet arriving
        // here still has rinfo.port == 32100 from the gateway's perspective).
        sock.on('message', (buf, rinfo) => this._handleIncoming(buf, rinfo, /*viaMulticast=*/ false, /*source=*/ 'RECV32101'));
        sock.on('listening', () => {
            this._unicastListener = sock;
            this.log.debug(`unicast listener bound to 0.0.0.0:${RECV_PORT}`);
        });
        try {
            sock.bind(RECV_PORT);
        } catch (e) {
            this.log.warn(`could not bind unicast listener on :${RECV_PORT}: ${e.message}`);
        }
    }

    _bindMulticast(mc) {
        mc.on('message', (msg, rinfo) => this._handleIncoming(msg, rinfo, /*viaMulticast=*/ true));
    }

    /**
     * Lazily create a single persistent UDP socket used for all outbound
     * commands. Bugfix: v0.1–0.2 created a fresh socket per send, which meant
     * every retry sent from a different ephemeral port. The Motion gateway
     * sends WriteDeviceAck back to the source port of the request; a new
     * ephemeral port per retry means acks arrive at a socket that no longer
     * exists (or has already timed out). The upshot was the symptom of
     * "see three responses via multicast, then timeout error" because only
     * the multicast listener was actually receiving the acks and the pending
     * resolver got overwritten between retries.
     *
     * Using one long-lived socket bound to a fixed ephemeral port fixes that,
     * AND avoids leaking sockets when many commands are in flight.
     */
    _getSendSocket() {
        if (this._sock) return Promise.resolve(this._sock);
        if (this._sockReady) return this._sockReady;
        this._sockReady = new Promise((resolve, reject) => {
            const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
            sock.on('error', (err) => {
                this.log.warn(`send socket error: ${err.message}`);
                // If the socket dies, clear the cache so next request rebuilds it.
                if (this._sock === sock) {
                    this._sock = null;
                    this._sockReady = null;
                }
            });
            sock.on('message', (buf, rinfo) => this._handleIncoming(buf, rinfo, /*viaMulticast=*/ false));
            sock.on('listening', () => {
                this._sock = sock;
                resolve(sock);
            });
            // Bind to an OS-picked ephemeral port on all interfaces. The
            // gateway will send the ack back to this port.
            try {
                sock.bind(0);
            } catch (e) {
                reject(e);
            }
        });
        return this._sockReady;
    }

    /**
     * Build the response signature for a given request. The gateway's ack
     * type is the request type with 'Ack' appended (e.g. ReadDevice ->
     * ReadDeviceAck). Correlation is done on (ackType, mac) because some
     * firmware versions rewrite the msgID in the response, so strict
     * msgID matching is unreliable.
     *
     * @param {object} req  — the request payload we sent
     * @returns {string}    — signature string
     */
    _reqSig(req) {
        const mac = req.mac || '';
        return `${req.msgType}Ack:${mac}`;
    }

    /** Build the signature of an incoming response. */
    _respSig(parsed) {
        const t = parsed.msgType || '';
        // 'Report' (unsolicited status push) maps to ReadDeviceAck for
        // correlation purposes — clients that issued ReadDevice are often
        // happy to accept a Report with matching mac as the "answer."
        const sigType = (t === 'Report') ? 'ReadDeviceAck' : t;
        const mac = parsed.mac || '';
        return `${sigType}:${mac}`;
    }

    /**
     * Send a request and await the ack. Retries on timeout with a FRESH msgID
     * each time (the protocol spec says msgID must be strictly increasing per
     * operation or the gateway may silently drop the duplicate).
     */
    async _request(payload) {
        const basePayload = { ...payload };
        let lastErr;
        for (let attempt = 0; attempt < this.retries; attempt++) {
            try {
                const msgID = makeMsgId();
                const withId = { ...basePayload, msgID };
                return await this._sendOnce(withId, msgID);
            } catch (err) {
                lastErr = err;
                this.log.debug(`attempt ${attempt + 1}/${this.retries} of ${basePayload.msgType} timed out`);
            }
        }
        throw new Error(`Timeout after ${this.retries} attempts sending ${basePayload.msgType}: ${lastErr && lastErr.message}`);
    }

    _sendOnce(payloadObj, msgID) {
        return new Promise(async (resolve, reject) => {
            let settled = false;
            const sig = this._reqSig(payloadObj);
            const pendingEntry = {
                msgID,
                sig,
                sentAt: Date.now(),
                resolve: (obj) => {
                    if (settled) return;
                    settled = true;
                    clearTimeout(timer);
                    cleanup();
                    resolve(obj);
                },
                reject: (e) => {
                    if (settled) return;
                    settled = true;
                    clearTimeout(timer);
                    cleanup();
                    reject(e);
                },
            };

            const cleanup = () => { this._pending.delete(msgID); };

            const timer = setTimeout(() => {
                if (settled) return;
                settled = true;
                cleanup();
                this.log.debug(`[TIMEOUT] msgID=${msgID} sig=${sig} pending-map-size-after=${this._pending.size}`);
                reject(new Error('request timeout'));
            }, this.timeout);

            this._pending.set(msgID, pendingEntry);

            try {
                const sock = await this._getSendSocket();
                if (settled) return; // might have timed out while waiting for socket
                const data = Buffer.from(JSON.stringify(payloadObj));
                const localPort = (sock.address && sock.address().port) || '?';
                this.log.debug(`[SEND] ${payloadObj.msgType} msgID=${msgID} sig=${sig} to ${this.ip}:${SEND_PORT} from local-port=${localPort} bytes=${data.length}`);
                sock.send(data, 0, data.length, SEND_PORT, this.ip, (err) => {
                    if (err && !settled) {
                        settled = true;
                        clearTimeout(timer);
                        cleanup();
                        reject(err);
                    }
                });
            } catch (e) {
                if (settled) return;
                settled = true;
                clearTimeout(timer);
                cleanup();
                reject(e);
            }
        });
    }

    /**
     * Find the oldest pending request whose signature matches this response,
     * or a pending request whose msgID matches. Returns the entry (or null).
     * Matching on sig is the primary path — some gateway firmwares rewrite
     * msgIDs in responses, so a strict msgID match is unreliable.
     *
     * Matching rules:
     *   - msgID exact match wins (well-behaved firmware)
     *   - else (ackType, mac) match, oldest first
     *   - else (ackType only) match for gateway-wide ops where the request
     *     had no mac but the response does (e.g. GetDeviceList)
     */
    _matchPending(parsed) {
        if (!this._pending.size) return null;

        // Primary: msgID exact match (covers well-behaved firmware)
        if (parsed.msgID && this._pending.has(parsed.msgID)) {
            return this._pending.get(parsed.msgID);
        }

        const respSig = this._respSig(parsed);
        const respType = respSig.split(':')[0];

        // Secondary: exact sig match (msgType + mac). Pick the oldest
        // in-flight request with this signature so that burst-of-N reads
        // still pair up in order.
        let best = null;
        for (const entry of this._pending.values()) {
            if (entry.sig === respSig) {
                if (!best || entry.sentAt < best.sentAt) best = entry;
            }
        }
        if (best) return best;

        // Tertiary: type-only match, for gateway-wide requests whose
        // sig has no mac (e.g. GetDeviceListAck: matches a response
        // GetDeviceListAck:500291b691fd).
        for (const entry of this._pending.values()) {
            const [entryType, entryMac] = entry.sig.split(':');
            if (entryType === respType && !entryMac) {
                if (!best || entry.sentAt < best.sentAt) best = entry;
            }
        }
        return best;
    }

    _handleIncoming(buf, rinfo, viaMulticast, sourceTag) {
        let parsed;
        try {
            parsed = JSON.parse(buf.toString('utf8'));
        } catch (e) {
            this.log.warn(`unparseable packet from ${rinfo.address}:${rinfo.port}: ${e.message}`);
            return;
        }

        // Source label — explicit tag wins, otherwise fall back to heuristic.
        const src = sourceTag
            || (viaMulticast ? 'MCAST' : 'SEND-SOCK');

        // Heartbeats are chatty (every 30–60s forever) and not typically
        // useful to see in logs. Skip the [RECV] line for them unless the
        // user opts in; still process them normally below.
        const isHeartbeat = parsed.msgType === 'Heartbeat';
        if (!isHeartbeat || this._logHeartbeats) {
            this.log.debug(`[RECV ${src}] from=${rinfo.address}:${rinfo.port} msgType=${parsed.msgType} msgID=${parsed.msgID || '-'} mac=${parsed.mac || '-'} pending=${this._pending.size}`);
        }

        // Ignore packets from other gateways on multicast. Real-world blind
        // MACs do not always share an OUI prefix with their gateway, so we
        // identify "ours" by either:
        //   - the packet's mac is our gateway mac, or
        //   - the packet's mac is a blind we've seen on this gateway, or
        //   - we don't know our own mac yet (first GetDeviceListAck)
        const logSubLines = !isHeartbeat || this._logHeartbeats;
        if (viaMulticast && this.mac && parsed.mac) {
            const m = String(parsed.mac);
            const isOurs =
                m === this.mac ||
                this.devices.has(m) ||
                // Heuristic for brand-new blinds we haven't recorded yet:
                // gateway's own mac appears at the start (some vendors) OR
                // the packet is a Heartbeat (gateway itself, already matched
                // above via m === this.mac).
                m.startsWith(this.mac);
            if (!isOurs) {
                if (logSubLines) this.log.debug(`  [drop] unknown-mac packet ${m} (gateway=${this.mac})`);
                return;
            }
        }
        if (!viaMulticast && rinfo.address !== this.ip) {
            if (logSubLines) this.log.debug(`  [drop] unicast from non-gateway address (expected ${this.ip})`);
            return;
        }

        // Deduplicate: the same packet can reach us on multiple sockets —
        // e.g. multicast listener + unicast 32101 listener both receive the
        // gateway's broadcast Report, or a unicast ack echoes into both the
        // send socket and the 32101 listener. Process each logical packet
        // exactly once, keyed on (msgType, mac, msgID). A short TTL lets
        // new state arrivals through quickly while suppressing the twin.
        const dedupKey = `${parsed.msgType}|${parsed.mac || ''}|${parsed.msgID || ''}`;
        const now = Date.now();
        if (!this._dedup) this._dedup = new Map();
        // Sweep any stale entries while we're here (cheap — Map is small).
        if (this._dedup.size > 64) {
            for (const [k, t] of this._dedup) {
                if (now - t > 2000) this._dedup.delete(k);
            }
        }
        if (this._dedup.has(dedupKey) && (now - this._dedup.get(dedupKey)) < 500) {
            if (logSubLines) this.log.debug(`  [dupe] suppressing duplicate delivery via ${src}`);
            // Still resolve a pending request if one is waiting — the
            // promise might have been registered between the first and
            // second delivery — but never emit state/events a second time.
            const entry = this._matchPending(parsed);
            if (entry) entry.resolve(parsed);
            return;
        }
        this._dedup.set(dedupKey, now);

        this.emit('raw', parsed, rinfo);

        const entry = this._matchPending(parsed);
        if (entry) {
            const via = (parsed.msgID === entry.msgID) ? 'msgID' : 'sig';
            if (logSubLines) this.log.debug(`  [MATCH via ${via}] resolving pending ${entry.sig} (msgID ours=${entry.msgID} theirs=${parsed.msgID || '-'})`);
            entry.resolve(parsed);
        } else if (parsed.msgID && logSubLines) {
            this.log.debug(`  [no match] respSig=${this._respSig(parsed)} msgID=${parsed.msgID} pending-sigs=[${[...this._pending.values()].map(e=>e.sig).join(',') || 'empty'}]`);
        }

        this._absorb(parsed);
    }

    /** Merge an incoming message into gateway/blind state and emit events. */
    _absorb(msg) {
        const t = msg.msgType;
        if (t === 'Heartbeat' || t === 'GetDeviceListAck') {
            if (msg.mac) this.mac = msg.mac;
            if (msg.deviceType) this.deviceType = msg.deviceType;
            if (msg.ProtocolVersion) this.protocol = msg.ProtocolVersion;
            if (msg.token) {
                this.token = msg.token;
                try {
                    this.accessToken = computeAccessToken(this.token, this.key);
                } catch (e) {
                    this.log.error(`AccessToken derivation failed: ${e.message}`);
                }
            }
            if (msg.fwVersion) this.firmware = msg.fwVersion;
            if (msg.data && !Array.isArray(msg.data)) {
                // Heartbeat: data is an object
                if (typeof msg.data.currentState === 'number') this.status = GatewayStatus[msg.data.currentState] || String(msg.data.currentState);
                if (typeof msg.data.numberOfDevices === 'number') this.numDevices = msg.data.numberOfDevices;
                if (typeof msg.data.RSSI === 'number') this.rssi = msg.data.RSSI;
            }
            if (Array.isArray(msg.data)) {
                // GetDeviceListAck: data is an array of { mac, deviceType }
                for (const entry of msg.data) {
                    if (!entry || !entry.mac) continue;
                    if (entry.mac === this.mac) continue; // skip the gateway itself
                    if (!this.devices.has(entry.mac)) {
                        this.devices.set(entry.mac, new MotionBlind(this, entry.mac, entry.deviceType));
                    }
                }
            }
            this.emit('update', this.snapshot());
        } else if (t === 'WriteDeviceAck' || t === 'ReadDeviceAck' || t === 'Report') {
            // Per-blind status update
            const mac = msg.mac;
            if (!mac) return;
            let blind = this.devices.get(mac);
            if (!blind) {
                blind = new MotionBlind(this, mac, msg.deviceType);
                this.devices.set(mac, blind);
            }
            blind._absorb(msg);
            this.emit('blind-update', mac, blind.snapshot());
        }
    }

    /** Retrieve device list and populate this.devices. Returns the raw ack. */
    async getDeviceList() {
        const ack = await this._request({ msgType: 'GetDeviceList' });
        return ack;
    }

    /** Ask for gateway heartbeat-equivalent status.
     *  The protocol doesn't expose a dedicated status-query for the gateway, but
     *  GetDeviceList refreshes token + device list, and the multicast Heartbeat
     *  fills in RSSI/numDevices/status. */
    async update() {
        return this.getDeviceList();
    }

    /** Fetch a blind by mac; auto-creates the object if not yet discovered. */
    blind(mac) {
        let b = this.devices.get(mac);
        if (!b) {
            b = new MotionBlind(this, mac, DeviceType.BLIND);
            this.devices.set(mac, b);
        }
        return b;
    }

    /** Plain-object snapshot, safe to forward as a Node-RED msg.payload */
    snapshot() {
        return {
            ip: this.ip,
            mac: this.mac,
            deviceType: this.deviceType,
            protocol: this.protocol,
            status: this.status,
            numDevices: this.numDevices,
            RSSI: this.rssi,
            firmware: this.firmware,
            token: this.token,
            blinds: [...this.devices.keys()],
        };
    }

    close() {
        this._closed = true;
        for (const p of this._pending.values()) {
            try { p.reject(new Error('gateway closed')); } catch (_) {}
        }
        this._pending.clear();
        if (this._sock) {
            try { this._sock.close(); } catch (_) {}
            this._sock = null;
            this._sockReady = null;
        }
        if (this._unicastListener) {
            try { this._unicastListener.close(); } catch (_) {}
            this._unicastListener = null;
        }
    }
}

// ---------- Blind ----------

class MotionBlind {
    constructor(gateway, mac, deviceType) {
        this.gateway = gateway;
        this.mac = mac;
        this.deviceType = deviceType || DeviceType.BLIND;
        this.type = null;           // numeric
        this.blindType = null;      // string (BlindType name)
        this.operation = null;      // numeric (last operation reported)
        this.status = null;         // BlindStatus name (derived from operation)
        this.position = null;       // 0-100  (for TDBU this is { T, B })
        this.angle = null;          // 0-180  (for TDBU this is { T, B })
        this.limitStatus = null;
        // Battery data is reported by the gateway as a raw centivolt reading
        // (e.g. 1195 == 11.95 V). We split that into three user-friendly
        // fields. For TDBU blinds each is { T, B }.
        this.batteryVoltage = null; // volts (0.01 precision) — null when not applicable
        this.batteryLevel = null;   // percentage 0-100 — null when not applicable
        this.isCharging = null;     // boolean — true when voltage >= charging threshold
        this.batteryRaw = null;     // raw centivolt value(s), preserved for debugging
        this.voltageMode = null;
        this.wirelessMode = null;
        this.rssi = null;
        this.available = true;
        this.lastUpdate = null;
    }

    get isTdbu() {
        return this.deviceType === DeviceType.TDBU || this.type === 9;
    }

    _absorb(msg) {
        const d = msg.data || {};
        this.lastUpdate = new Date().toISOString();
        if (msg.deviceType) this.deviceType = msg.deviceType;
        if (typeof d.type === 'number') {
            this.type = d.type;
            this.blindType = BlindType[d.type] || `Unknown(${d.type})`;
        }
        if (typeof d.voltageMode === 'number') this.voltageMode = VoltageMode[d.voltageMode] || d.voltageMode;
        if (typeof d.wirelessMode === 'number') this.wirelessMode = WirelessMode[d.wirelessMode] || d.wirelessMode;
        if (typeof d.RSSI === 'number') this.rssi = d.RSSI;

        // AC motors report batteryLevel=0. Don't fabricate a percentage for them.
        const isAc = (this.voltageMode === 'AC' || d.voltageMode === 0);
        const scale = this.gateway.batteryScale;

        if (this.isTdbu) {
            this.operation = { T: d.operation_T, B: d.operation_B };
            this.status = {
                T: BlindStatus[d.operation_T] || null,
                B: BlindStatus[d.operation_B] || null,
            };
            this.position = { T: d.currentPosition_T, B: d.currentPosition_B };
            this.angle = { T: d.currentAngle_T, B: d.currentAngle_B };
            this.limitStatus = {
                T: LimitStatus[d.currentState_T] || null,
                B: LimitStatus[d.currentState_B] || null,
            };

            // Per-motor battery. TDBU reports batteryLevel_T / batteryLevel_B
            // as centivolts, one per motor.
            this.batteryRaw = { T: d.batteryLevel_T, B: d.batteryLevel_B };
            if (isAc) {
                this.batteryVoltage = null;
                this.batteryLevel = null;
                this.isCharging = null;
            } else {
                const vt = centivoltsToVolts(d.batteryLevel_T);
                const vb = centivoltsToVolts(d.batteryLevel_B);
                this.batteryVoltage = { T: vt, B: vb };
                this.batteryLevel = {
                    T: batteryPercent(d.batteryLevel_T, scale.min, scale.max),
                    B: batteryPercent(d.batteryLevel_B, scale.min, scale.max),
                };
                this.isCharging = {
                    T: vt != null ? vt >= scale.charging : null,
                    B: vb != null ? vb >= scale.charging : null,
                };
            }
        } else {
            if (typeof d.operation === 'number') {
                this.operation = d.operation;
                this.status = BlindStatus[d.operation] || null;
            }
            if (typeof d.currentPosition === 'number') this.position = d.currentPosition;
            if (typeof d.currentAngle === 'number') this.angle = d.currentAngle;
            if (typeof d.currentState === 'number') this.limitStatus = LimitStatus[d.currentState] || null;

            if (typeof d.batteryLevel === 'number') {
                this.batteryRaw = d.batteryLevel;
                if (isAc) {
                    this.batteryVoltage = null;
                    this.batteryLevel = null;
                    this.isCharging = null;
                } else {
                    const v = centivoltsToVolts(d.batteryLevel);
                    this.batteryVoltage = v;
                    this.batteryLevel = batteryPercent(d.batteryLevel, scale.min, scale.max);
                    this.isCharging = v != null ? v >= scale.charging : null;
                    // Warn once per blind if the voltage is well outside the
                    // configured scale — a strong signal that the Battery
                    // scale config doesn't match this motor's battery pack.
                    // Margin = 0.5 V on each side to avoid nuisance warnings
                    // for deep-discharge or slightly-over-float readings.
                    if (v != null && !this._scaleWarned) {
                        const under = v < (scale.min - 0.5);
                        const over  = v > (scale.max + 0.5);
                        if (under || over) {
                            this._scaleWarned = true;
                            const gw = this.gateway;
                            gw.log.warn(
                                `blind ${this.mac}: battery voltage ${v.toFixed(2)} V is outside the configured scale ` +
                                `(${scale.min}–${scale.max} V). The batteryLevel % will be clamped and inaccurate. ` +
                                `Update the gateway config's Battery scale to match this motor's pack, ` +
                                `or use the batteryRaw / batteryVoltage fields directly.`
                            );
                        }
                    }
                }
            }
        }

        if (msg.actionResult) {
            this.available = false;
            this._lastError = msg.actionResult;
        }
    }

    snapshot() {
        return {
            mac: this.mac,
            deviceType: this.deviceType,
            type: this.type,
            blindType: this.blindType,
            status: this.status,
            position: this.position,
            angle: this.angle,
            limitStatus: this.limitStatus,
            batteryVoltage: this.batteryVoltage, // volts (or { T, B } for TDBU)
            batteryLevel: this.batteryLevel,     // percent 0-100 (or { T, B })
            isCharging: this.isCharging,         // boolean (or { T, B })
            batteryRaw: this.batteryRaw,         // centivolts, unprocessed
            voltageMode: this.voltageMode,
            wirelessMode: this.wirelessMode,
            RSSI: this.rssi,
            available: this.available,
            lastUpdate: this.lastUpdate,
            lastError: this._lastError || null,
        };
    }

    // ---- Commands ----

    _writeDevice(data) {
        if (!this.gateway.accessToken) {
            return Promise.reject(new Error('No AccessToken yet — call getDeviceList() first so the gateway token is known.'));
        }
        return this.gateway._request({
            msgType: 'WriteDevice',
            mac: this.mac,
            deviceType: this.deviceType,
            AccessToken: this.gateway.accessToken,
            data,
        });
    }

    _readDevice() {
        return this.gateway._request({
            msgType: 'ReadDevice',
            mac: this.mac,
            deviceType: this.deviceType,
        });
    }

    update() { return this._readDevice(); }

    open(motor)  { return this._motorOp(Operation.OPEN, motor); }
    close(motor) { return this._motorOp(Operation.CLOSE, motor); }
    stop(motor)  { return this._motorOp(Operation.STOP, motor); }

    _motorOp(op, motor) {
        if (this.isTdbu) {
            return this._writeDevice(this._tdbuOp(op, motor));
        }
        return this._writeDevice({ operation: op });
    }

    _tdbuOp(op, motor) {
        motor = motor || 'B';
        if (motor === 'T') return { operation_T: op };
        if (motor === 'B') return { operation_B: op };
        if (motor === 'C') return { operation_T: op, operation_B: op };
        throw new Error(`TDBU motor must be 'T', 'B', or 'C' (got ${motor})`);
    }

    setPosition(position, motor) {
        if (position < 0 || position > 100) throw new Error('position must be 0-100');
        if (this.isTdbu) {
            motor = motor || 'B';
            const data = {};
            if (motor === 'T' || motor === 'C') data.targetPosition_T = position;
            if (motor === 'B' || motor === 'C') data.targetPosition_B = position;
            return this._writeDevice(data);
        }
        return this._writeDevice({ targetPosition: position });
    }

    setAngle(angle, motor) {
        if (angle < 0 || angle > 180) throw new Error('angle must be 0-180');
        if (this.isTdbu) {
            motor = motor || 'B';
            const data = {};
            if (motor === 'T' || motor === 'C') data.targetAngle_T = angle;
            if (motor === 'B' || motor === 'C') data.targetAngle_B = angle;
            return this._writeDevice(data);
        }
        return this._writeDevice({ targetAngle: angle });
    }
}

// ---------- Multicast listener (shared by many gateways) ----------

/**
 * MotionMulticast — joins 238.0.0.18:32101 and emits 'message' for every
 * inbound Heartbeat / Report packet. One instance can feed many MotionGateways.
 */
class MotionMulticast extends EventEmitter {
    constructor(opts) {
        super();
        this.interface = (opts && opts.interface) || null; // e.g. '0.0.0.0' or a specific local IP
        this.port = (opts && opts.port) || RECV_PORT;
        this.group = (opts && opts.group) || MULTICAST_ADDR;
        this.sock = null;
        this._listening = false;
    }

    start() {
        if (this._listening) return Promise.resolve();
        return new Promise((resolve, reject) => {
            const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
            this.sock = sock;

            sock.on('error', (err) => {
                this.emit('error', err);
                if (!this._listening) reject(err);
            });

            sock.on('message', (msg, rinfo) => this.emit('message', msg, rinfo));

            sock.on('listening', () => {
                try {
                    sock.setBroadcast(true);
                    sock.addMembership(this.group, this.interface || undefined);
                    this._listening = true;
                    resolve();
                } catch (e) {
                    reject(e);
                }
            });

            sock.bind(this.port, () => {});
        });
    }

    stop() {
        if (!this._listening) return;
        try { this.sock.dropMembership(this.group); } catch (_) {}
        try { this.sock.close(); } catch (_) {}
        this._listening = false;
        this.sock = null;
    }
}

// ---------- Discovery ----------

/**
 * Discover gateways by broadcasting GetDeviceList and collecting every ack.
 * Returns an array of raw GetDeviceListAck objects keyed by source IP.
 */
function discover({ duration = 5000, interfaceIp } = {}) {
    return new Promise((resolve, reject) => {
        const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
        const found = {};
        const payload = Buffer.from(JSON.stringify({
            msgType: 'GetDeviceList',
            msgID: makeMsgId(),
        }));

        sock.on('error', (err) => {
            try { sock.close(); } catch (_) {}
            reject(err);
        });

        sock.on('message', (msg, rinfo) => {
            try {
                const parsed = JSON.parse(msg.toString('utf8'));
                if (parsed.msgType === 'GetDeviceListAck') {
                    found[rinfo.address] = parsed;
                }
            } catch (_) { /* ignore */ }
        });

        sock.on('listening', () => {
            try { sock.setBroadcast(true); } catch (_) {}
            try { sock.addMembership(MULTICAST_ADDR, interfaceIp || undefined); } catch (_) {}
            sock.send(payload, 0, payload.length, SEND_PORT, MULTICAST_ADDR, (err) => {
                if (err) {
                    try { sock.close(); } catch (_) {}
                    return reject(err);
                }
            });
        });

        sock.bind(0, interfaceIp || undefined);

        setTimeout(() => {
            try { sock.dropMembership(MULTICAST_ADDR); } catch (_) {}
            try { sock.close(); } catch (_) {}
            resolve(found);
        }, duration);
    });
}

module.exports = {
    MotionGateway,
    MotionBlind,
    MotionMulticast,
    discover,
    computeAccessToken,
    makeMsgId,
    batteryPercent,
    centivoltsToVolts,
    DeviceType,
    BlindType,
    BlindStatus,
    LimitStatus,
    VoltageMode,
    WirelessMode,
    GatewayStatus,
    Operation,
    DEFAULT_BATTERY_MIN_V,
    DEFAULT_BATTERY_MAX_V,
    DEFAULT_CHARGING_THRESHOLD_V,
    SEND_PORT,
    RECV_PORT,
    MULTICAST_ADDR,
};
