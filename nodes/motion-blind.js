module.exports = function (RED) {
    function MotionBlindNode(config) {
        RED.nodes.createNode(this, config);
        const node = this;

        node.gatewayConfig = RED.nodes.getNode(config.gateway);
        node.mac = config.mac;
        node.deviceType = config.deviceType || '10000000';
        node.defaultMotor = config.defaultMotor || 'B'; // TDBU only
        node.emitOnPush = config.emitOnPush !== false;  // default true

        // Some blinds are installed with their up/down limits flipped: the
        // protocol reports closed=0/open=100, but the motor's physical 0 is
        // the open end and 100 is the closed end. The Motion protocol has no
        // invert-direction command, so we fix it client-side when set.
        node.invertPosition = config.invertPosition === true;

        if (!node.gatewayConfig) {
            node.status({ fill: 'red', shape: 'ring', text: 'no gateway' });
            node.error('motion-blind: missing gateway config');
            return;
        }
        if (!node.mac) {
            node.status({ fill: 'red', shape: 'ring', text: 'no mac' });
            node.error('motion-blind: mac is required');
            return;
        }

        node.status({ fill: 'grey', shape: 'ring', text: 'idle' });

        // Grab or lazily create the blind object
        const gw = node.gatewayConfig.gateway;
        let blind = gw.blind(node.mac);
        // Ensure the stored deviceType matches what the user configured (TDBU vs single)
        blind.deviceType = node.deviceType;

        // Track pending command count. While > 0, we're actively awaiting a
        // round-trip response; the ack path will emit the message, so we
        // suppress the push-path emit for that same update to avoid a duplicate
        // output. (The blind-update event still fires on the gateway for other
        // listeners — we just don't forward it from THIS node.)
        let inFlight = 0;

        // Emit on unsolicited push updates (e.g. after manual remote, a blind
        // finishing its motion, another client's status query).
        const pushHandler = (mac, snap) => {
            if (mac !== node.mac) return;
            if (!node.emitOnPush) return;
            if (inFlight > 0) return; // ack path will emit instead
            const out = maybeInvert(snap, node.invertPosition);
            node.status(buildStatus(out));
            node.send({
                topic: 'status',
                payload: out,
                _source: 'push',
            });
        };
        gw.on('blind-update', pushHandler);

        node.on('input', async (msg, send, done) => {
            // Allow one-off override of mac/deviceType per-message (useful for dynamic flows)
            const mac = msg.mac || node.mac;
            const deviceType = msg.deviceType || node.deviceType;
            const b = gw.blind(mac);
            b.deviceType = deviceType;

            let { action, value, motor } = parseCommand(msg, node.defaultMotor);

            // Apply invert to commands: open<->close swap, and set-position
            // values flip around 50 (100 - value).
            if (node.invertPosition) {
                if (action === 'open') action = 'close';
                else if (action === 'close') action = 'open';
                if (action === 'position' && typeof value === 'number') {
                    value = 100 - value;
                }
                // Note: angle/tilt direction is a separate installer setting
                // and isn't flipped here — positions 0/100 and angles 0/180
                // are independent axes. If a user wants to invert angles too
                // they can add a change node, or we add a second toggle later.
            }

            node.status({ fill: 'blue', shape: 'dot', text: `${action}…` });

            inFlight++;
            try {
                // Make sure we have a token + accessToken before sending a write.
                if (needsAccessToken(action) && !gw.accessToken) {
                    await gw.getDeviceList();
                }

                let ack;
                switch (action) {
                    case 'open':         ack = await b.open(motor); break;
                    case 'close':        ack = await b.close(motor); break;
                    case 'stop':         ack = await b.stop(motor); break;
                    case 'position':     ack = await b.setPosition(value, motor); break;
                    case 'angle':        ack = await b.setAngle(value, motor); break;
                    case 'status':       ack = await b.update(); break;
                    case 'refresh-gateway': ack = await gw.getDeviceList(); break;
                    default:
                        throw new Error(`unknown action "${action}". Expected one of: open, close, stop, position, angle, status, refresh-gateway.`);
                }

                const snap = maybeInvert(b.snapshot(), node.invertPosition);
                node.status(buildStatus(snap));
                send({
                    topic: msg.action || (msg.payload && msg.payload.action) || action,
                    payload: snap,
                    ack,
                    _source: 'ack',
                });
                if (done) done();
            } catch (err) {
                node.status({ fill: 'red', shape: 'ring', text: err.message.slice(0, 30) });
                if (done) done(err); else node.error(err, msg);
            } finally {
                inFlight--;
            }
        });

        node.on('close', (done) => {
            gw.removeListener('blind-update', pushHandler);
            done();
        });
    }

    RED.nodes.registerType('motion-blind', MotionBlindNode);

    // ---------- helpers ----------

    /**
     * Return a snapshot with position and motion-status inverted so that from
     * the Node-RED flow's point of view, 0=closed/100=open and "Opening" means
     * the blind is getting lighter. Non-destructive — original snapshot is
     * left unchanged.
     */
    function maybeInvert(snap, invert) {
        if (!invert || !snap) return snap;
        const out = Object.assign({}, snap);

        // Position: 0<->100 flip, per-motor for TDBU
        if (typeof snap.position === 'number') {
            out.position = 100 - snap.position;
        } else if (snap.position && typeof snap.position === 'object') {
            out.position = {};
            if (typeof snap.position.T === 'number') out.position.T = 100 - snap.position.T;
            if (typeof snap.position.B === 'number') out.position.B = 100 - snap.position.B;
        }

        // Motion status: Opening<->Closing swap. ("Stopped" and "StatusQuery"
        // are direction-agnostic and passed through.)
        const swap = (s) => s === 'Opening' ? 'Closing' : s === 'Closing' ? 'Opening' : s;
        if (typeof snap.status === 'string') {
            out.status = swap(snap.status);
        } else if (snap.status && typeof snap.status === 'object') {
            out.status = {};
            if (snap.status.T) out.status.T = swap(snap.status.T);
            if (snap.status.B) out.status.B = swap(snap.status.B);
        }

        // Tag the output so downstream consumers can tell this was inverted
        // (useful when debugging, or when a flow wants the raw reading too).
        out.inverted = true;
        return out;
    }

    function parseCommand(msg, defaultMotor) {
        // Precedence: explicit msg.action > msg.topic > msg.payload
        let action = null;
        let value;
        let motor = msg.motor || defaultMotor;

        const payload = msg.payload;

        if (msg.action) {
            action = String(msg.action).toLowerCase();
        } else if (typeof payload === 'string') {
            // "open", "close", "stop", "status", "position:50", "angle:90"
            const str = payload.trim().toLowerCase();
            if (str.includes(':')) {
                const [a, v] = str.split(':', 2);
                action = a;
                value = Number(v);
            } else {
                action = str;
            }
        } else if (payload && typeof payload === 'object') {
            action = (payload.action || payload.command || '').toLowerCase();
            if (typeof payload.position === 'number') { action = action || 'position'; value = payload.position; }
            if (typeof payload.angle === 'number')    { action = action || 'angle';    value = payload.angle; }
            if (payload.motor) motor = payload.motor;
        } else if (typeof payload === 'number') {
            // Bare number on payload = set position
            action = 'position';
            value = payload;
        }

        // msg.position / msg.angle can override at top level too
        if (typeof msg.position === 'number') { action = action || 'position'; value = msg.position; }
        if (typeof msg.angle === 'number')    { action = action || 'angle';    value = msg.angle; }

        // Topic fallback
        if (!action && typeof msg.topic === 'string') {
            action = msg.topic.toLowerCase();
        }

        if (!action) action = 'status';

        // Normalise a few aliases
        if (action === 'up')   action = 'open';
        if (action === 'down') action = 'close';
        if (action === 'query' || action === 'read' || action === 'update') action = 'status';
        if (action === 'refresh') action = 'refresh-gateway';

        return { action, value, motor };
    }

    function needsAccessToken(action) {
        return ['open', 'close', 'stop', 'position', 'angle'].includes(action);
    }

    function buildStatus(snap) {
        if (!snap) return { fill: 'grey', shape: 'ring', text: 'idle' };
        if (snap.lastError) return { fill: 'red', shape: 'ring', text: snap.lastError };
        if (!snap.available) return { fill: 'red', shape: 'ring', text: 'unavailable' };

        const pos = (snap.position && typeof snap.position === 'object')
            ? `T${snap.position.T ?? '?'}/B${snap.position.B ?? '?'}`
            : snap.position;
        const stat = (snap.status && typeof snap.status === 'object')
            ? `${snap.status.T || '?'}/${snap.status.B || '?'}`
            : (snap.status || 'ok');

        // Tack on a battery % for at-a-glance visibility. Null means AC or
        // unknown, in which case we skip it entirely.
        let batt = '';
        if (snap.batteryLevel && typeof snap.batteryLevel === 'object') {
            const t = snap.batteryLevel.T, b = snap.batteryLevel.B;
            if (t != null || b != null) batt = ` 🔋${t ?? '?'}/${b ?? '?'}%`;
        } else if (typeof snap.batteryLevel === 'number') {
            batt = ` 🔋${snap.batteryLevel}%`;
        }

        return { fill: 'green', shape: 'dot', text: `${stat} @ ${pos ?? '?'}%${batt}` };
    }
};
