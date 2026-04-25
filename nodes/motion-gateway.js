module.exports = function (RED) {
    const { MotionGateway, MotionMulticast } = require('../lib/motion-blinds');

    function MotionGatewayConfigNode(config) {
        RED.nodes.createNode(this, config);
        const node = this;

        node.ip = config.ip;
        node.useMulticast = config.useMulticast !== false; // default true
        node.multicastInterface = config.multicastInterface || ''; // '' => let OS choose
        node.autoPoll = parseInt(config.autoPoll, 10) || 0; // seconds; 0 = off
        node.verbose = config.verbose === true; // route packet-level logs to warn() for visibility

        // Optional battery-scale overrides (see lib/motion-blinds.js). Empty
        // strings from the editor mean "use the library defaults".
        const batteryScale = {};
        if (config.batteryMinV !== undefined && config.batteryMinV !== '')      batteryScale.min      = parseFloat(config.batteryMinV);
        if (config.batteryMaxV !== undefined && config.batteryMaxV !== '')      batteryScale.max      = parseFloat(config.batteryMaxV);
        if (config.batteryChargingV !== undefined && config.batteryChargingV !== '') batteryScale.charging = parseFloat(config.batteryChargingV);

        // The KEY is sensitive; Node-RED stores it in the credentials file.
        const creds = node.credentials || {};
        node.key = creds.key || config.key || ''; // fallback to config for migration

        if (!node.ip || !node.key) {
            node.error('motion-gateway: ip and key are required');
            return;
        }

        const logger = {
            // Packet-level trace lines live at debug. When verbose is enabled,
            // route them to warn() so they surface in the Node-RED debug
            // sidebar without the user having to edit settings.js to raise
            // the console log level.
            debug: node.verbose ? (m) => node.warn(m) : (m) => node.debug(m),
            info:  (m) => node.log(m),
            warn:  (m) => node.warn(m),
            error: (m) => node.error(m),
        };

        // Shared multicast listener (one per config node)
        node.multicast = null;
        if (node.useMulticast) {
            try {
                node.multicast = new MotionMulticast({
                    interface: node.multicastInterface || undefined,
                });
                node.multicast.start().catch((err) => {
                    node.warn(`multicast listener failed to start: ${err.message}. Falling back to unicast only.`);
                    node.multicast = null;
                });
            } catch (e) {
                node.warn(`multicast setup error: ${e.message}`);
                node.multicast = null;
            }
        }

        node.gateway = new MotionGateway({
            ip: node.ip,
            key: node.key,
            multicast: node.multicast,
            logger,
            batteryScale,
        });

        // Kick off an initial getDeviceList so we have a token + accessToken ready.
        // Do not throw on failure — the blind nodes will retry on demand.
        node._ready = node.gateway.getDeviceList().then(() => {
            node.log(`connected to gateway ${node.ip} (${node.gateway.mac || 'mac pending'})`);
        }).catch((err) => {
            node.warn(`initial getDeviceList failed for ${node.ip}: ${err.message}`);
        });

        // Optional periodic refresh (keeps token fresh, re-discovers devices)
        if (node.autoPoll > 0) {
            node._pollTimer = setInterval(() => {
                node.gateway.getDeviceList().catch((err) => {
                    node.debug(`auto-poll failed: ${err.message}`);
                });
            }, node.autoPoll * 1000);
        }

        node.on('close', (done) => {
            if (node._pollTimer) clearInterval(node._pollTimer);
            try { node.gateway.close(); } catch (_) {}
            if (node.multicast) {
                try { node.multicast.stop(); } catch (_) {}
            }
            done();
        });
    }

    RED.nodes.registerType('motion-gateway', MotionGatewayConfigNode, {
        credentials: {
            key: { type: 'password' },
        },
    });
};
