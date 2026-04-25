module.exports = function (RED) {
    const { discover } = require('../lib/motion-blinds');

    function MotionDiscoverNode(config) {
        RED.nodes.createNode(this, config);
        const node = this;

        node.duration = parseInt(config.duration, 10) || 5000;
        node.interfaceIp = config.interfaceIp || '';

        node.on('input', async (msg, send, done) => {
            const duration = (typeof msg.duration === 'number') ? msg.duration : node.duration;
            const iface = msg.interface || node.interfaceIp || undefined;

            node.status({ fill: 'blue', shape: 'dot', text: 'searching…' });
            try {
                const result = await discover({ duration, interfaceIp: iface });
                const ips = Object.keys(result);
                node.status({ fill: 'green', shape: 'dot', text: `found ${ips.length}` });

                send({
                    ...msg,
                    topic: 'discover',
                    payload: {
                        count: ips.length,
                        gateways: result, // { ip: { msgType, mac, deviceType, token, data: [...] } }
                    },
                });
                if (done) done();
            } catch (err) {
                node.status({ fill: 'red', shape: 'ring', text: err.message.slice(0, 30) });
                if (done) done(err); else node.error(err, msg);
            }
        });
    }

    RED.nodes.registerType('motion-discover', MotionDiscoverNode);
};
