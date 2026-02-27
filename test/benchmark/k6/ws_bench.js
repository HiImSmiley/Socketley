import ws from 'k6/ws';
import { check } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// Custom metrics
const wsConnections = new Counter('ws_connections');
const wsConnectionsFailed = new Counter('ws_connections_failed');
const wsMessages = new Counter('ws_messages_sent');
const wsEchoes = new Counter('ws_echoes_received');
const wsRTT = new Trend('ws_rtt', true);
const wsErrorRate = new Rate('ws_error_rate');

const WS_URL = __ENV.WS_URL || 'ws://localhost:19021';
const MSGS_PER_VU = parseInt(__ENV.MSGS_PER_VU || '200');
const MSG_INTERVAL_MS = parseInt(__ENV.MSG_INTERVAL_MS || '1');

export const options = {
    stages: [
        { duration: '5s',  target: 50 },   // Ramp-up
        { duration: '15s', target: 50 },   // Sustained
        { duration: '5s',  target: 200 },  // High concurrency
        { duration: '10s', target: 200 },  // Sustained spike
        { duration: '5s',  target: 1 },    // Cooldown
    ],
    summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(90)', 'p(95)', 'p(99)'],
    thresholds: {
        'ws_rtt':        ['p(95)<200'],
        'ws_error_rate': ['rate<0.05'],
    },
};

export default function () {
    const res = ws.connect(WS_URL, {}, function (socket) {
        let sent = 0;
        let received = 0;
        const sendTimes = {};

        socket.on('open', function () {
            wsConnections.add(1);
            wsErrorRate.add(0);

            // Send timestamped messages in a tight loop
            let done = false;
            socket.setInterval(function () {
                if (done) return;
                if (sent >= MSGS_PER_VU) {
                    done = true;
                    // Allow time for remaining echoes before closing
                    socket.setTimeout(function () {
                        socket.close();
                    }, 500);
                    return;
                }

                const seq = sent;
                const ts = Date.now();
                const msg = `${seq}:${ts}`;
                sendTimes[seq] = ts;
                socket.send(msg);
                wsMessages.add(1);
                sent++;
            }, MSG_INTERVAL_MS);
        });

        socket.on('message', function (data) {
            // Echo comes back as "seq:timestamp" — measure RTT
            const parts = data.split(':');
            if (parts.length >= 2) {
                const seq = parseInt(parts[0]);
                const sendTime = sendTimes[seq];
                if (sendTime) {
                    const rtt = Date.now() - sendTime;
                    wsRTT.add(rtt);
                    delete sendTimes[seq];
                }
            }
            wsEchoes.add(1);
            received++;
        });

        socket.on('error', function (e) {
            wsConnectionsFailed.add(1);
            wsErrorRate.add(1);
        });

        socket.on('close', function () {
            // Connection closed
        });

        // Timeout: close after max duration to avoid hanging VUs
        socket.setTimeout(function () {
            socket.close();
        }, 15000);
    });

    check(res, {
        'WS status is 101': (r) => r && r.status === 101,
    });
}
