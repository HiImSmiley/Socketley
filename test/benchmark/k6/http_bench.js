import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// Custom metrics
const requestsOK = new Counter('requests_ok');
const requestsFailed = new Counter('requests_failed');
const errorRate = new Rate('error_rate');
const indexDuration = new Trend('index_duration', true);
const cssDuration = new Trend('css_duration', true);
const jsonDuration = new Trend('json_duration', true);
const largeDuration = new Trend('large_duration', true);

const BASE_URL = __ENV.BASE_URL || 'http://localhost:19020';

const ENDPOINTS = [
    { path: '/index.html', trend: indexDuration, name: 'index.html' },
    { path: '/style.css',  trend: cssDuration,   name: 'style.css' },
    { path: '/data.json',  trend: jsonDuration,   name: 'data.json' },
    { path: '/large.bin',  trend: largeDuration,  name: 'large.bin' },
];

export const options = {
    stages: [
        { duration: '10s', target: 50 },   // Ramp-up
        { duration: '20s', target: 50 },   // Sustained load
        { duration: '10s', target: 200 },  // Spike
        { duration: '5s',  target: 1 },    // Cooldown
    ],
    summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(90)', 'p(95)', 'p(99)'],
    thresholds: {
        'http_req_duration': ['p(95)<50'],
        'http_req_failed':   ['rate<0.01'],
    },
};

export default function () {
    const ep = ENDPOINTS[__ITER % ENDPOINTS.length];
    const res = http.get(`${BASE_URL}${ep.path}`);

    const ok = check(res, {
        'status is 200': (r) => r.status === 200,
        'body not empty': (r) => r.body && r.body.length > 0,
    });

    ep.trend.add(res.timings.duration);

    if (ok) {
        requestsOK.add(1);
        errorRate.add(0);
    } else {
        requestsFailed.add(1);
        errorRate.add(1);
    }
}
