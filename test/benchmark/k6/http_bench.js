import http from 'k6/http';
import exec from 'k6/execution';
import { check } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// ─── Why this script reports per stage ──────────────────────────────────────
//
// It reported one p50 and one p99 for the whole run:
//
//     k6_http_disk    p50 5.06 ms   p99 57.96 ms
//     k6_http_cached  p50 2.85 ms   p99 53.27 ms
//
// Both p99s are +51 ms over their own median, and it reads as a latency defect
// that --http-cache does nothing for.  It is neither.  The load profile below
// deliberately doubles to 200 VUs against a single-threaded server, and the
// request mix includes a 100 KB file.  The p99 is a percentile over a saturated
// phase and an unsaturated one mixed together, so it is dominated by whichever
// phase happens to contribute the slowest 1% -- which is the spike, every time,
// by construction.  It cannot move when the server gets faster and it cannot
// stay put when the stage table is edited, so it is not a tail metric of
// anything.
//
// Two numbers were wanted and one was printed.  Now each stage keeps its own
// Trend, so the steady-state tail and the spike tail are separate figures and a
// real tail regression in steady state is visible instead of buried under a
// spike this file asked for.
//
// The whole-run aggregate is still exported, because k6 computes it anyway and
// removing it would break older comparisons; bench_k6_http.sh prints it labelled
// as what it is.

// One table.  options.stages and the bucket boundaries are both derived from
// it, so a stage cannot be added to the load profile and left out of the
// reporting -- which is the failure this whole change is about, one level up.
//
// `steady` is the figure to quote for latency; `spike` is the figure to quote
// for behaviour under a doubling.  The two ramps are transitional by
// construction and are reported separately rather than folded into either.
const STAGES = [
    { name: 'ramp',       duration: '5s',  target: 100, transitional: true  },
    { name: 'steady',     duration: '15s', target: 100, transitional: false },
    { name: 'spike_ramp', duration: '5s',  target: 200, transitional: true  },
    { name: 'spike',      duration: '10s', target: 200, transitional: false },
    { name: 'cooldown',   duration: '5s',  target: 1,   transitional: true  },
];

function seconds(d) {
    const m = /^(\d+(?:\.\d+)?)(ms|s|m)$/.exec(d);
    if (!m) throw new Error('unparsable stage duration: ' + d);
    const v = parseFloat(m[1]);
    return m[2] === 'ms' ? v / 1000 : (m[2] === 'm' ? v * 60 : v);
}

// Cumulative end of each stage, in milliseconds since the run started.
const STAGE_END_MS = [];
{
    let acc = 0;
    for (const st of STAGES) { acc += seconds(st.duration) * 1000; STAGE_END_MS.push(acc); }
}

const stageTrend = {};
const stageReqs = {};
for (const st of STAGES) {
    stageTrend[st.name] = new Trend('stage_' + st.name + '_duration', true);
    stageReqs[st.name] = new Counter('stage_' + st.name + '_reqs');
}

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
    stages: STAGES.map((s) => ({ duration: s.duration, target: s.target })),
    summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(90)', 'p(95)', 'p(99)', 'count'],
    thresholds: {
        // The threshold moves onto the steady stage for the same reason the
        // reporting did: 'http_req_duration p(95)<100' over the whole run is a
        // threshold on a mixture, and it fails or passes according to how long
        // the spike was told to last.
        'stage_steady_duration': ['p(95)<100'],
        'http_req_failed':       ['rate<0.01'],
    },
};

function currentStage() {
    const ms = exec.instance.currentTestRunDuration;
    for (let i = 0; i < STAGE_END_MS.length; i++) {
        if (ms <= STAGE_END_MS[i]) return STAGES[i].name;
    }
    // Past the last boundary: k6 lets iterations already in flight finish, and
    // attributing them to a stage that had ended would put the teardown's
    // stragglers into the cooldown's percentiles.  They go to the last stage,
    // which is what they belong to, and the count column shows how few they are.
    return STAGES[STAGES.length - 1].name;
}

export default function () {
    const ep = ENDPOINTS[__ITER % ENDPOINTS.length];
    const res = http.get(`${BASE_URL}${ep.path}`);

    const ok = check(res, {
        'status is 200': (r) => r.status === 200,
        'body not empty': (r) => r.body && r.body.length > 0,
    });

    ep.trend.add(res.timings.duration);

    // Bucketed on the clock at the point the sample is recorded, so a request
    // that started in one stage and finished in the next counts where it
    // finished.  The alternative is to read the clock before the request and
    // attribute a spike-length response to the quiet stage that issued it.
    const st = currentStage();
    stageTrend[st].add(res.timings.duration);
    stageReqs[st].add(1);

    if (ok) {
        requestsOK.add(1);
        errorRate.add(0);
    } else {
        requestsFailed.add(1);
        errorRate.add(1);
    }
}
