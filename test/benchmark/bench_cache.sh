#!/bin/bash
# Cache Runtime Benchmark
# Tests: SET/GET operations, throughput, concurrent access, persistence

source "$(dirname "$0")/utils.sh"

CACHE_PORT=19001
RESULTS_FILE="${RESULTS_DIR}/cache_${TIMESTAMP}.json"

echo "[" > "$RESULTS_FILE"
FIRST_RESULT=true

append_result() {
    if [[ $FIRST_RESULT == true ]]; then
        FIRST_RESULT=false
    else
        echo "," >> "$RESULTS_FILE"
    fi
}

# Helper: Send command to cache and get response
cache_cmd() {
    echo "$1" | nc -q1 localhost $CACHE_PORT 2>/dev/null
}

# Test 1: SET operation throughput
test_set_throughput() {
    local num_ops=${1:-10000}
    local value_size=${2:-64}
    local test_name="cache_set_throughput"

    log_section "Test: SET Throughput ($num_ops ops, ${value_size}B values)"

    socketley_cmd create cache bench_cache -p $CACHE_PORT -s
    wait_for_port $CACHE_PORT || { log_error "Cache failed to start"; return 1; }
    sleep 0.5

    local value=$(head -c $value_size /dev/urandom | base64 | head -c $value_size | tr -d '\n')
    local latencies_file=$(mktemp)

    local start_time=$(get_time_ms)

    for i in $(seq 1 $num_ops); do
        local op_start=$(get_time_ms)
        local result=$(echo "SET key$i $value" | nc -q0 localhost $CACHE_PORT 2>/dev/null)
        local op_end=$(get_time_ms)

        if [[ "$result" == "OK" ]]; then
            echo "$((op_end - op_start))" >> "$latencies_file"
        fi

        if [[ $((i % 1000)) -eq 0 ]]; then
            echo -ne "\r  Progress: $i / $num_ops"
        fi
    done
    echo ""

    local end_time=$(get_time_ms)
    local total_time=$((end_time - start_time))
    local ops_sec=$(echo "scale=2; $num_ops * 1000 / $total_time" | bc)
    local throughput_mb=$(echo "scale=2; $num_ops * $value_size / 1024 / 1024 * 1000 / $total_time" | bc)

    local stats=$(calc_stats "$latencies_file")
    rm -f "$latencies_file"

    local avg_lat=$(echo "$stats" | grep -oP 'avg=\K[0-9.]+')
    local p99_lat=$(echo "$stats" | grep -oP 'p99=\K[0-9.]+')

    log_success "Operations: $num_ops SET"
    log_success "Total time: $(format_duration $total_time)"
    log_success "Throughput: $ops_sec ops/sec, ${throughput_mb} MB/sec"
    log_info "Latency: $stats"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "operations" "$num_ops" \
        "value_size_bytes" "$value_size" \
        "total_time_ms" "$total_time" \
        "ops_per_sec" "$ops_sec" \
        "throughput_mb_sec" "$throughput_mb" \
        "avg_latency_ms" "$avg_lat" \
        "p99_latency_ms" "$p99_lat"

    socketley_cmd stop bench_cache
    socketley_cmd remove bench_cache

    echo "$ops_sec $avg_lat $p99_lat"
}

# Test 2: GET operation throughput (pre-populated)
test_get_throughput() {
    local num_ops=${1:-10000}
    local test_name="cache_get_throughput"

    log_section "Test: GET Throughput ($num_ops ops)"

    socketley_cmd create cache bench_cache -p $CACHE_PORT -s
    wait_for_port $CACHE_PORT || { log_error "Cache failed to start"; return 1; }
    sleep 0.5

    # Pre-populate cache
    log_info "Pre-populating cache with $num_ops keys..."
    local value="benchmark_value_64_bytes_padding_padding_padding_pad"
    for i in $(seq 1 $num_ops); do
        echo "SET key$i $value" | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
        if [[ $((i % 1000)) -eq 0 ]]; then
            echo -ne "\r  Populating: $i / $num_ops"
        fi
    done
    echo ""

    local latencies_file=$(mktemp)
    local hits=0
    local misses=0

    local start_time=$(get_time_ms)

    for i in $(seq 1 $num_ops); do
        local op_start=$(get_time_ms)
        local result=$(echo "GET key$i" | nc -q0 localhost $CACHE_PORT 2>/dev/null)
        local op_end=$(get_time_ms)

        if [[ "$result" != "NIL" && -n "$result" ]]; then
            ((hits++))
            echo "$((op_end - op_start))" >> "$latencies_file"
        else
            ((misses++))
        fi

        if [[ $((i % 1000)) -eq 0 ]]; then
            echo -ne "\r  Progress: $i / $num_ops"
        fi
    done
    echo ""

    local end_time=$(get_time_ms)
    local total_time=$((end_time - start_time))
    local ops_sec=$(echo "scale=2; $num_ops * 1000 / $total_time" | bc)

    local stats=$(calc_stats "$latencies_file")
    rm -f "$latencies_file"

    local avg_lat=$(echo "$stats" | grep -oP 'avg=\K[0-9.]+')
    local p99_lat=$(echo "$stats" | grep -oP 'p99=\K[0-9.]+')

    log_success "Operations: $hits hits, $misses misses"
    log_success "Total time: $(format_duration $total_time)"
    log_success "Throughput: $ops_sec ops/sec"
    log_info "Latency: $stats"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "operations" "$num_ops" \
        "hits" "$hits" \
        "misses" "$misses" \
        "total_time_ms" "$total_time" \
        "ops_per_sec" "$ops_sec" \
        "avg_latency_ms" "$avg_lat" \
        "p99_latency_ms" "$p99_lat"

    socketley_cmd stop bench_cache
    socketley_cmd remove bench_cache

    echo "$ops_sec $avg_lat $p99_lat"
}

# Test 3: Mixed workload (80% GET, 20% SET)
test_mixed_workload() {
    local num_ops=${1:-10000}
    local test_name="cache_mixed_workload"

    log_section "Test: Mixed Workload ($num_ops ops, 80% GET / 20% SET)"

    socketley_cmd create cache bench_cache -p $CACHE_PORT -s
    wait_for_port $CACHE_PORT || { log_error "Cache failed to start"; return 1; }
    sleep 0.5

    # Pre-populate with some keys
    local prepop=$((num_ops / 5))
    local value="mixed_workload_test_value_padding_padding_padding"
    log_info "Pre-populating $prepop keys..."
    for i in $(seq 1 $prepop); do
        echo "SET key$i $value" | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    done

    local get_count=0
    local set_count=0
    local key_counter=$((prepop + 1))

    local start_time=$(get_time_ms)

    for i in $(seq 1 $num_ops); do
        local rand=$((RANDOM % 100))
        if [[ $rand -lt 80 ]]; then
            # GET operation (random existing key)
            local key=$((RANDOM % prepop + 1))
            echo "GET key$key" | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
            ((get_count++))
        else
            # SET operation (new key)
            echo "SET key$key_counter $value" | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
            ((key_counter++))
            ((set_count++))
        fi

        if [[ $((i % 1000)) -eq 0 ]]; then
            echo -ne "\r  Progress: $i / $num_ops (GET: $get_count, SET: $set_count)"
        fi
    done
    echo ""

    local end_time=$(get_time_ms)
    local total_time=$((end_time - start_time))
    local ops_sec=$(echo "scale=2; $num_ops * 1000 / $total_time" | bc)

    log_success "Operations: $get_count GET, $set_count SET"
    log_success "Total time: $(format_duration $total_time)"
    log_success "Throughput: $ops_sec ops/sec"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "total_operations" "$num_ops" \
        "get_operations" "$get_count" \
        "set_operations" "$set_count" \
        "total_time_ms" "$total_time" \
        "ops_per_sec" "$ops_sec"

    socketley_cmd stop bench_cache
    socketley_cmd remove bench_cache

    echo "$ops_sec"
}

# Test 4: Concurrent client access
test_concurrent_access() {
    local num_clients=${1:-20}
    local ops_per_client=${2:-500}
    local test_name="cache_concurrent_access"

    log_section "Test: Concurrent Access ($num_clients clients, $ops_per_client ops each)"

    socketley_cmd create cache bench_cache -p $CACHE_PORT -s
    wait_for_port $CACHE_PORT || { log_error "Cache failed to start"; return 1; }
    sleep 0.5

    local value="concurrent_test_value_padding_padding_padding_pad"
    local pids=()
    local results_dir=$(mktemp -d)

    local start_time=$(get_time_ms)

    for c in $(seq 1 $num_clients); do
        (
            local count=0
            for i in $(seq 1 $ops_per_client); do
                local key="client${c}_key${i}"
                local result=$(echo "SET $key $value" | nc -q0 localhost $CACHE_PORT 2>/dev/null)
                [[ "$result" == "OK" ]] && ((count++))
            done
            echo "$count" > "$results_dir/client_$c"
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait "$pid"
    done

    local end_time=$(get_time_ms)
    local total_time=$((end_time - start_time))

    local total_ops=0
    for f in "$results_dir"/client_*; do
        total_ops=$((total_ops + $(cat "$f")))
    done
    rm -rf "$results_dir"

    local ops_sec=$(echo "scale=2; $total_ops * 1000 / $total_time" | bc)

    log_success "Total successful operations: $total_ops"
    log_success "Total time: $(format_duration $total_time)"
    log_success "Aggregate throughput: $ops_sec ops/sec"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "num_clients" "$num_clients" \
        "ops_per_client" "$ops_per_client" \
        "total_ops" "$total_ops" \
        "total_time_ms" "$total_time" \
        "ops_per_sec" "$ops_sec"

    socketley_cmd stop bench_cache
    socketley_cmd remove bench_cache

    echo "$ops_sec"
}

# Test 5: Persistence performance (FLUSH/LOAD)
test_persistence() {
    local num_keys=${1:-5000}
    local test_name="cache_persistence"

    log_section "Test: Persistence Performance ($num_keys keys)"

    local persist_file="/tmp/bench_cache_persist.bin"
    rm -f "$persist_file"

    socketley_cmd create cache bench_cache -p $CACHE_PORT --persistent "$persist_file" -s
    wait_for_port $CACHE_PORT || { log_error "Cache failed to start"; return 1; }
    sleep 0.5

    # Populate cache
    local value="persistence_test_value_padding_padding_padding_p"
    log_info "Populating cache..."
    for i in $(seq 1 $num_keys); do
        echo "SET key$i $value" | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
        if [[ $((i % 1000)) -eq 0 ]]; then
            echo -ne "\r  Populating: $i / $num_keys"
        fi
    done
    echo ""

    # Test FLUSH performance
    local flush_start=$(get_time_ms)
    local flush_result=$(echo "FLUSH" | nc -q1 localhost $CACHE_PORT 2>/dev/null)
    local flush_end=$(get_time_ms)
    local flush_time=$((flush_end - flush_start))

    log_success "FLUSH time: $(format_duration $flush_time)"

    # Check file size
    local file_size=$(stat -c%s "$persist_file" 2>/dev/null || echo 0)
    log_info "Persisted file size: $((file_size / 1024)) KB"

    # Restart cache and test LOAD
    socketley_cmd stop bench_cache
    sleep 0.5
    socketley_cmd run bench_cache
    wait_for_port $CACHE_PORT || { log_error "Cache failed to restart"; return 1; }
    sleep 0.5

    local load_start=$(get_time_ms)
    local load_result=$(echo "LOAD" | nc -q1 localhost $CACHE_PORT 2>/dev/null)
    local load_end=$(get_time_ms)
    local load_time=$((load_end - load_start))

    log_success "LOAD time: $(format_duration $load_time)"

    # Verify data integrity
    local size_result=$(echo "SIZE" | nc -q1 localhost $CACHE_PORT 2>/dev/null)
    log_info "Keys after LOAD: $size_result"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "num_keys" "$num_keys" \
        "flush_time_ms" "$flush_time" \
        "load_time_ms" "$load_time" \
        "file_size_bytes" "$file_size" \
        "keys_restored" "$size_result"

    socketley_cmd stop bench_cache
    socketley_cmd remove bench_cache
    rm -f "$persist_file"

    echo "$flush_time $load_time"
}

# Test 6: Large value handling
test_large_values() {
    local value_sizes=(64 256 1024 4096 16384)
    local ops_per_size=1000
    local test_name="cache_large_values"

    log_section "Test: Large Value Handling"

    socketley_cmd create cache bench_cache -p $CACHE_PORT -s
    wait_for_port $CACHE_PORT || { log_error "Cache failed to start"; return 1; }
    sleep 0.5

    for size in "${value_sizes[@]}"; do
        local value=$(head -c $size /dev/urandom | base64 | head -c $size | tr -d '\n')

        local start_time=$(get_time_ms)
        for i in $(seq 1 $ops_per_size); do
            echo "SET largekey$i $value" | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
        done
        local end_time=$(get_time_ms)

        local total_time=$((end_time - start_time))
        local ops_sec=$(echo "scale=2; $ops_per_size * 1000 / $total_time" | bc)
        local throughput_mb=$(echo "scale=2; $ops_per_size * $size / 1024 / 1024 * 1000 / $total_time" | bc)

        log_success "  ${size}B values: $ops_sec ops/sec, ${throughput_mb} MB/sec"

        append_result
        write_json_result "${test_name}_${size}B" "$RESULTS_FILE" \
            "value_size_bytes" "$size" \
            "operations" "$ops_per_size" \
            "total_time_ms" "$total_time" \
            "ops_per_sec" "$ops_sec" \
            "throughput_mb_sec" "$throughput_mb"

        # Clear for next test
        echo "FLUSH /dev/null" | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    done

    socketley_cmd stop bench_cache
    socketley_cmd remove bench_cache
}

# Test 7: LIST operations throughput
test_list_throughput() {
    local num_ops=${1:-3000}
    local test_name="cache_list_throughput"

    log_section "Test: LIST Throughput ($num_ops ops each for LPUSH/LPOP)"

    socketley_cmd create cache bench_cache -p $CACHE_PORT -s
    wait_for_port $CACHE_PORT || { log_error "Cache failed to start"; return 1; }
    sleep 0.5

    # LPUSH
    local start_time=$(get_time_ms)
    for i in $(seq 1 $num_ops); do
        echo "lpush benchlist item$i" | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    done
    local end_time=$(get_time_ms)
    local lpush_time=$((end_time - start_time))
    local lpush_ops=$(echo "scale=2; $num_ops * 1000 / $lpush_time" | bc)
    log_success "  LPUSH: $lpush_ops ops/sec"

    # LPOP
    start_time=$(get_time_ms)
    for i in $(seq 1 $num_ops); do
        echo "lpop benchlist" | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    done
    end_time=$(get_time_ms)
    local lpop_time=$((end_time - start_time))
    local lpop_ops=$(echo "scale=2; $num_ops * 1000 / $lpop_time" | bc)
    log_success "  LPOP: $lpop_ops ops/sec"

    # LRANGE
    for i in $(seq 1 100); do
        echo "rpush rangelist val$i" | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    done
    start_time=$(get_time_ms)
    for i in $(seq 1 $((num_ops / 10))); do
        echo "lrange rangelist 0 99" | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    done
    end_time=$(get_time_ms)
    local lrange_time=$((end_time - start_time))
    local lrange_ops=$(echo "scale=2; $num_ops / 10 * 1000 / $lrange_time" | bc)
    log_success "  LRANGE 0-99: $lrange_ops ops/sec"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "operations" "$num_ops" \
        "lpush_ops_sec" "$lpush_ops" \
        "lpop_ops_sec" "$lpop_ops" \
        "lrange_ops_sec" "$lrange_ops"

    socketley_cmd stop bench_cache
    socketley_cmd remove bench_cache
}

# Test 8: SET (data structure) operations throughput
test_set_ds_throughput() {
    local num_ops=${1:-3000}
    local test_name="cache_set_ds_throughput"

    log_section "Test: SET (data structure) Throughput ($num_ops ops)"

    socketley_cmd create cache bench_cache -p $CACHE_PORT -s
    wait_for_port $CACHE_PORT || { log_error "Cache failed to start"; return 1; }
    sleep 0.5

    # SADD
    local start_time=$(get_time_ms)
    for i in $(seq 1 $num_ops); do
        echo "sadd benchset member$i" | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    done
    local end_time=$(get_time_ms)
    local sadd_time=$((end_time - start_time))
    local sadd_ops=$(echo "scale=2; $num_ops * 1000 / $sadd_time" | bc)
    log_success "  SADD: $sadd_ops ops/sec"

    # SISMEMBER
    start_time=$(get_time_ms)
    for i in $(seq 1 $num_ops); do
        echo "sismember benchset member$((RANDOM % num_ops + 1))" | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    done
    end_time=$(get_time_ms)
    local sismember_time=$((end_time - start_time))
    local sismember_ops=$(echo "scale=2; $num_ops * 1000 / $sismember_time" | bc)
    log_success "  SISMEMBER: $sismember_ops ops/sec"

    # SCARD
    start_time=$(get_time_ms)
    for i in $(seq 1 $((num_ops / 10))); do
        echo "scard benchset" | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    done
    end_time=$(get_time_ms)
    local scard_time=$((end_time - start_time))
    local scard_ops=$(echo "scale=2; $num_ops / 10 * 1000 / $scard_time" | bc)
    log_success "  SCARD: $scard_ops ops/sec"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "operations" "$num_ops" \
        "sadd_ops_sec" "$sadd_ops" \
        "sismember_ops_sec" "$sismember_ops" \
        "scard_ops_sec" "$scard_ops"

    socketley_cmd stop bench_cache
    socketley_cmd remove bench_cache
}

# Test 9: HASH operations throughput
test_hash_throughput() {
    local num_ops=${1:-3000}
    local test_name="cache_hash_throughput"

    log_section "Test: HASH Throughput ($num_ops ops)"

    socketley_cmd create cache bench_cache -p $CACHE_PORT -s
    wait_for_port $CACHE_PORT || { log_error "Cache failed to start"; return 1; }
    sleep 0.5

    # HSET
    local start_time=$(get_time_ms)
    for i in $(seq 1 $num_ops); do
        echo "hset benchhash field$i value$i" | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    done
    local end_time=$(get_time_ms)
    local hset_time=$((end_time - start_time))
    local hset_ops=$(echo "scale=2; $num_ops * 1000 / $hset_time" | bc)
    log_success "  HSET: $hset_ops ops/sec"

    # HGET
    start_time=$(get_time_ms)
    for i in $(seq 1 $num_ops); do
        echo "hget benchhash field$((RANDOM % num_ops + 1))" | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    done
    end_time=$(get_time_ms)
    local hget_time=$((end_time - start_time))
    local hget_ops=$(echo "scale=2; $num_ops * 1000 / $hget_time" | bc)
    log_success "  HGET: $hget_ops ops/sec"

    # HGETALL
    start_time=$(get_time_ms)
    for i in $(seq 1 $((num_ops / 30))); do
        echo "hgetall benchhash" | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    done
    end_time=$(get_time_ms)
    local hgetall_time=$((end_time - start_time))
    local hgetall_ops=$(echo "scale=2; $num_ops / 30 * 1000 / $hgetall_time" | bc)
    log_success "  HGETALL: $hgetall_ops ops/sec"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "operations" "$num_ops" \
        "hset_ops_sec" "$hset_ops" \
        "hget_ops_sec" "$hget_ops" \
        "hgetall_ops_sec" "$hgetall_ops"

    socketley_cmd stop bench_cache
    socketley_cmd remove bench_cache
}

# Test 10: TTL/Expiry operations throughput
test_ttl_throughput() {
    local num_ops=${1:-3000}
    local test_name="cache_ttl_throughput"

    log_section "Test: TTL/Expiry Throughput ($num_ops ops)"

    socketley_cmd create cache bench_cache -p $CACHE_PORT -s
    wait_for_port $CACHE_PORT || { log_error "Cache failed to start"; return 1; }
    sleep 0.5

    # Pre-populate keys
    for i in $(seq 1 $num_ops); do
        echo "set ttlkey$i val$i" | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    done

    # EXPIRE
    local start_time=$(get_time_ms)
    for i in $(seq 1 $num_ops); do
        echo "expire ttlkey$i 3600" | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    done
    local end_time=$(get_time_ms)
    local expire_time=$((end_time - start_time))
    local expire_ops=$(echo "scale=2; $num_ops * 1000 / $expire_time" | bc)
    log_success "  EXPIRE: $expire_ops ops/sec"

    # TTL
    start_time=$(get_time_ms)
    for i in $(seq 1 $num_ops); do
        echo "ttl ttlkey$((RANDOM % num_ops + 1))" | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    done
    end_time=$(get_time_ms)
    local ttl_time=$((end_time - start_time))
    local ttl_ops=$(echo "scale=2; $num_ops * 1000 / $ttl_time" | bc)
    log_success "  TTL: $ttl_ops ops/sec"

    # PERSIST
    start_time=$(get_time_ms)
    for i in $(seq 1 $num_ops); do
        echo "persist ttlkey$i" | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    done
    end_time=$(get_time_ms)
    local persist_time=$((end_time - start_time))
    local persist_ops=$(echo "scale=2; $num_ops * 1000 / $persist_time" | bc)
    log_success "  PERSIST: $persist_ops ops/sec"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "operations" "$num_ops" \
        "expire_ops_sec" "$expire_ops" \
        "ttl_ops_sec" "$ttl_ops" \
        "persist_ops_sec" "$persist_ops"

    socketley_cmd stop bench_cache
    socketley_cmd remove bench_cache
}

# Main execution
run_cache_benchmarks() {
    log_section "CACHE RUNTIME BENCHMARKS"

    test_set_throughput 3000 64
    test_get_throughput 3000
    test_mixed_workload 3000
    test_concurrent_access 10 200
    test_persistence 2000
    test_large_values
    test_list_throughput 3000
    test_set_ds_throughput 3000
    test_hash_throughput 3000
    test_ttl_throughput 3000

    echo "]" >> "$RESULTS_FILE"

    log_section "Cache Benchmark Complete"
    log_success "Results saved to: $RESULTS_FILE"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    check_binary || exit 1
    check_dependencies || exit 1
    setup_cleanup_trap
    if should_manage_daemon; then
        start_daemon || exit 1
    fi
    run_cache_benchmarks
fi
