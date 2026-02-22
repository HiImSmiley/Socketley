#!/bin/bash
# Cache Runtime Benchmark
# Uses pipelined awk|nc connections instead of one nc per operation.

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

# Send a single one-off command and return its response.
cache_cmd() {
    printf '%s\n' "$1" | nc -q1 localhost $CACHE_PORT 2>/dev/null
}

# Pipeline N commands through one TCP connection; return the response text.
# $1 = num_ops, $2 = awk BEGIN program (uses variable i)
pipeline() {
    local num_ops=$1
    local awk_prog=$2
    awk -v n=$num_ops "BEGIN{ $awk_prog }" | nc -q0 localhost $CACHE_PORT 2>/dev/null
}

# Pipeline and count OK/integer responses.
pipeline_count_ok() {
    local num_ops=$1
    local awk_prog=$2
    pipeline "$num_ops" "$awk_prog" | grep -cE '^(OK|[0-9]+)$' || echo 0
}

# Test 1: SET throughput
test_set_throughput() {
    local num_ops=${1:-10000}
    local value_size=${2:-64}
    local test_name="cache_set_throughput"

    log_section "Test: SET Throughput ($num_ops ops, ${value_size}B values)"

    socketley_cmd create cache bench_cache -p $CACHE_PORT -s
    wait_for_port $CACHE_PORT || { log_error "Cache failed to start"; return 1; }
    sleep 0.5

    local value
    value=$(head -c $value_size /dev/urandom | base64 | tr -d '\n=' | head -c $value_size)

    local start_time=$(get_time_ms)
    awk -v n=$num_ops -v v="$value" \
        'BEGIN{ for(i=1;i<=n;i++) printf "SET key%d %s\n",i,v }' \
        | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    local end_time=$(get_time_ms)

    local total_time=$((end_time - start_time))
    local ops_sec=$(echo "scale=2; $num_ops * 1000 / $total_time" | bc)
    local throughput_mb=$(echo "scale=2; $num_ops * $value_size / 1048576.0 * 1000 / $total_time" | bc)

    log_success "Total time: $(format_duration $total_time)"
    log_success "Throughput: $ops_sec ops/sec, ${throughput_mb} MB/sec"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "operations"        "$num_ops" \
        "value_size_bytes"  "$value_size" \
        "total_time_ms"     "$total_time" \
        "ops_per_sec"       "$ops_sec" \
        "throughput_mb_sec" "$throughput_mb"

    socketley_cmd stop bench_cache
    socketley_cmd remove bench_cache

    echo "$ops_sec"
}

# Test 2: GET throughput (pre-populated)
test_get_throughput() {
    local num_ops=${1:-10000}
    local test_name="cache_get_throughput"

    log_section "Test: GET Throughput ($num_ops ops)"

    socketley_cmd create cache bench_cache -p $CACHE_PORT -s
    wait_for_port $CACHE_PORT || { log_error "Cache failed to start"; return 1; }
    sleep 0.5

    local value="benchmark_value_64_bytes_padding_padding_padding_pad"

    # Populate in one pipeline
    log_info "Pre-populating $num_ops keys..."
    awk -v n=$num_ops -v v="$value" \
        'BEGIN{ for(i=1;i<=n;i++) printf "SET key%d %s\n",i,v }' \
        | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    sleep 0.1  # let the server drain the populate pipeline

    # Benchmark GETs
    local start_time=$(get_time_ms)
    awk -v n=$num_ops \
        'BEGIN{ for(i=1;i<=n;i++) printf "GET key%d\n",i }' \
        | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    local end_time=$(get_time_ms)

    local total_time=$((end_time - start_time))
    local ops_sec=$(echo "scale=2; $num_ops * 1000 / $total_time" | bc)

    log_success "Total time: $(format_duration $total_time)"
    log_success "Throughput: $ops_sec ops/sec"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "operations"    "$num_ops" \
        "total_time_ms" "$total_time" \
        "ops_per_sec"   "$ops_sec"

    socketley_cmd stop bench_cache
    socketley_cmd remove bench_cache

    echo "$ops_sec"
}

# Test 3: Mixed workload (80% GET, 20% SET)
test_mixed_workload() {
    local num_ops=${1:-10000}
    local test_name="cache_mixed_workload"

    log_section "Test: Mixed Workload ($num_ops ops, 80% GET / 20% SET)"

    socketley_cmd create cache bench_cache -p $CACHE_PORT -s
    wait_for_port $CACHE_PORT || { log_error "Cache failed to start"; return 1; }
    sleep 0.5

    local value="mixed_workload_test_value_padding_padding_padding"
    local prepop=$((num_ops / 5))

    # Pre-populate
    awk -v n=$prepop -v v="$value" \
        'BEGIN{ for(i=1;i<=n;i++) printf "SET key%d %s\n",i,v }' \
        | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    sleep 0.1

    # Generate mixed command stream and benchmark
    local start_time=$(get_time_ms)
    awk -v n=$num_ops -v pre=$prepop -v v="$value" 'BEGIN{
        srand(42)
        new_key = pre + 1
        for(i=1;i<=n;i++) {
            if(rand() < 0.8)
                printf "GET key%d\n", int(rand()*pre)+1
            else
                printf "SET key%d %s\n", new_key++, v
        }
    }' | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    local end_time=$(get_time_ms)

    local total_time=$((end_time - start_time))
    local ops_sec=$(echo "scale=2; $num_ops * 1000 / $total_time" | bc)

    log_success "Total time: $(format_duration $total_time)"
    log_success "Throughput: $ops_sec ops/sec"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "total_operations" "$num_ops" \
        "total_time_ms"    "$total_time" \
        "ops_per_sec"      "$ops_sec"

    socketley_cmd stop bench_cache
    socketley_cmd remove bench_cache

    echo "$ops_sec"
}

# Test 4: Concurrent client access (N background awk|nc pipelines)
test_concurrent_access() {
    local num_clients=${1:-20}
    local ops_per_client=${2:-2000}
    local test_name="cache_concurrent_access"

    log_section "Test: Concurrent Access ($num_clients clients × $ops_per_client ops)"

    socketley_cmd create cache bench_cache -p $CACHE_PORT -s
    wait_for_port $CACHE_PORT || { log_error "Cache failed to start"; return 1; }
    sleep 0.5

    local value="concurrent_test_value_padding_padding_padding_pad"
    local pids=()

    local start_time=$(get_time_ms)

    for c in $(seq 1 $num_clients); do
        awk -v n=$ops_per_client -v c=$c -v v="$value" \
            'BEGIN{ for(i=1;i<=n;i++) printf "SET c%d_key%d %s\n",c,i,v }' \
            | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1 &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do wait "$pid"; done

    local end_time=$(get_time_ms)
    local total_time=$((end_time - start_time))
    local total_ops=$((num_clients * ops_per_client))
    local ops_sec=$(echo "scale=2; $total_ops * 1000 / $total_time" | bc)

    log_success "Total time: $(format_duration $total_time)"
    log_success "Aggregate throughput: $ops_sec ops/sec"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "num_clients"      "$num_clients" \
        "ops_per_client"   "$ops_per_client" \
        "total_ops"        "$total_ops" \
        "total_time_ms"    "$total_time" \
        "ops_per_sec"      "$ops_sec"

    socketley_cmd stop bench_cache
    socketley_cmd remove bench_cache

    echo "$ops_sec"
}

# Test 5: Persistence (FLUSH / LOAD)
test_persistence() {
    local num_keys=${1:-10000}
    local test_name="cache_persistence"

    log_section "Test: Persistence ($num_keys keys)"

    local persist_file="/tmp/bench_cache_persist.bin"
    rm -f "$persist_file"

    socketley_cmd create cache bench_cache -p $CACHE_PORT --persistent "$persist_file" -s
    wait_for_port $CACHE_PORT || { log_error "Cache failed to start"; return 1; }
    sleep 0.5

    local value="persistence_test_value_padding_padding_padding_p"

    log_info "Populating $num_keys keys..."
    awk -v n=$num_keys -v v="$value" \
        'BEGIN{ for(i=1;i<=n;i++) printf "SET key%d %s\n",i,v }' \
        | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    sleep 0.1

    # FLUSH
    local flush_start=$(get_time_ms)
    cache_cmd "FLUSH" >/dev/null
    local flush_end=$(get_time_ms)
    local flush_time=$((flush_end - flush_start))
    log_success "FLUSH time: $(format_duration $flush_time)"

    local file_size=$(stat -c%s "$persist_file" 2>/dev/null || echo 0)
    log_info "Persisted file: $((file_size / 1024)) KB"

    # Restart and LOAD
    socketley_cmd stop bench_cache
    sleep 0.5
    socketley_cmd start bench_cache
    wait_for_port $CACHE_PORT || { log_error "Cache failed to restart"; return 1; }
    sleep 0.5

    local load_start=$(get_time_ms)
    cache_cmd "LOAD" >/dev/null
    local load_end=$(get_time_ms)
    local load_time=$((load_end - load_start))
    log_success "LOAD time: $(format_duration $load_time)"

    local size_result=$(cache_cmd "SIZE")
    log_info "Keys after LOAD: $size_result"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "num_keys"        "$num_keys" \
        "flush_time_ms"   "$flush_time" \
        "load_time_ms"    "$load_time" \
        "file_size_bytes" "$file_size" \
        "keys_restored"   "$size_result"

    socketley_cmd stop bench_cache
    socketley_cmd remove bench_cache
    rm -f "$persist_file"

    echo "$flush_time $load_time"
}

# Test 6: Large value throughput (multiple sizes)
test_large_values() {
    local value_sizes=(64 256 1024 4096)
    local ops_per_size=2000
    local test_name="cache_large_values"

    log_section "Test: Large Value Throughput"

    socketley_cmd create cache bench_cache -p $CACHE_PORT -s
    wait_for_port $CACHE_PORT || { log_error "Cache failed to start"; return 1; }
    sleep 0.5

    for size in "${value_sizes[@]}"; do
        local value
        value=$(head -c $size /dev/urandom | base64 | tr -d '\n=' | head -c $size)

        local start_time=$(get_time_ms)
        awk -v n=$ops_per_size -v v="$value" \
            'BEGIN{ for(i=1;i<=n;i++) printf "SET lk%d %s\n",i,v }' \
            | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
        local end_time=$(get_time_ms)

        local total_time=$((end_time - start_time))
        local ops_sec=$(echo "scale=2; $ops_per_size * 1000 / $total_time" | bc)
        local throughput_mb=$(echo "scale=2; $ops_per_size * $size / 1048576.0 * 1000 / $total_time" | bc)

        log_success "  ${size}B: $ops_sec ops/sec, ${throughput_mb} MB/sec"

        append_result
        write_json_result "${test_name}_${size}B" "$RESULTS_FILE" \
            "value_size_bytes"  "$size" \
            "operations"        "$ops_per_size" \
            "total_time_ms"     "$total_time" \
            "ops_per_sec"       "$ops_sec" \
            "throughput_mb_sec" "$throughput_mb"

        # Flush between sizes
        cache_cmd "FLUSH /dev/null" >/dev/null
        sleep 0.05
    done

    socketley_cmd stop bench_cache
    socketley_cmd remove bench_cache
}

# Test 7: LIST operations
test_list_throughput() {
    local num_ops=${1:-5000}
    local test_name="cache_list_throughput"

    log_section "Test: LIST Throughput ($num_ops ops)"

    socketley_cmd create cache bench_cache -p $CACHE_PORT -s
    wait_for_port $CACHE_PORT || { log_error "Cache failed to start"; return 1; }
    sleep 0.5

    # LPUSH
    local start_time=$(get_time_ms)
    awk -v n=$num_ops 'BEGIN{ for(i=1;i<=n;i++) printf "LPUSH benchlist item%d\n",i }' \
        | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    local end_time=$(get_time_ms)
    local lpush_time=$((end_time - start_time))
    local lpush_ops=$(echo "scale=2; $num_ops * 1000 / $lpush_time" | bc)
    log_success "  LPUSH: $lpush_ops ops/sec"

    # LPOP
    start_time=$(get_time_ms)
    awk -v n=$num_ops 'BEGIN{ for(i=1;i<=n;i++) printf "LPOP benchlist\n" }' \
        | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    end_time=$(get_time_ms)
    local lpop_time=$((end_time - start_time))
    local lpop_ops=$(echo "scale=2; $num_ops * 1000 / $lpop_time" | bc)
    log_success "  LPOP: $lpop_ops ops/sec"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "operations"    "$num_ops" \
        "lpush_ops_sec" "$lpush_ops" \
        "lpop_ops_sec"  "$lpop_ops"

    socketley_cmd stop bench_cache
    socketley_cmd remove bench_cache
}

# Test 8: SET data structure operations
test_set_ds_throughput() {
    local num_ops=${1:-5000}
    local test_name="cache_set_ds_throughput"

    log_section "Test: SET (data structure) Throughput ($num_ops ops)"

    socketley_cmd create cache bench_cache -p $CACHE_PORT -s
    wait_for_port $CACHE_PORT || { log_error "Cache failed to start"; return 1; }
    sleep 0.5

    # SADD
    local start_time=$(get_time_ms)
    awk -v n=$num_ops 'BEGIN{ for(i=1;i<=n;i++) printf "SADD benchset member%d\n",i }' \
        | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    local end_time=$(get_time_ms)
    local sadd_time=$((end_time - start_time))
    local sadd_ops=$(echo "scale=2; $num_ops * 1000 / $sadd_time" | bc)
    log_success "  SADD: $sadd_ops ops/sec"

    # SISMEMBER
    start_time=$(get_time_ms)
    awk -v n=$num_ops 'BEGIN{ srand(42); for(i=1;i<=n;i++) printf "SISMEMBER benchset member%d\n",int(rand()*n)+1 }' \
        | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    end_time=$(get_time_ms)
    local sismember_time=$((end_time - start_time))
    local sismember_ops=$(echo "scale=2; $num_ops * 1000 / $sismember_time" | bc)
    log_success "  SISMEMBER: $sismember_ops ops/sec"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "operations"        "$num_ops" \
        "sadd_ops_sec"      "$sadd_ops" \
        "sismember_ops_sec" "$sismember_ops"

    socketley_cmd stop bench_cache
    socketley_cmd remove bench_cache
}

# Test 9: HASH operations
test_hash_throughput() {
    local num_ops=${1:-5000}
    local test_name="cache_hash_throughput"

    log_section "Test: HASH Throughput ($num_ops ops)"

    socketley_cmd create cache bench_cache -p $CACHE_PORT -s
    wait_for_port $CACHE_PORT || { log_error "Cache failed to start"; return 1; }
    sleep 0.5

    # HSET
    local start_time=$(get_time_ms)
    awk -v n=$num_ops 'BEGIN{ for(i=1;i<=n;i++) printf "HSET benchhash field%d value%d\n",i,i }' \
        | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    local end_time=$(get_time_ms)
    local hset_time=$((end_time - start_time))
    local hset_ops=$(echo "scale=2; $num_ops * 1000 / $hset_time" | bc)
    log_success "  HSET: $hset_ops ops/sec"

    # HGET
    start_time=$(get_time_ms)
    awk -v n=$num_ops 'BEGIN{ srand(42); for(i=1;i<=n;i++) printf "HGET benchhash field%d\n",int(rand()*n)+1 }' \
        | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    end_time=$(get_time_ms)
    local hget_time=$((end_time - start_time))
    local hget_ops=$(echo "scale=2; $num_ops * 1000 / $hget_time" | bc)
    log_success "  HGET: $hget_ops ops/sec"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "operations"   "$num_ops" \
        "hset_ops_sec" "$hset_ops" \
        "hget_ops_sec" "$hget_ops"

    socketley_cmd stop bench_cache
    socketley_cmd remove bench_cache
}

# Test 10: TTL operations
test_ttl_throughput() {
    local num_ops=${1:-5000}
    local test_name="cache_ttl_throughput"

    log_section "Test: TTL Throughput ($num_ops ops)"

    socketley_cmd create cache bench_cache -p $CACHE_PORT -s
    wait_for_port $CACHE_PORT || { log_error "Cache failed to start"; return 1; }
    sleep 0.5

    # Populate keys
    awk -v n=$num_ops 'BEGIN{ for(i=1;i<=n;i++) printf "SET ttlkey%d val%d\n",i,i }' \
        | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    sleep 0.1

    # EXPIRE
    local start_time=$(get_time_ms)
    awk -v n=$num_ops 'BEGIN{ for(i=1;i<=n;i++) printf "EXPIRE ttlkey%d 3600\n",i }' \
        | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    local end_time=$(get_time_ms)
    local expire_time=$((end_time - start_time))
    local expire_ops=$(echo "scale=2; $num_ops * 1000 / $expire_time" | bc)
    log_success "  EXPIRE: $expire_ops ops/sec"

    # TTL
    start_time=$(get_time_ms)
    awk -v n=$num_ops 'BEGIN{ srand(42); for(i=1;i<=n;i++) printf "TTL ttlkey%d\n",int(rand()*n)+1 }' \
        | nc -q0 localhost $CACHE_PORT >/dev/null 2>&1
    end_time=$(get_time_ms)
    local ttl_time=$((end_time - start_time))
    local ttl_ops=$(echo "scale=2; $num_ops * 1000 / $ttl_time" | bc)
    log_success "  TTL: $ttl_ops ops/sec"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "operations"     "$num_ops" \
        "expire_ops_sec" "$expire_ops" \
        "ttl_ops_sec"    "$ttl_ops"

    socketley_cmd stop bench_cache
    socketley_cmd remove bench_cache
}

# Main
run_cache_benchmarks() {
    log_section "CACHE RUNTIME BENCHMARKS"

    test_set_throughput     10000 64
    test_get_throughput     10000
    test_mixed_workload     10000
    test_concurrent_access  20 2000
    test_persistence        10000
    test_large_values
    test_list_throughput    5000
    test_set_ds_throughput  5000
    test_hash_throughput    5000
    test_ttl_throughput     5000

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
