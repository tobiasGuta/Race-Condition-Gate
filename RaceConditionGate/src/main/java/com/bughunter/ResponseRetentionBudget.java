package com.bughunter;

import java.util.concurrent.atomic.AtomicInteger;

final class ResponseRetentionBudget {
    static final int MAX_RETAINED_RESPONSE_BODY_BYTES = 1024 * 1024;
    static final int MAX_RETAINED_RESPONSE_BODY_KB = MAX_RETAINED_RESPONSE_BODY_BYTES / 1024;
    static final int MAX_PENDING_ATTEMPT_BYTES = 32 * 1024 * 1024;

    private final int maxPerResponseBytes;
    private final int maxPerAttemptBytes;
    private final AtomicInteger reservedBytes = new AtomicInteger(0);

    ResponseRetentionBudget(int maxPerResponseBytes) {
        this(maxPerResponseBytes, MAX_PENDING_ATTEMPT_BYTES);
    }

    ResponseRetentionBudget(int maxPerResponseBytes, int maxPerAttemptBytes) {
        this.maxPerResponseBytes = Math.min(Math.max(maxPerResponseBytes, 0), MAX_RETAINED_RESPONSE_BODY_BYTES);
        this.maxPerAttemptBytes = Math.max(maxPerAttemptBytes, 0);
    }

    int maxPerResponseBytes() {
        return maxPerResponseBytes;
    }

    int maxPerAttemptBytes() {
        return maxPerAttemptBytes;
    }

    int reservedBytes() {
        return reservedBytes.get();
    }

    boolean exceedsPerResponseLimit(int bodyBytes) {
        return maxPerResponseBytes <= 0 || bodyBytes > maxPerResponseBytes;
    }

    boolean tryReserve(int bodyBytes) {
        if (exceedsPerResponseLimit(bodyBytes) || bodyBytes < 0) {
            return false;
        }

        while (true) {
            int current = reservedBytes.get();
            int next = current + bodyBytes;
            if (next > maxPerAttemptBytes) {
                return false;
            }
            if (reservedBytes.compareAndSet(current, next)) {
                return true;
            }
        }
    }
}
