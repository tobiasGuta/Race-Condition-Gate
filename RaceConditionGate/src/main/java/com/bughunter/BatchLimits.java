package com.bughunter;

final class BatchLimits {
    static final int MAX_TOTAL_OPERATIONS = 500;
    static final int HIGH_TOTAL_OPERATIONS_WARNING = 200;

    private BatchLimits() {
    }

    static int totalOperations(int requestCount, int totalAttempts) {
        return requestCount * totalAttempts;
    }

    static boolean exceedsMaximum(int requestCount, int totalAttempts) {
        return totalOperations(requestCount, totalAttempts) > MAX_TOTAL_OPERATIONS;
    }

    static boolean requiresWarning(int requestCount, int totalAttempts) {
        int totalOperations = totalOperations(requestCount, totalAttempts);
        return totalOperations > HIGH_TOTAL_OPERATIONS_WARNING && totalOperations <= MAX_TOTAL_OPERATIONS;
    }
}
