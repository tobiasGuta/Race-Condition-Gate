package com.bughunter;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class BatchLimitsTest {
    @Test
    void calculatesTotalOperationsAcrossAttempts() {
        assertEquals(500, BatchLimits.totalOperations(50, 10));
    }

    @Test
    void rejectsBatchesAboveMaximumTotalOperations() {
        assertFalse(BatchLimits.exceedsMaximum(50, 10));
        assertTrue(BatchLimits.exceedsMaximum(50, 11));
    }

    @Test
    void warnsOnlyForHighButAllowedTotalOperations() {
        assertFalse(BatchLimits.requiresWarning(20, 10));
        assertTrue(BatchLimits.requiresWarning(20, 11));
        assertFalse(BatchLimits.requiresWarning(50, 11));
    }
}
