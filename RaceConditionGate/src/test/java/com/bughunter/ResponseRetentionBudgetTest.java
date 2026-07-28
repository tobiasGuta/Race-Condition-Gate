package com.bughunter;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ResponseRetentionBudgetTest {
    @Test
    void clampsPerResponseLimitToOneMegabyte() {
        ResponseRetentionBudget budget = new ResponseRetentionBudget(10 * 1024 * 1024);

        assertEquals(1024 * 1024, budget.maxPerResponseBytes());
        assertTrue(budget.tryReserve(1024 * 1024));
        assertFalse(budget.tryReserve(1024 * 1024 + 1));
    }

    @Test
    void rejectsRetentionWhenAttemptBudgetWouldBeExceeded() {
        ResponseRetentionBudget budget = new ResponseRetentionBudget(1024, 2048);

        assertTrue(budget.tryReserve(1024));
        assertTrue(budget.tryReserve(1024));
        assertFalse(budget.tryReserve(1));
        assertEquals(2048, budget.reservedBytes());
    }

    @Test
    void zeroPerResponseLimitStoresMetadataOnly() {
        ResponseRetentionBudget budget = new ResponseRetentionBudget(0, 2048);

        assertTrue(budget.exceedsPerResponseLimit(0));
        assertFalse(budget.tryReserve(0));
        assertEquals(0, budget.reservedBytes());
    }
}
