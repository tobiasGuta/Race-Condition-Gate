package com.bughunter;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class HttpMethodSafetyTest {
    @Test
    void onlyReadOnlyMethodsAreSafeForControlBaseline() {
        assertTrue(HttpMethodSafety.isSafeForControlBaseline("GET"));
        assertTrue(HttpMethodSafety.isSafeForControlBaseline("HEAD"));
        assertTrue(HttpMethodSafety.isSafeForControlBaseline("OPTIONS"));

        assertFalse(HttpMethodSafety.isSafeForControlBaseline("POST"));
        assertFalse(HttpMethodSafety.isSafeForControlBaseline("PUT"));
        assertFalse(HttpMethodSafety.isSafeForControlBaseline("DELETE"));
    }
}
