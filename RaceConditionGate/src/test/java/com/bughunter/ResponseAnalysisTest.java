package com.bughunter;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ResponseAnalysisTest {
    @Test
    void extractsTopLevelJsonFieldsForExpressions() {
        String body = "{\"status\":\"redeemed\",\"balance\":25,\"success\":true}";

        assertEquals("redeemed", ResponseAnalysis.extractJsonValue(body, "$.status"));
        assertEquals("25", ResponseAnalysis.extractJsonValue(body, "$.balance"));
        assertEquals("true", ResponseAnalysis.extractJsonValue(body, "$.success"));
        assertEquals("", ResponseAnalysis.extractJsonValue(body, "$.missing"));
    }

    @Test
    void successExpressionSupportsStatusBodyHeaderAndJsonTerms() {
        ResponseFingerprint current = fingerprint((short) 200, Map.of("location", "/done"), Map.of("$.balance", "10"));
        ResponseFingerprint baseline = fingerprint((short) 200, Map.of("location", "/start"), Map.of("$.balance", "5"));
        SuccessExpression expression = SuccessExpression.parse(
                "status == 200 and body contains \"redeemed\" and header Location contains \"/done\" and json $.balance changed"
        );

        assertTrue(expression.matches(current, baseline, "coupon redeemed"));
    }

    @Test
    void summarizeDifferenceIncludesConfiguredSignals() {
        ResponseFingerprint baseline = new ResponseFingerprint(
                (short) 403,
                12,
                "aaa",
                Map.of("location", "/login"),
                Map.of("redeemed", 0),
                Map.of("$.balance", "5"),
                "/login",
                100,
                1
        );
        ResponseFingerprint current = new ResponseFingerprint(
                (short) 200,
                42,
                "bbb",
                Map.of("location", "/success"),
                Map.of("redeemed", 1),
                Map.of("$.balance", "10"),
                "/success",
                200,
                2
        );

        String summary = ResponseAnalysis.summarizeDifference(baseline, current, true);

        assertTrue(summary.contains("success expression matched"));
        assertTrue(summary.contains("status 403 -> 200"));
        assertTrue(summary.contains("body hash changed"));
        assertTrue(summary.contains("keyword redeemed 0 -> 1"));
        assertTrue(summary.contains("json $.balance changed"));
    }

    private static ResponseFingerprint fingerprint(short status, Map<String, String> headers, Map<String, String> jsonFields) {
        return new ResponseFingerprint(status, 0, "hash", headers, Map.of(), jsonFields, headers.getOrDefault("location", ""), 0, 0);
    }
}
