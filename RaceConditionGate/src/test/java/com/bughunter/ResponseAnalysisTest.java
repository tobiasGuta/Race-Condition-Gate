package com.bughunter;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

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
    void successExpressionRejectsUnknownTerms() {
        SuccessExpression.InvalidExpressionException error = assertThrows(
                SuccessExpression.InvalidExpressionException.class,
                () -> SuccessExpression.parse("stats == 200")
        );

        assertTrue(error.getMessage().contains("stats == 200"));
        assertTrue(error.getMessage().contains("unsupported success-expression term"));
    }

    @Test
    void successExpressionTracksAndMatchesCustomHeaders() {
        SuccessExpression expression = SuccessExpression.parse("header X-RateLimit-Remaining contains \"0\"");
        ResponseFingerprint current = fingerprint((short) 200, Map.of("x-ratelimit-remaining", "0"), Map.of());

        assertEquals(List.of("x-ratelimit-remaining"), expression.referencedHeaders());
        assertTrue(expression.matches(current, null, ""));
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
                1,
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
                2,
                2
        );

        String summary = ResponseAnalysis.summarizeDifference(baseline, current, true);

        assertTrue(summary.contains("success expression matched"));
        assertTrue(summary.contains("status 403 -> 200"));
        assertTrue(summary.contains("body hash changed"));
        assertTrue(summary.contains("keyword redeemed 0 -> 1"));
        assertTrue(summary.contains("json $.balance changed"));
    }

    @Test
    void summarizeDifferenceDetectsHeaderDisappearance() {
        ResponseFingerprint baseline = fingerprint((short) 302, Map.of("location", "/login"), Map.of());
        ResponseFingerprint current = fingerprint((short) 302, Map.of(), Map.of());

        String summary = ResponseAnalysis.summarizeDifference(baseline, current, false);

        assertTrue(summary.contains("header location changed"));
        assertTrue(summary.contains("redirect changed"));
    }

    @Test
    void clusterResponsesMarksEightTwoAsMinorityCluster() {
        ResponseFingerprint conflict = new ResponseFingerprint(
                (short) 409,
                80,
                "a23e91",
                Map.of("content-type", "application/json"),
                Map.of(),
                Map.of(),
                "",
                100,
                1,
                1
        );
        ResponseFingerprint success = new ResponseFingerprint(
                (short) 200,
                120,
                "42d1fe",
                Map.of("content-type", "application/json"),
                Map.of(),
                Map.of(),
                "",
                110,
                19,
                19
        );

        var fingerprints = new java.util.ArrayList<ResponseFingerprint>();
        for (int i = 0; i < 18; i++) {
            fingerprints.add(conflict);
        }
        fingerprints.add(success);
        fingerprints.add(success);

        var clusters = ResponseAnalysis.clusterResponses(fingerprints);
        String summary = ResponseAnalysis.summarizeClusters(clusters);

        assertEquals(2, clusters.size());
        assertEquals("A", clusters.get(0).label());
        assertEquals(18, clusters.get(0).count());
        assertFalse(clusters.get(0).minority());
        assertEquals("B", clusters.get(1).label());
        assertEquals(2, clusters.get(1).count());
        assertTrue(clusters.get(1).minority());
        assertTrue(clusters.get(1).divergent());
        assertTrue(summary.contains("Cluster A: 18 responses - 409 - len 80 - hash a23e91"));
        assertTrue(summary.contains("Cluster B: 2 responses - 200 - len 120 - hash 42d1fe"));
        assertTrue(summary.contains("minority cluster"));
    }

    @Test
    void clusterResponsesMarksOneOneAsSplitResponseFamily() {
        var clusters = ResponseAnalysis.clusterResponses(List.of(
                fingerprint((short) 200, 10, "success"),
                fingerprint((short) 409, 10, "conflict")
        ));

        assertEquals(2, clusters.size());
        assertTrue(clusters.get(0).divergent());
        assertTrue(clusters.get(1).divergent());
        assertFalse(clusters.get(0).minority());
        assertTrue(ResponseAnalysis.summarizeClusters(clusters).contains("split response family"));
        assertTrue(clusters.get(0).anomalySummary(2).contains("split response family"));
    }

    @Test
    void clusterResponsesMarksFiveFiveAsSplitResponseFamily() {
        var fingerprints = new java.util.ArrayList<ResponseFingerprint>();
        for (int i = 0; i < 5; i++) {
            fingerprints.add(fingerprint((short) 200, 10, "success"));
            fingerprints.add(fingerprint((short) 409, 10, "conflict"));
        }

        var clusters = ResponseAnalysis.clusterResponses(fingerprints);

        assertEquals(2, clusters.size());
        assertEquals(5, clusters.get(0).count());
        assertEquals(5, clusters.get(1).count());
        assertTrue(clusters.get(0).divergent());
        assertTrue(clusters.get(1).divergent());
        assertTrue(ResponseAnalysis.summarizeClusters(clusters).contains("split response family"));
    }

    @Test
    void clusterResponsesMarksAllUniqueAsHighlyDivergent() {
        var clusters = ResponseAnalysis.clusterResponses(List.of(
                fingerprint((short) 200, 10, "success"),
                fingerprint((short) 409, 11, "conflict"),
                fingerprint((short) 500, 12, "error")
        ));

        assertEquals(3, clusters.size());
        assertTrue(clusters.stream().allMatch(ResponseAnalysis.AttemptResponseCluster::divergent));
        assertTrue(ResponseAnalysis.summarizeClusters(clusters).contains("highly divergent"));
        assertTrue(clusters.get(0).anomalySummary(3).contains("highly divergent cluster"));
    }

    @Test
    void normalizationRedactsJsonFieldsAndRegexMatchesBeforeHashing() {
        ResponseNormalization normalization = new ResponseNormalization(
                Set.of(),
                List.of(Pattern.compile("\"requestId\":\"[^\"]+\"")),
                List.of("$.csrf"),
                false
        );
        String first = "{\"requestId\":\"abc\",\"csrf\":\"token-a\",\"state\":\"ok\"}";
        String second = "{\"requestId\":\"def\",\"csrf\":\"token-b\",\"state\":\"ok\"}";

        String firstNormalized = ResponseAnalysis.normalizeBody(first, normalization);
        String secondNormalized = ResponseAnalysis.normalizeBody(second, normalization);

        assertEquals(firstNormalized.length(), secondNormalized.length());
        assertEquals(ResponseAnalysis.sha256(firstNormalized), ResponseAnalysis.sha256(secondNormalized));
    }

    @Test
    void splitLinesPreservesRegexCommas() {
        assertEquals(List.of("\\d{1,3}"), ResponseAnalysis.splitLines("\\d{1,3}"));
    }

    @Test
    void splitLinesAcceptsOneRegexPerLine() {
        assertEquals(
                List.of("\\d{1,3}", "\"requestId\":\"[^\"]+\""),
                ResponseAnalysis.splitLines("\\d{1,3}\n\"requestId\":\"[^\"]+\"")
        );
    }

    @Test
    void utf8ByteLengthCountsBytesNotJavaChars() {
        String body = "\u00e9\u4e2d";

        assertEquals(2, body.length());
        assertEquals(5, ResponseAnalysis.utf8ByteLength(body));
    }

    @Test
    void ignoredHeadersAndSetCookieAreExcludedByNormalizationPolicy() {
        ResponseNormalization normalization = new ResponseNormalization(
                Set.of("location"),
                List.of(),
                List.of(),
                true
        );

        assertTrue(normalization.ignoresHeader("Location"));
        assertTrue(normalization.ignoresHeader("Set-Cookie"));
        assertFalse(normalization.ignoresHeader("Content-Type"));
    }

    private static ResponseFingerprint fingerprint(short status, Map<String, String> headers, Map<String, String> jsonFields) {
        return new ResponseFingerprint(status, 0, "hash", headers, Map.of(), jsonFields, headers.getOrDefault("location", ""), 0, 0, 0);
    }

    private static ResponseFingerprint fingerprint(short status, int length, String hash) {
        return new ResponseFingerprint(status, length, hash, Map.of(), Map.of(), Map.of(), "", 0, 0, 0);
    }
}
