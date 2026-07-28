package com.bughunter;

import java.util.Map;

record ResponseFingerprint(
        short statusCode,
        int length,
        String bodyHash,
        Map<String, String> selectedHeaders,
        Map<String, Integer> keywordCounts,
        Map<String, String> jsonFields,
        String redirectLocation,
        long responseTimeUs,
        int responseOrder
) {
}
