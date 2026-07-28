package com.bughunter;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class ResponseAnalysis {
    private static final List<String> DEFAULT_HEADERS = List.of("Location", "Content-Type", "Set-Cookie");

    private ResponseAnalysis() {
    }

    static ResponseFingerprint fingerprint(
            HttpResponse response,
            long responseTimeUs,
            int responseOrder,
            List<String> keywords,
            List<String> jsonPaths
    ) {
        String body = response.bodyToString();
        Map<String, String> selectedHeaders = selectedHeaders(response);
        Map<String, Integer> keywordCounts = keywordCounts(body, keywords);
        Map<String, String> jsonFields = jsonFields(body, jsonPaths);
        String location = selectedHeaders.getOrDefault("location", "");

        return new ResponseFingerprint(
                response.statusCode(),
                response.body().length(),
                sha256(body),
                selectedHeaders,
                keywordCounts,
                jsonFields,
                location,
                responseTimeUs,
                responseOrder
        );
    }

    static String summarizeDifference(ResponseFingerprint baseline, ResponseFingerprint current, boolean successExpressionMatched) {
        List<String> parts = new ArrayList<>();

        if (successExpressionMatched) {
            parts.add("success expression matched");
        }

        if (baseline == null) {
            if (current.statusCode() >= 500) {
                parts.add("server error");
            }
            return parts.isEmpty() ? "" : String.join("; ", parts);
        }

        if (baseline.statusCode() != current.statusCode()) {
            parts.add("status " + baseline.statusCode() + " -> " + current.statusCode());
        }
        if (baseline.length() != current.length()) {
            parts.add("length " + baseline.length() + " -> " + current.length());
        }
        if (!baseline.bodyHash().equals(current.bodyHash())) {
            parts.add("body hash changed");
        }
        if (!baseline.redirectLocation().equals(current.redirectLocation())) {
            parts.add("redirect changed");
        }

        for (Map.Entry<String, String> header : current.selectedHeaders().entrySet()) {
            String baselineValue = baseline.selectedHeaders().getOrDefault(header.getKey(), "");
            if (!baselineValue.equals(header.getValue())) {
                parts.add("header " + header.getKey() + " changed");
            }
        }

        for (Map.Entry<String, Integer> keyword : current.keywordCounts().entrySet()) {
            int baselineCount = baseline.keywordCounts().getOrDefault(keyword.getKey(), 0);
            if (baselineCount != keyword.getValue()) {
                parts.add("keyword " + keyword.getKey() + " " + baselineCount + " -> " + keyword.getValue());
            }
        }

        for (Map.Entry<String, String> jsonField : current.jsonFields().entrySet()) {
            String baselineValue = baseline.jsonFields().getOrDefault(jsonField.getKey(), "");
            if (!baselineValue.equals(jsonField.getValue())) {
                parts.add("json " + jsonField.getKey() + " changed");
            }
        }

        return String.join("; ", parts);
    }

    static List<String> splitCsv(String text) {
        if (text == null || text.isBlank()) {
            return List.of();
        }

        List<String> values = new ArrayList<>();
        for (String part : text.split(",")) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) {
                values.add(trimmed);
            }
        }
        return values;
    }

    static String extractJsonValue(String body, String jsonPath) {
        if (body == null || jsonPath == null || !jsonPath.startsWith("$.")) {
            return "";
        }

        String[] fields = jsonPath.substring(2).split("\\.");
        String searchArea = body;
        for (String field : fields) {
            Matcher matcher = Pattern.compile("\"" + Pattern.quote(field) + "\"\\s*:\\s*(\"(?:\\\\.|[^\"])*\"|-?\\d+(?:\\.\\d+)?|true|false|null|\\{[^{}]*}|\\[[^\\[\\]]*])").matcher(searchArea);
            if (!matcher.find()) {
                return "";
            }
            searchArea = matcher.group(1);
        }

        if (searchArea.length() >= 2 && searchArea.startsWith("\"") && searchArea.endsWith("\"")) {
            return searchArea.substring(1, searchArea.length() - 1);
        }
        return searchArea;
    }

    static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.substring(0, 12);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    private static Map<String, String> selectedHeaders(HttpResponse response) {
        Map<String, String> selected = new LinkedHashMap<>();
        for (HttpHeader header : response.headers()) {
            for (String candidate : DEFAULT_HEADERS) {
                if (header.name().equalsIgnoreCase(candidate)) {
                    selected.put(candidate.toLowerCase(Locale.ROOT), header.value());
                }
            }
        }
        return Map.copyOf(selected);
    }

    private static Map<String, Integer> keywordCounts(String body, List<String> keywords) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (String keyword : keywords) {
            counts.put(keyword, countOccurrences(body, keyword));
        }
        return Map.copyOf(counts);
    }

    private static Map<String, String> jsonFields(String body, List<String> jsonPaths) {
        Map<String, String> fields = new LinkedHashMap<>();
        for (String jsonPath : jsonPaths) {
            fields.put(jsonPath, extractJsonValue(body, jsonPath));
        }
        return Map.copyOf(fields);
    }

    private static int countOccurrences(String body, String keyword) {
        if (body == null || body.isEmpty() || keyword == null || keyword.isEmpty()) {
            return 0;
        }

        int count = 0;
        int index = 0;
        while ((index = body.indexOf(keyword, index)) != -1) {
            count++;
            index += keyword.length();
        }
        return count;
    }
}
