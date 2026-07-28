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
import java.util.Comparator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

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
        return fingerprint(response, responseTimeUs, responseOrder, keywords, jsonPaths, ResponseNormalization.none());
    }

    static ResponseFingerprint fingerprint(
            HttpResponse response,
            long responseTimeUs,
            int responseOrder,
            List<String> keywords,
            List<String> jsonPaths,
            ResponseNormalization normalization
    ) {
        return fingerprint(response, responseTimeUs, responseOrder, keywords, jsonPaths, normalization, List.of());
    }

    static ResponseFingerprint fingerprint(
            HttpResponse response,
            long responseTimeUs,
            int responseOrder,
            List<String> keywords,
            List<String> jsonPaths,
            ResponseNormalization normalization,
            List<String> additionalHeaderNames
    ) {
        String body = response.bodyToString();
        String normalizedBody = normalizeBody(body, normalization);
        Map<String, String> selectedHeaders = selectedHeaders(response, normalization, additionalHeaderNames);
        Map<String, Integer> keywordCounts = keywordCounts(body, keywords);
        Map<String, String> jsonFields = jsonFields(body, jsonPaths, normalization.ignoredJsonFields());
        String location = selectedHeaders.getOrDefault("location", "");

        return new ResponseFingerprint(
                response.statusCode(),
                normalizedBody.length(),
                sha256(normalizedBody),
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

        List<String> headerNames = new ArrayList<>(baseline.selectedHeaders().keySet());
        for (String headerName : current.selectedHeaders().keySet()) {
            if (!headerNames.contains(headerName)) {
                headerNames.add(headerName);
            }
        }
        for (String headerName : headerNames) {
            String baselineValue = baseline.selectedHeaders().getOrDefault(headerName, "");
            String currentValue = current.selectedHeaders().getOrDefault(headerName, "");
            if (!baselineValue.equals(currentValue)) {
                parts.add("header " + headerName + " changed");
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

    static List<AttemptResponseCluster> clusterResponses(List<ResponseFingerprint> fingerprints) {
        Map<ClusterKey, List<ResponseFingerprint>> grouped = new LinkedHashMap<>();
        for (ResponseFingerprint fingerprint : fingerprints) {
            grouped.computeIfAbsent(ClusterKey.from(fingerprint), ignored -> new ArrayList<>()).add(fingerprint);
        }

        int maxCount = grouped.values().stream()
                .mapToInt(List::size)
                .max()
                .orElse(0);

        List<Map.Entry<ClusterKey, List<ResponseFingerprint>>> entries = new ArrayList<>(grouped.entrySet());
        entries.sort(
                Comparator.<Map.Entry<ClusterKey, List<ResponseFingerprint>>>comparingInt(entry -> entry.getValue().size()).reversed()
                        .thenComparing(entry -> entry.getKey().statusCode())
                        .thenComparing(entry -> entry.getKey().bodyHash())
                        .thenComparing(entry -> entry.getKey().length())
                        .thenComparing(entry -> entry.getKey().headers().toString())
        );

        List<AttemptResponseCluster> clusters = new ArrayList<>();
        for (int i = 0; i < entries.size(); i++) {
            Map.Entry<ClusterKey, List<ResponseFingerprint>> entry = entries.get(i);
            clusters.add(new AttemptResponseCluster(
                    clusterLabel(i),
                    entry.getValue().size(),
                    entry.getKey(),
                    grouped.size() > 1 && entry.getValue().size() < maxCount
            ));
        }
        return List.copyOf(clusters);
    }

    static String summarizeClusters(List<AttemptResponseCluster> clusters) {
        return clusters.stream()
                .map(AttemptResponseCluster::summary)
                .collect(Collectors.joining("; "));
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

    static List<String> splitLinesOrCsv(String text) {
        if (text == null || text.isBlank()) {
            return List.of();
        }

        String delimiter = text.contains("\n") || text.contains("\r") ? "\\R" : ",";
        List<String> values = new ArrayList<>();
        for (String part : text.split(delimiter)) {
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

    static String normalizeBody(String body, ResponseNormalization normalization) {
        String normalized = body == null ? "" : body;
        for (String jsonField : normalization.ignoredJsonFields()) {
            normalized = replaceJsonFieldValue(normalized, jsonField);
        }
        for (Pattern pattern : normalization.bodyNormalizationPatterns()) {
            normalized = pattern.matcher(normalized).replaceAll("<ignored>");
        }
        return normalized;
    }

    private static Map<String, String> selectedHeaders(
            HttpResponse response,
            ResponseNormalization normalization,
            List<String> additionalHeaderNames
    ) {
        Map<String, String> selected = new LinkedHashMap<>();
        List<String> candidateHeaders = new ArrayList<>(DEFAULT_HEADERS);
        for (String headerName : additionalHeaderNames) {
            if (candidateHeaders.stream().noneMatch(candidate -> candidate.equalsIgnoreCase(headerName))) {
                candidateHeaders.add(headerName);
            }
        }
        for (HttpHeader header : response.headers()) {
            for (String candidate : candidateHeaders) {
                if (header.name().equalsIgnoreCase(candidate) && !normalization.ignoresHeader(candidate)) {
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

    private static Map<String, String> jsonFields(String body, List<String> jsonPaths, List<String> ignoredJsonFields) {
        Map<String, String> fields = new LinkedHashMap<>();
        for (String jsonPath : jsonPaths) {
            if (!ignoredJsonFields.contains(jsonPath)) {
                fields.put(jsonPath, extractJsonValue(body, jsonPath));
            }
        }
        return Map.copyOf(fields);
    }

    private static String replaceJsonFieldValue(String body, String jsonPath) {
        if (body == null || jsonPath == null || !jsonPath.startsWith("$.")) {
            return body;
        }

        String[] fields = jsonPath.substring(2).split("\\.");
        if (fields.length == 0) {
            return body;
        }

        String field = fields[fields.length - 1];
        Pattern pattern = Pattern.compile(
                "(\"" + Pattern.quote(field) + "\"\\s*:\\s*)(\"(?:\\\\.|[^\"])*\"|-?\\d+(?:\\.\\d+)?|true|false|null)"
        );
        return pattern.matcher(body).replaceAll("$1\"<ignored>\"");
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

    private static String clusterLabel(int index) {
        if (index < 26) {
            return String.valueOf((char) ('A' + index));
        }
        return "Z" + (index - 25);
    }

    record AttemptResponseCluster(
            String label,
            int count,
            ClusterKey key,
            boolean minority
    ) {
        String summary() {
            StringBuilder sb = new StringBuilder()
                    .append("Cluster ").append(label)
                    .append(": ").append(count).append(count == 1 ? " response" : " responses")
                    .append(" - ").append(key.statusCode())
                    .append(" - len ").append(key.length())
                    .append(" - hash ").append(key.bodyHash());
            if (!key.headers().isEmpty()) {
                sb.append(" - headers ").append(key.headers());
            }
            if (minority) {
                sb.append(" - minority cluster");
            }
            return sb.toString();
        }

        String anomalySummary(int totalResponses) {
            return "minority cluster " + label
                    + " (" + count + "/" + totalResponses
                    + "; status " + key.statusCode()
                    + "; hash " + key.bodyHash() + ")";
        }
    }

    record ClusterKey(
            short statusCode,
            String bodyHash,
            int length,
            Map<String, String> headers
    ) {
        static ClusterKey from(ResponseFingerprint fingerprint) {
            return new ClusterKey(
                    fingerprint.statusCode(),
                    fingerprint.bodyHash(),
                    fingerprint.length(),
                    fingerprint.selectedHeaders()
            );
        }
    }
}
