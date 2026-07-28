package com.bughunter;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

record RequestTemplateKey(String fingerprint) {
    static RequestTemplateKey from(HttpRequest request) {
        List<HeaderLine> headers = new ArrayList<>();
        for (HttpHeader header : request.headers()) {
            headers.add(new HeaderLine(header.name(), header.value()));
        }
        return fromParts(
                request.method(),
                request.url(),
                headers,
                request.bodyToString()
        );
    }

    static RequestTemplateKey fromParts(String method, String url, List<HeaderLine> headers, String body) {
        return new RequestTemplateKey(sha256(canonicalTemplate(method, url, headers, body)));
    }

    private static String canonicalTemplate(String method, String url, List<HeaderLine> headers, String body) {
        StringBuilder canonical = new StringBuilder()
                .append(normalizeValue(method)).append('\n')
                .append(normalizeValue(url)).append('\n');

        canonicalHeaders(headers).forEach(header -> canonical
                .append(header.name()).append(": ")
                .append(header.value()).append('\n'));

        canonical.append('\n').append(body == null ? "" : body);
        return canonical.toString();
    }

    private static List<HeaderLine> canonicalHeaders(List<HeaderLine> headers) {
        if (headers == null || headers.isEmpty()) {
            return List.of();
        }

        List<HeaderLine> canonical = new ArrayList<>();
        for (HeaderLine header : headers) {
            String name = normalizeHeaderName(header.name());
            if (!isTransportGeneratedHeader(name)) {
                canonical.add(new HeaderLine(name, normalizeHeaderValue(header.value())));
            }
        }
        return List.copyOf(canonical);
    }

    private static boolean isTransportGeneratedHeader(String normalizedName) {
        return switch (normalizedName) {
            case "connection",
                 "content-length",
                 "keep-alive",
                 "proxy-connection",
                 "te",
                 "trailer",
                 "transfer-encoding",
                 "upgrade" -> true;
            default -> false;
        };
    }

    private static String normalizeHeaderName(String name) {
        return normalizeValue(name).toLowerCase(Locale.ROOT);
    }

    private static String normalizeHeaderValue(String value) {
        return normalizeValue(value);
    }

    private static String normalizeValue(String value) {
        return value == null ? "" : value;
    }

    private static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    record HeaderLine(String name, String value) {
    }
}
