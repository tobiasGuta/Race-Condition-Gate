package com.bughunter;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.Locale;
import java.util.Objects;

record TargetMetadata(String host, int port, boolean secure, String httpProtocol) {
    TargetMetadata {
        host = normalizeHost(host);
        httpProtocol = normalizeProtocol(httpProtocol);
    }

    static TargetMetadata from(HttpRequest request) {
        HttpService service = request.httpService();
        return new TargetMetadata(service.host(), service.port(), service.secure(), request.httpVersion());
    }

    boolean isCompatibleWith(TargetMetadata other) {
        return other != null
                && Objects.equals(host, other.host)
                && port == other.port
                && secure == other.secure
                && Objects.equals(httpProtocol, other.httpProtocol);
    }

    String describe() {
        String scheme = secure ? "https" : "http";
        return scheme + "://" + host + ":" + port + " " + httpProtocol;
    }

    private static String normalizeHost(String host) {
        return host == null ? "" : host.trim().toLowerCase(Locale.ROOT);
    }

    private static String normalizeProtocol(String protocol) {
        return protocol == null ? "" : protocol.trim().toUpperCase(Locale.ROOT);
    }
}
