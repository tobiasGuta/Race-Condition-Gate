package com.bughunter;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RequestTemplateKeyTest {
    @Test
    void includesSecurityContextHeadersInTemplateFingerprint() {
        RequestTemplateKey first = RequestTemplateKey.fromParts(
                "POST",
                "https://example.test/redeem",
                List.of(
                        new RequestTemplateKey.HeaderLine("Authorization", "Bearer account-a"),
                        new RequestTemplateKey.HeaderLine("Cookie", "session=a")
                ),
                "coupon=one"
        );
        RequestTemplateKey second = RequestTemplateKey.fromParts(
                "POST",
                "https://example.test/redeem",
                List.of(
                        new RequestTemplateKey.HeaderLine("Authorization", "Bearer account-b"),
                        new RequestTemplateKey.HeaderLine("Cookie", "session=a")
                ),
                "coupon=one"
        );

        assertNotEquals(first, second);
    }

    @Test
    void ignoresTransportGeneratedHeadersInTemplateFingerprint() {
        RequestTemplateKey first = RequestTemplateKey.fromParts(
                "POST",
                "https://example.test/redeem",
                List.of(
                        new RequestTemplateKey.HeaderLine("Content-Length", "10"),
                        new RequestTemplateKey.HeaderLine("Connection", "keep-alive"),
                        new RequestTemplateKey.HeaderLine("Idempotency-Key", "same-key")
                ),
                "coupon=one"
        );
        RequestTemplateKey second = RequestTemplateKey.fromParts(
                "POST",
                "https://example.test/redeem",
                List.of(
                        new RequestTemplateKey.HeaderLine("Content-Length", "999"),
                        new RequestTemplateKey.HeaderLine("Connection", "close"),
                        new RequestTemplateKey.HeaderLine("Idempotency-Key", "same-key")
                ),
                "coupon=one"
        );

        assertEquals(first, second);
    }

    @Test
    void includesContentTypeAndCustomTenantHeadersInTemplateFingerprint() {
        RequestTemplateKey first = RequestTemplateKey.fromParts(
                "POST",
                "https://example.test/redeem",
                List.of(
                        new RequestTemplateKey.HeaderLine("Content-Type", "application/json"),
                        new RequestTemplateKey.HeaderLine("X-Tenant-ID", "tenant-a")
                ),
                "{}"
        );
        RequestTemplateKey second = RequestTemplateKey.fromParts(
                "POST",
                "https://example.test/redeem",
                List.of(
                        new RequestTemplateKey.HeaderLine("Content-Type", "application/x-www-form-urlencoded"),
                        new RequestTemplateKey.HeaderLine("X-Tenant-ID", "tenant-a")
                ),
                "{}"
        );
        RequestTemplateKey third = RequestTemplateKey.fromParts(
                "POST",
                "https://example.test/redeem",
                List.of(
                        new RequestTemplateKey.HeaderLine("Content-Type", "application/json"),
                        new RequestTemplateKey.HeaderLine("X-Tenant-ID", "tenant-b")
                ),
                "{}"
        );

        assertNotEquals(first, second);
        assertNotEquals(first, third);
    }
}
