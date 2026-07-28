package com.bughunter;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RaceBatchTest {
    @Test
    void attemptOnlyReleasesAfterEveryWorkerIsReady() {
        RaceBatch batch = new RaceBatch(7, 2, 1, target("https", 443, true, "HTTP/1.1"), false);
        RaceBatch.RaceAttempt attempt = batch.attempt(1);

        assertFalse(attempt.isReadyToRelease());
        assertTrue(attempt.markReady());
        assertEquals(1, attempt.readyCount());
        assertFalse(attempt.release());

        assertTrue(attempt.markReady());
        assertEquals(2, attempt.readyCount());
        assertTrue(attempt.isReadyToRelease());
        assertTrue(attempt.release());
        assertTrue(attempt.isReleased());
        assertTrue(attempt.releaseTimeNanos() > 0);
    }

    @Test
    void cancelUnblocksAttemptsAndPreventsRelease() {
        RaceBatch batch = new RaceBatch(8, 1, 2, target("https", 443, true, "HTTP/2"), false);
        RaceBatch.RaceAttempt first = batch.attempt(1);
        RaceBatch.RaceAttempt second = batch.attempt(2);

        batch.cancel();

        assertTrue(batch.isCancelled());
        assertFalse(first.markReady());
        assertFalse(second.markReady());
        assertFalse(first.release());
        assertFalse(second.release());
        assertDoesNotThrow(first::awaitReady);
        assertDoesNotThrow(first::awaitRelease);
        assertDoesNotThrow(first::awaitCompletion);
        assertDoesNotThrow(second::awaitRelease);
    }

    @Test
    void targetCompatibilityRequiresSameEndpointAndProtocolUnlessMultiEndpointMode() {
        TargetMetadata base = target("Example.COM", 443, true, "HTTP/2");
        TargetMetadata same = target("example.com", 443, true, "http/2");
        TargetMetadata differentProtocol = target("example.com", 443, true, "HTTP/1.1");

        RaceBatch precisionBatch = new RaceBatch(9, 1, 1, base, false);
        RaceBatch logicalBatch = new RaceBatch(10, 1, 1, base, true);

        assertTrue(precisionBatch.isCompatible(same));
        assertFalse(precisionBatch.isCompatible(differentProtocol));
        assertTrue(logicalBatch.isCompatible(differentProtocol));
    }

    private static TargetMetadata target(String host, int port, boolean secure, String protocol) {
        return new TargetMetadata(host, port, secure, protocol);
    }
}
