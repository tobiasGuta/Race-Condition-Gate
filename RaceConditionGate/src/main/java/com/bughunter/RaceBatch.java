package com.bughunter;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

final class RaceBatch {
    private final long batchId;
    private final int expectedWorkerCount;
    private final int totalAttempts;
    private final TargetMetadata targetMetadata;
    private final boolean multiEndpointMode;
    private final AtomicBoolean cancelled = new AtomicBoolean(false);
    private final List<RaceAttempt> attempts;

    RaceBatch(long batchId, int expectedWorkerCount, int totalAttempts, TargetMetadata targetMetadata, boolean multiEndpointMode) {
        if (expectedWorkerCount <= 0) {
            throw new IllegalArgumentException("expectedWorkerCount must be positive");
        }
        if (totalAttempts <= 0) {
            throw new IllegalArgumentException("totalAttempts must be positive");
        }

        this.batchId = batchId;
        this.expectedWorkerCount = expectedWorkerCount;
        this.totalAttempts = totalAttempts;
        this.targetMetadata = targetMetadata;
        this.multiEndpointMode = multiEndpointMode;

        List<RaceAttempt> builtAttempts = new ArrayList<>();
        for (int attempt = 1; attempt <= totalAttempts; attempt++) {
            builtAttempts.add(new RaceAttempt(this, attempt, expectedWorkerCount));
        }
        this.attempts = List.copyOf(builtAttempts);
    }

    static RaceBatch empty() {
        return new RaceBatch(0, 1, 1, new TargetMetadata("", 0, false, ""), false);
    }

    long batchId() {
        return batchId;
    }

    int expectedWorkerCount() {
        return expectedWorkerCount;
    }

    int totalAttempts() {
        return totalAttempts;
    }

    TargetMetadata targetMetadata() {
        return targetMetadata;
    }

    boolean isEmpty() {
        return batchId == 0;
    }

    boolean isCancelled() {
        return cancelled.get();
    }

    boolean isCompatible(TargetMetadata metadata) {
        return multiEndpointMode || targetMetadata.isCompatibleWith(metadata);
    }

    RaceAttempt attempt(int attemptNumber) {
        if (attemptNumber < 1 || attemptNumber > attempts.size()) {
            throw new IllegalArgumentException("Unknown attempt: " + attemptNumber);
        }
        return attempts.get(attemptNumber - 1);
    }

    void cancel() {
        if (cancelled.compareAndSet(false, true)) {
            for (RaceAttempt attempt : attempts) {
                attempt.cancel();
            }
        }
    }

    static final class RaceAttempt {
        private final RaceBatch batch;
        private final int attemptNumber;
        private final int expectedWorkerCount;
        private final CountDownLatch readyLatch;
        private final CountDownLatch releaseLatch = new CountDownLatch(1);
        private final CountDownLatch completionLatch;
        private final Set<Integer> readyWorkers = ConcurrentHashMap.newKeySet();
        private final AtomicInteger readyCount = new AtomicInteger(0);
        private final AtomicInteger completionCount = new AtomicInteger(0);
        private final AtomicInteger responseOrder = new AtomicInteger(0);
        private final AtomicBoolean released = new AtomicBoolean(false);
        private volatile long releaseTimeNanos = 0;

        private RaceAttempt(RaceBatch batch, int attemptNumber, int expectedWorkerCount) {
            this.batch = batch;
            this.attemptNumber = attemptNumber;
            this.expectedWorkerCount = expectedWorkerCount;
            this.readyLatch = new CountDownLatch(expectedWorkerCount);
            this.completionLatch = new CountDownLatch(expectedWorkerCount);
        }

        long batchId() {
            return batch.batchId();
        }

        int attemptNumber() {
            return attemptNumber;
        }

        int expectedWorkerCount() {
            return expectedWorkerCount;
        }

        int readyCount() {
            return readyCount.get();
        }

        int completionCount() {
            return completionCount.get();
        }

        int nextResponseOrder() {
            return responseOrder.incrementAndGet();
        }

        boolean isReleased() {
            return released.get();
        }

        boolean isReadyToRelease() {
            return !batch.isCancelled() && !isReleased() && readyLatch.getCount() == 0;
        }

        boolean markReady(int workerId) {
            if (batch.isCancelled() || isReleased()) {
                return false;
            }
            if (workerId < 1 || workerId > expectedWorkerCount) {
                throw new IllegalArgumentException("workerId out of range: " + workerId);
            }
            if (!readyWorkers.add(workerId)) {
                return false;
            }
            readyCount.incrementAndGet();
            readyLatch.countDown();
            return true;
        }

        boolean release() {
            if (!isReadyToRelease()) {
                return false;
            }
            if (released.compareAndSet(false, true)) {
                releaseTimeNanos = System.nanoTime();
                releaseLatch.countDown();
                return true;
            }
            return false;
        }

        void cancel() {
            drain(readyLatch);
            releaseLatch.countDown();
            drain(completionLatch);
        }

        void awaitReady() throws InterruptedException {
            readyLatch.await();
        }

        boolean awaitReady(long timeout, TimeUnit unit) throws InterruptedException {
            return readyLatch.await(timeout, unit);
        }

        void awaitRelease() throws InterruptedException {
            releaseLatch.await();
        }

        void markComplete() {
            completionCount.incrementAndGet();
            completionLatch.countDown();
        }

        void awaitCompletion() throws InterruptedException {
            completionLatch.await();
        }

        boolean wasReleasedByBatch() {
            return !batch.isCancelled() && isReleased();
        }

        long releaseTimeNanos() {
            return releaseTimeNanos;
        }

        private static void drain(CountDownLatch latch) {
            while (latch.getCount() > 0) {
                latch.countDown();
            }
        }
    }
}
