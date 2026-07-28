package com.bughunter;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

record RaceResultSnapshot(
        int id,
        int attempt,
        int requestIndex,
        HttpRequest request,
        HttpResponse response,
        String status,
        short statusCode,
        int length,
        long timeTakenUs,
        long dispatchOffsetUs,
        String bodyHash,
        int attemptOrder,
        int batchOrder,
        String anomaly,
        ResponseFingerprint fingerprint
) {
    static RaceResultSnapshot queued(int id, int attempt, int requestIndex, HttpRequest request) {
        return new RaceResultSnapshot(id, attempt, requestIndex, request, null, "Queued", (short) 0, 0, 0, 0, "", 0, 0, "", null);
    }

    RaceResultSnapshot withStatus(String status) {
        return new RaceResultSnapshot(id, attempt, requestIndex, request, response, status, statusCode, length, timeTakenUs, dispatchOffsetUs, bodyHash, attemptOrder, batchOrder, anomaly, fingerprint);
    }

    RaceResultSnapshot withAnomaly(String anomaly) {
        return new RaceResultSnapshot(id, attempt, requestIndex, request, response, status, statusCode, length, timeTakenUs, dispatchOffsetUs, bodyHash, attemptOrder, batchOrder, anomaly, fingerprint);
    }

    RaceResultSnapshot withResponse(HttpResponse response) {
        return new RaceResultSnapshot(id, attempt, requestIndex, request, response, status, statusCode, length, timeTakenUs, dispatchOffsetUs, bodyHash, attemptOrder, batchOrder, anomaly, fingerprint);
    }

    RaceResultSnapshot completed(
            HttpResponse rawResponse,
            HttpResponse retainedResponse,
            ResponseFingerprint fingerprint,
            long timeTakenUs,
            long dispatchOffsetUs,
            String anomaly
    ) {
        return new RaceResultSnapshot(
                id,
                attempt,
                requestIndex,
                request,
                retainedResponse,
                "Done",
                rawResponse.statusCode(),
                fingerprint.length(),
                timeTakenUs,
                dispatchOffsetUs,
                fingerprint.bodyHash(),
                fingerprint.attemptOrder(),
                fingerprint.batchOrder(),
                anomaly,
                fingerprint
        );
    }
}
