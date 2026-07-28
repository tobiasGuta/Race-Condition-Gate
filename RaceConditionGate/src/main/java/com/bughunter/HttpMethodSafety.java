package com.bughunter;

final class HttpMethodSafety {
    private HttpMethodSafety() {
    }

    static boolean isSafeForControlBaseline(String method) {
        return "GET".equalsIgnoreCase(method)
                || "HEAD".equalsIgnoreCase(method)
                || "OPTIONS".equalsIgnoreCase(method);
    }
}
