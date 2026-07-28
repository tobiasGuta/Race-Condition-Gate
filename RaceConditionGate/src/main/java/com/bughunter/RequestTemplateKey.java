package com.bughunter;

import burp.api.montoya.http.message.requests.HttpRequest;

record RequestTemplateKey(String method, String url, String body) {
    static RequestTemplateKey from(HttpRequest request) {
        return new RequestTemplateKey(
                request.method(),
                request.url(),
                request.bodyToString()
        );
    }
}
