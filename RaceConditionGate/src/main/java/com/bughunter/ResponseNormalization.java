package com.bughunter;

import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

record ResponseNormalization(
        Set<String> ignoredHeaders,
        List<Pattern> bodyNormalizationPatterns,
        List<String> ignoredJsonFields,
        boolean ignoreSetCookie
) {
    static ResponseNormalization none() {
        return new ResponseNormalization(Set.of(), List.of(), List.of(), false);
    }

    static ResponseNormalization fromUserInput(
            List<String> ignoredHeaders,
            List<String> bodyRegexes,
            List<String> ignoredJsonFields,
            boolean ignoreSetCookie
    ) {
        Set<String> normalizedHeaders = ignoredHeaders.stream()
                .map(header -> header.toLowerCase(Locale.ROOT))
                .collect(Collectors.toUnmodifiableSet());
        List<Pattern> patterns = bodyRegexes.stream()
                .map(Pattern::compile)
                .toList();
        return new ResponseNormalization(
                normalizedHeaders,
                List.copyOf(patterns),
                List.copyOf(ignoredJsonFields),
                ignoreSetCookie
        );
    }

    boolean ignoresHeader(String headerName) {
        String normalizedHeader = headerName.toLowerCase(Locale.ROOT);
        return ignoredHeaders.contains(normalizedHeader) || (ignoreSetCookie && "set-cookie".equals(normalizedHeader));
    }
}
