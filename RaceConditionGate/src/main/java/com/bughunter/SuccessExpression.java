package com.bughunter;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class SuccessExpression {
    private static final SuccessExpression EMPTY = new SuccessExpression(List.of());

    private final List<Term> terms;

    private SuccessExpression(List<Term> terms) {
        this.terms = terms;
    }

    static SuccessExpression parse(String expression) {
        if (expression == null || expression.isBlank()) {
            return EMPTY;
        }

        List<Term> parsed = new ArrayList<>();
        for (String part : expression.split("(?i)\\s+and\\s+")) {
            String term = part.trim();
            if (!term.isEmpty()) {
                parsed.add(parseTerm(term));
            }
        }
        return new SuccessExpression(List.copyOf(parsed));
    }

    boolean isEmpty() {
        return terms.isEmpty();
    }

    boolean matches(ResponseFingerprint current, ResponseFingerprint baseline, String body) {
        for (Term term : terms) {
            if (!term.matches(current, baseline, body)) {
                return false;
            }
        }
        return !terms.isEmpty();
    }

    private static Term parseTerm(String term) {
        Matcher statusMatcher = Pattern.compile("status\\s*(==|!=)\\s*(\\d+)", Pattern.CASE_INSENSITIVE).matcher(term);
        if (statusMatcher.matches()) {
            short expected = Short.parseShort(statusMatcher.group(2));
            boolean equals = statusMatcher.group(1).equals("==");
            return (current, baseline, body) -> equals == (current.statusCode() == expected);
        }

        Matcher bodyMatcher = Pattern.compile("body\\s+(contains|not contains)\\s+(.+)", Pattern.CASE_INSENSITIVE).matcher(term);
        if (bodyMatcher.matches()) {
            boolean contains = bodyMatcher.group(1).equalsIgnoreCase("contains");
            String needle = unquote(bodyMatcher.group(2));
            return (current, baseline, body) -> contains == body.contains(needle);
        }

        Matcher headerMatcher = Pattern.compile("header\\s+([A-Za-z0-9_-]+)\\s+contains\\s+(.+)", Pattern.CASE_INSENSITIVE).matcher(term);
        if (headerMatcher.matches()) {
            String headerName = headerMatcher.group(1).toLowerCase(Locale.ROOT);
            String needle = unquote(headerMatcher.group(2));
            return (current, baseline, body) -> current.selectedHeaders().getOrDefault(headerName, "").contains(needle);
        }

        Matcher jsonChangedMatcher = Pattern.compile("json\\s+(\\$\\.[A-Za-z0-9_.-]+)\\s+changed", Pattern.CASE_INSENSITIVE).matcher(term);
        if (jsonChangedMatcher.matches()) {
            String path = jsonChangedMatcher.group(1);
            return (current, baseline, body) -> baseline != null
                    && !baseline.jsonFields().getOrDefault(path, "").equals(current.jsonFields().getOrDefault(path, ""));
        }

        Matcher jsonEqualsMatcher = Pattern.compile("json\\s+(\\$\\.[A-Za-z0-9_.-]+)\\s*==\\s*(.+)", Pattern.CASE_INSENSITIVE).matcher(term);
        if (jsonEqualsMatcher.matches()) {
            String path = jsonEqualsMatcher.group(1);
            String expected = unquote(jsonEqualsMatcher.group(2));
            return (current, baseline, body) -> expected.equals(current.jsonFields().getOrDefault(path, ""));
        }

        return (current, baseline, body) -> false;
    }

    static List<String> jsonPathsFromExpression(String expression) {
        if (expression == null || expression.isBlank()) {
            return List.of();
        }

        List<String> paths = new ArrayList<>();
        Matcher matcher = Pattern.compile("json\\s+(\\$\\.[A-Za-z0-9_.-]+)", Pattern.CASE_INSENSITIVE).matcher(expression);
        while (matcher.find()) {
            paths.add(matcher.group(1));
        }
        return paths;
    }

    private static String unquote(String text) {
        String trimmed = text.trim();
        if (trimmed.length() >= 2
                && ((trimmed.startsWith("\"") && trimmed.endsWith("\""))
                || (trimmed.startsWith("'") && trimmed.endsWith("'")))) {
            return trimmed.substring(1, trimmed.length() - 1);
        }
        return trimmed;
    }

    private interface Term {
        boolean matches(ResponseFingerprint current, ResponseFingerprint baseline, String body);
    }
}
