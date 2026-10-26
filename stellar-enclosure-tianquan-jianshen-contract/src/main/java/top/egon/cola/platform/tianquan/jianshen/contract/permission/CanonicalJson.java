package top.egon.cola.platform.tianquan.jianshen.contract.permission;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** Canonical JSON for the bounded, integer-only cross-language manifest contract. */
public final class CanonicalJson {

    private static final BigInteger MAX_SAFE_INTEGER = BigInteger.valueOf(9_007_199_254_740_991L);

    private CanonicalJson() {
    }

    public static String write(Object value) {
        StringBuilder output = new StringBuilder();
        append(value, output, 0);
        String result = output.toString();
        if (result.getBytes(StandardCharsets.UTF_8).length > PermissionManifest.MAX_BYTES) {
            throw new IllegalArgumentException("canonical JSON exceeds the byte limit");
        }
        return result;
    }

    public static String digest(Object value) {
        return digestUtf8(write(value));
    }

    public static String digestUtf8(String value) {
        if (!ManifestChecks.wellFormed(value)) {
            throw new IllegalArgumentException("invalid Unicode in digest input");
        }
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by the JDK", exception);
        }
    }

    private static void append(Object value, StringBuilder output, int depth) {
        if (depth > 16 || output.length() > PermissionManifest.MAX_BYTES) {
            throw new IllegalArgumentException("canonical JSON exceeds its structural limit");
        }
        if (value == null) {
            output.append("null");
        } else if (value instanceof String text) {
            appendString(text, output);
        } else if (value instanceof Boolean bool) {
            output.append(bool);
        } else if (value instanceof Byte || value instanceof Short || value instanceof Integer
                || value instanceof Long || value instanceof BigInteger) {
            BigInteger number = new BigInteger(value.toString());
            if (number.abs().compareTo(MAX_SAFE_INTEGER) > 0) {
                throw new IllegalArgumentException("large integers must be encoded as decimal strings");
            }
            output.append(number);
        } else if (value instanceof Map<?, ?> map) {
            TreeMap<String, Object> sorted = new TreeMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!(entry.getKey() instanceof String key) || key.isEmpty()
                        || key.chars().anyMatch(character -> character < 0x20 || character > 0x7e)) {
                    throw new IllegalArgumentException("canonical object keys must be printable ASCII");
                }
                sorted.put(key, entry.getValue());
            }
            output.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> entry : sorted.entrySet()) {
                if (!first) output.append(',');
                first = false;
                appendString(entry.getKey(), output);
                output.append(':');
                append(entry.getValue(), output, depth + 1);
            }
            output.append('}');
        } else if (value instanceof List<?> list) {
            output.append('[');
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) output.append(',');
                append(list.get(i), output, depth + 1);
            }
            output.append(']');
        } else {
            throw new IllegalArgumentException("unsupported canonical JSON value: " + value.getClass().getName());
        }
    }

    private static void appendString(String text, StringBuilder output) {
        if (!ManifestChecks.wellFormed(text)) {
            throw new IllegalArgumentException("unpaired Unicode surrogate");
        }
        output.append('"');
        for (int i = 0; i < text.length(); i++) {
            char character = text.charAt(i);
            switch (character) {
                case '"' -> output.append("\\\"");
                case '\\' -> output.append("\\\\");
                case '\b' -> output.append("\\b");
                case '\f' -> output.append("\\f");
                case '\n' -> output.append("\\n");
                case '\r' -> output.append("\\r");
                case '\t' -> output.append("\\t");
                default -> {
                    if (character < 0x20) {
                        output.append("\\u00");
                        output.append(Character.forDigit(character >> 4, 16));
                        output.append(Character.forDigit(character & 15, 16));
                    } else {
                        output.append(character);
                    }
                }
            }
        }
        output.append('"');
    }
}
