package top.egon.cola.platform.tianquan.jianshen.contract.permission;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;

final class ManifestChecks {

    private static final Pattern IDENTIFIER = Pattern.compile("[A-Za-z][A-Za-z0-9_.:-]*");
    private static final Pattern DECIMAL = Pattern.compile("0|[1-9][0-9]{0,18}");
    private static final Pattern HASH = Pattern.compile("[0-9a-f]{64}");

    private ManifestChecks() {
    }

    static String identifier(String value, String name, int maxLength) {
        text(value, name, maxLength);
        if (!IDENTIFIER.matcher(value).matches()) {
            throw new IllegalArgumentException(name + " must be an ASCII identifier");
        }
        return value;
    }

    static String text(String value, String name, int maxLength) {
        if (value == null || value.isBlank() || value.length() > maxLength
                || !value.equals(value.strip()) || !wellFormed(value)) {
            throw new IllegalArgumentException(name + " is invalid");
        }
        return value;
    }

    static boolean wellFormed(String value) {
        for (int i = 0; i < value.length(); i++) {
            char character = value.charAt(i);
            if (Character.isHighSurrogate(character)) {
                if (++i >= value.length() || !Character.isLowSurrogate(value.charAt(i))) {
                    return false;
                }
            } else if (Character.isLowSurrogate(character)) {
                return false;
            }
        }
        return true;
    }

    static String decimal(String value, String name, boolean allowZero) {
        if (value == null || !DECIMAL.matcher(value).matches()) {
            throw new IllegalArgumentException(name + " must be a decimal long string");
        }
        try {
            if (Long.parseLong(value) < (allowZero ? 0 : 1)) {
                throw new IllegalArgumentException(name + " is out of range");
            }
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException(name + " is out of range", exception);
        }
        return value;
    }

    static String hash(String value, String name) {
        if (value == null || !HASH.matcher(value).matches()) {
            throw new IllegalArgumentException(name + " must be a SHA-256 digest");
        }
        return value;
    }

    static <T> List<T> sortedUnique(Collection<T> values, String name, int maximum,
                                    Function<T, String> key) {
        Objects.requireNonNull(values, name);
        if (values.size() > maximum) {
            throw new IllegalArgumentException(name + " exceeds its limit");
        }
        Set<String> seen = new HashSet<>();
        List<T> result = new ArrayList<>(values);
        for (T value : result) {
            String identity = key.apply(Objects.requireNonNull(value, name));
            if (!seen.add(identity.toLowerCase(Locale.ROOT))) {
                throw new IllegalArgumentException(name + " contains a duplicate or case-only collision");
            }
        }
        result.sort(Comparator.comparing(key));
        return List.copyOf(result);
    }

    static List<String> identifiers(Collection<String> values, String name, int maximum, int maxLength) {
        List<String> result = sortedUnique(values, name, maximum, Function.identity());
        result.forEach(value -> identifier(value, name, maxLength));
        return result;
    }
}
