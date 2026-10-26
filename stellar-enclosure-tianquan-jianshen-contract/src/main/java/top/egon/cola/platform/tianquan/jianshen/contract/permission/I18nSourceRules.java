package top.egon.cola.platform.tianquan.jianshen.contract.permission;

import java.util.Arrays;
import java.util.IllformedLocaleException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

/** Source text follows the existing Tianshu key, locale and {{name}} grammar. */
public final class I18nSourceRules {

    private static final Pattern KEY = Pattern.compile("[A-Za-z0-9_-]+(?:\\.[A-Za-z0-9_-]+)*");
    private static final Pattern VARIABLE = Pattern.compile("\\{\\{\\s*([A-Za-z_][A-Za-z0-9_]*)\\s*}}");
    private static final Set<String> UNSAFE_SEGMENTS = Set.of("__proto__", "constructor", "prototype");

    private I18nSourceRules() {
    }

    public static String key(String value) {
        if (value == null || value.length() > 128 || !KEY.matcher(value).matches()
                || Arrays.stream(value.split("\\.")).anyMatch(UNSAFE_SEGMENTS::contains)) {
            throw new IllegalArgumentException("invalid i18n page or message key");
        }
        return value;
    }

    public static String locale(String value) {
        if (value == null || value.isBlank() || value.length() > 64) {
            throw new IllegalArgumentException("invalid i18n locale");
        }
        try {
            Locale locale = new Locale.Builder().setLanguageTag(value).build();
            if (locale.getLanguage().isEmpty() || "und".equals(locale.getLanguage())
                    || !locale.toLanguageTag().equals(value)) {
                throw new IllegalArgumentException("locale must be a canonical BCP 47 tag");
            }
            return value;
        } catch (IllformedLocaleException exception) {
            throw new IllegalArgumentException("invalid i18n locale", exception);
        }
    }

    public static List<String> placeholders(String value) {
        if (value == null || value.isBlank() || value.length() > 8192 || value.indexOf('\u0000') >= 0
                || !ManifestChecks.wellFormed(value)) {
            throw new IllegalArgumentException("source text must contain 1..8192 well-formed characters without NUL");
        }
        TreeSet<String> names = new TreeSet<>();
        var matcher = VARIABLE.matcher(value);
        while (matcher.find()) names.add(matcher.group(1));
        String remaining = matcher.replaceAll("");
        if (remaining.contains("{{") || remaining.contains("}}")) {
            throw new IllegalArgumentException("only {{name}} interpolation is supported");
        }
        return List.copyOf(names);
    }

    public static String sourceHash(PermissionManifest.Message message) {
        return CanonicalJson.digest(Map.of("pageCode", message.pageCode(), "key", message.key(),
                "defaultLocale", message.defaultLocale(), "defaults", message.defaults(),
                "placeholders", placeholders(message.defaults().get(message.defaultLocale()))));
    }
}
