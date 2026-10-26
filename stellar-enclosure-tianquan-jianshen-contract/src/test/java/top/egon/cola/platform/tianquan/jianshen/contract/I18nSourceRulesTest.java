package top.egon.cola.platform.tianquan.jianshen.contract;

import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.I18nSourceRules;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class I18nSourceRulesTest {

    @Test
    void publishedLocaleCorpusMatchesJavaAuthority() throws Exception {
        try (var stream = getClass().getResourceAsStream("/permission-contract/locales-v1.json")) {
            var cases = new com.fasterxml.jackson.databind.ObjectMapper().readTree(stream).get("cases");
            assertEquals(110, cases.size());
            for (var entry : cases) {
                String input = entry.get("input").asText();
                if (entry.get("canonical").isNull()) {
                    assertThrows(java.util.IllformedLocaleException.class,
                            () -> new java.util.Locale.Builder().setLanguageTag(input).build(), input);
                } else {
                    assertEquals(entry.get("canonical").asText(), new java.util.Locale.Builder().setLanguageTag(input).build().toLanguageTag(), input);
                }
                if (entry.get("valid").asBoolean()) assertEquals(input, I18nSourceRules.locale(input));
                else assertThrows(IllegalArgumentException.class, () -> I18nSourceRules.locale(input), input);
            }
        }
    }

    @Test
    void followsExistingDotSegmentKeysAndRejectsPrototypeNames() {
        assertEquals("1_order.field_2", I18nSourceRules.key("1_order.field_2"));
        for (String key : List.of("order:read", "order..name", "order.", "__proto__", "order.constructor", "prototype.name")) {
            assertThrows(IllegalArgumentException.class, () -> I18nSourceRules.key(key), key);
        }
    }

    @Test
    void localeMustBeCanonicalAndConcrete() {
        assertEquals("zh-CN", I18nSourceRules.locale("zh-CN"));
        for (String locale : List.of("zh-cn", "en_US", "und", "", "x-private")) {
            assertThrows(IllegalArgumentException.class, () -> I18nSourceRules.locale(locale), locale);
        }
    }

    @Test
    void enforcesTextLengthAndExistingInterpolationGrammar() {
        assertEquals(List.of("count", "name"), I18nSourceRules.placeholders("{{ name }} has {{count}} / {{name}}"));
        for (String text : List.of("", " \n", "a\u0000b", "{{nested.value}}", "{{name", "x".repeat(8193))) {
            assertThrows(IllegalArgumentException.class, () -> I18nSourceRules.placeholders(text));
        }
    }

    @Test
    void translationsCannotChangePlaceholderSetsAndSourceHashIncludesDefaults() {
        var original = new PermissionManifest.Message("order", "greeting", "zh-CN",
                Map.of("zh-CN", "你好 {{name}}", "en-US", "Hello {{name}}"));
        var changed = new PermissionManifest.Message("order", "greeting", "zh-CN",
                Map.of("zh-CN", "您好 {{name}}", "en-US", "Hello {{name}}"));
        assertNotEquals(I18nSourceRules.sourceHash(original), I18nSourceRules.sourceHash(changed));
        assertThrows(IllegalArgumentException.class, () -> new PermissionManifest.Message("order", "greeting", "zh-CN",
                Map.of("zh-CN", "你好 {{name}}", "en-US", "Hello {{other}}")));
    }
}
