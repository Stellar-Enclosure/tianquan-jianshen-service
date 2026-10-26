package top.egon.cola.platform.tianquan.jianshen.processor;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.DefinitionLifecycle;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestCanonicalizer;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionMode;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionRequirement;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;

import javax.annotation.processing.AbstractProcessor;
import javax.annotation.processing.RoundEnvironment;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.AnnotationMirror;
import javax.lang.model.element.AnnotationValue;
import javax.lang.model.element.Element;
import javax.lang.model.element.ElementKind;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.Modifier;
import javax.lang.model.element.TypeElement;
import javax.lang.model.type.DeclaredType;
import javax.lang.model.type.ExecutableType;
import javax.lang.model.type.TypeKind;
import javax.lang.model.type.TypeMirror;
import javax.lang.model.util.ElementFilter;
import javax.tools.Diagnostic;
import javax.tools.StandardLocation;
import java.io.IOException;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/** Exports compiler symbols as PARTIAL fragments. Successful packaging is a separate FULL gate. */
public final class PermissionManifestProcessor extends AbstractProcessor {

    public static final String FRAGMENT = "META-INF/permissions/fragment-v1.json";
    private final Map<String, TypeElement> roots = new TreeMap<>();
    private final Set<String> packages = new HashSet<>();
    private final List<PermissionManifest.PermissionDefinition> definitions = new ArrayList<>();
    private final Set<String> references = new TreeSet<>();
    private final List<PermissionManifest.Message> messages = new ArrayList<>();
    private final List<PermissionManifest.ResourceDefinition> resources = new ArrayList<>();
    private CompilerAnnotations annotations;
    private SpringMappingResolver mappings;
    private Set<String> metadataOnlyTypes = Set.of();
    private boolean initialized;
    private boolean failed;

    @Override
    public Set<String> getSupportedAnnotationTypes() {
        return Set.of("*");
    }

    @Override
    public Set<String> getSupportedOptions() {
        return Set.of("pac.business", "pac.application", "pac.producer", "pac.module", "pac.expectedModules",
                "pac.ownedKeyPrefixes", "pac.managedPackages", "pac.metadataOnlyTypes", "pac.repository", "pac.commit", "pac.buildId", "pac.version");
    }

    @Override
    public SourceVersion getSupportedSourceVersion() {
        return SourceVersion.latestSupported();
    }

    @Override
    public boolean process(Set<? extends TypeElement> annotationTypes, RoundEnvironment round) {
        if (!initialized) {
            initialized = true;
            annotations = new CompilerAnnotations(processingEnv.getElementUtils());
            mappings = new SpringMappingResolver(annotations);
            try {
                // Incremental compiler failures must not leave a previous successful fragment behind.
                var previous = processingEnv.getFiler().getResource(StandardLocation.CLASS_OUTPUT, "", FRAGMENT);
                if (!"file".equals(previous.toUri().getScheme())) {
                    throw new IllegalArgumentException("permission export requires an explicit filesystem CLASS_OUTPUT");
                }
                Files.deleteIfExists(Path.of(previous.toUri()));
                for (String name : getSupportedOptions()) {
                    if (!name.equals("pac.metadataOnlyTypes")) option(name.substring(4));
                }
                if (processingEnv.getOptions().containsKey("pac.metadataOnlyTypes")) {
                    metadataOnlyTypes = Set.copyOf(listOption("metadataOnlyTypes"));
                }
            } catch (IllegalArgumentException failure) {
                error(null, failure.getMessage());
            } catch (IOException failure) {
                error(null, "cannot invalidate previous permission fragment: " + failure.getMessage());
            }
        }
        if (round.errorRaised()) failed = true;
        for (Element root : round.getRootElements()) collectRoot(root);
        if (round.processingOver() && !failed) {
            try {
                for (String name : metadataOnlyTypes) {
                    if (!roots.containsKey(name)) throw new IllegalArgumentException("metadata-only type is not a compiled source: " + name);
                    validateMetadataOnlyType(roots.get(name));
                }
                for (TypeElement type : roots.values()) scan(type);
                if (!failed) writeFragment();
            } catch (IllegalArgumentException failure) {
                error(null, failure.getMessage());
            } catch (IOException failure) {
                error(null, "cannot write permission fragment: " + failure.getMessage());
            }
        }
        return false;
    }

    private void collectRoot(Element element) {
        if (element instanceof TypeElement type) {
            roots.put(type.getQualifiedName().toString(), type);
            for (TypeElement nested : ElementFilter.typesIn(type.getEnclosedElements())) collectRoot(nested);
        } else if (element.getKind() == ElementKind.PACKAGE && packages.add(element.toString())) {
            collectDeclarations(element);
        }
    }

    private void scan(TypeElement type) {
        if (type.getKind() == ElementKind.ANNOTATION_TYPE) return;
        collectDeclarations(type);
        if (!annotations.find(type, "PermissionResource").isEmpty()) {
            error(type, "Java resources require an explicit API method or DTO field target");
        }
        Element packageElement = processingEnv.getElementUtils().getPackageOf(type);
        if (packages.add(packageElement.toString())) collectDeclarations(packageElement);
        if (type.getKind() == ElementKind.INTERFACE || type.getModifiers().contains(Modifier.ABSTRACT)) return;
        boolean metadataOnly = metadataOnlyTypes.contains(type.getQualifiedName().toString());
        List<TypeElement> hierarchy = hierarchy(type);
        boolean controller = hierarchy.stream().anyMatch(candidate -> annotations.hasAnnotation(candidate,
                "org.springframework.stereotype.Controller"));
        Map<String, List<String>> typeMapping = mappings.resolve(hierarchy);
        for (ExecutableElement method : ElementFilter.methodsIn(processingEnv.getElementUtils().getAllMembers(type))) {
            List<ExecutableElement> declarations = metadataOnly || method.getModifiers().contains(Modifier.STATIC)
                    ? List.of(method) : methodHierarchy(type, method, hierarchy);
            Map<String, List<String>> mapping = mappings.resolve(declarations);
            AnnotationMirror resource = annotations.unique(declarations, "PermissionResource");
            AnnotationMirror dispatcher = annotations.unique(declarations, "PermissionNativeDispatcher");
            if (dispatcher != null) {
                if (!metadataOnly || mapping != null || typeMapping != null || resource == null
                        || !annotations.enumeration(resource, "type").equals("API")
                        || !annotations.enumeration(resource, "access").equals("INTERNAL")) {
                    error(method, "native dispatcher requires an INTERNAL API on an exact metadata-only holder without Spring mappings");
                    continue;
                }
                resources.add(resource(resource, nativeDispatcherTarget(dispatcher), null, null));
            } else if (mapping != null && (controller || metadataOnly)) {
                if (resource == null) {
                    if (managed(type) || metadataOnly) error(method, "managed API mapping requires @PermissionResource, including PUBLIC/INTERNAL");
                    continue;
                }
                if (!annotations.enumeration(resource, "type").equals("API")) {
                    error(method, "mapped methods must declare an API resource");
                    continue;
                }
                List<Element> groups = new ArrayList<>(hierarchy);
                groups.addAll(declarations);
                if (metadataOnly && annotations.enumeration(resource, "access").equals("PROTECTED")) {
                    error(method, "metadata-only protocol declarations require PUBLIC or INTERNAL access");
                    continue;
                }
                resources.add(resource(resource, mappings.target(typeMapping, mapping, !metadataOnly), requirement(groups), null));
            } else if (resource != null && annotations.enumeration(resource, "type").equals("API")) {
                error(method, "API resource has no unambiguous controller mapping");
            } else if (resource != null && annotations.enumeration(resource, "type").equals("FIELD")) {
                if (!method.getParameters().isEmpty() || method.getReturnType().getKind() == TypeKind.VOID) {
                    error(method, "FIELD getter must have no parameters and return a value");
                    continue;
                }
                field(type, method, declarations, resource, method.getReturnType());
            } else if (resource != null) {
                error(method, "only API methods and DTO FIELD resources are supported by Java export");
            }
        }
        for (Element field : type.getEnclosedElements()) {
            if (field.getKind() != ElementKind.FIELD && field.getKind() != ElementKind.RECORD_COMPONENT) continue;
            // A record component annotation also propagates to its backing field and accessor.
            if (type.getKind() == ElementKind.RECORD && field.getKind() == ElementKind.FIELD) continue;
            AnnotationMirror resource = annotations.unique(List.of(field), "PermissionResource");
            if (resource != null) field(type, field, List.of(field), resource, field.asType());
        }
    }

    private void validateMetadataOnlyType(TypeElement type) {
        if (type.getKind() != ElementKind.CLASS || !type.getModifiers().contains(Modifier.FINAL)
                || !type.getInterfaces().isEmpty() || !type.getSuperclass().toString().equals("java.lang.Object")
                || type.getNestingKind() != javax.lang.model.element.NestingKind.TOP_LEVEL
                || annotations.hasAnnotation(type, "org.springframework.stereotype.Component")
                || annotations.hasAnnotation(type, "org.springframework.stereotype.Controller")
                || annotations.hasAnnotation(type, "jakarta.inject.Named")
                || annotations.hasAnnotation(type, "jakarta.annotation.ManagedBean")) {
            throw new IllegalArgumentException("metadata-only type must be a final non-bean top-level declaration holder");
        }
        List<ExecutableElement> constructors = ElementFilter.constructorsIn(type.getEnclosedElements());
        if (constructors.size() != 1 || !constructors.getFirst().getModifiers().contains(Modifier.PRIVATE)
                || !constructors.getFirst().getParameters().isEmpty()) {
            throw new IllegalArgumentException("metadata-only type requires one private no-argument constructor");
        }
        List<ExecutableElement> methods = ElementFilter.methodsIn(type.getEnclosedElements());
        if (methods.isEmpty()) throw new IllegalArgumentException("metadata-only type requires explicit protocol declarations");
        for (ExecutableElement method : methods) {
            AnnotationMirror resource = annotations.unique(List.of(method), "PermissionResource");
            if (!method.getModifiers().containsAll(Set.of(Modifier.PUBLIC, Modifier.STATIC))
                    || !method.getParameters().isEmpty() || method.getReturnType().getKind() != TypeKind.VOID
                    || annotations.hasAnnotation(method, "org.springframework.context.annotation.Bean")
                    || resource == null || !annotations.enumeration(resource, "type").equals("API")
                    || (mappings.resolve(List.of(method)) == null
                        && annotations.unique(List.of(method), "PermissionNativeDispatcher") == null)) {
                throw new IllegalArgumentException("metadata-only methods require public static void API declarations with explicit mappings");
            }
        }
    }

    private Map<String, Object> nativeDispatcherTarget(AnnotationMirror dispatcher) {
        Object routeValue = annotations.values(dispatcher).get("routeType").getValue();
        if (!(routeValue instanceof DeclaredType route)
                || !(route.asElement() instanceof TypeElement owner)) {
            throw new IllegalArgumentException("native dispatcher routeType must resolve to a declared type");
        }
        String pathName = annotations.text(dispatcher, "pathAccessor");
        String methodsName = annotations.text(dispatcher, "methodsAccessor");
        TypeMirror path = nativeAccessor(route, owner, pathName);
        if (!path.toString().equals("java.lang.String")) {
            throw new IllegalArgumentException("native dispatcher path accessor must return String");
        }
        TypeMirror methods = nativeAccessor(route, owner, methodsName);
        if (!stringCollection(methods, new HashSet<>())) {
            throw new IllegalArgumentException("native dispatcher methods accessor must return Collection<String>");
        }
        return Map.of("nativeRouteType", owner.getQualifiedName().toString(), "pathSource", pathName,
                "methodSource", methodsName, "protocol", "HTTP");
    }

    private TypeMirror nativeAccessor(DeclaredType route, TypeElement owner, String name) {
        if (!name.matches("[A-Za-z_$][A-Za-z0-9_$]{0,127}")) {
            throw new IllegalArgumentException("native dispatcher accessor must be a bounded Java identifier");
        }
        var matches = ElementFilter.methodsIn(processingEnv.getElementUtils().getAllMembers(owner)).stream()
                .filter(method -> method.getSimpleName().contentEquals(name) && method.getParameters().isEmpty()
                        && method.getModifiers().contains(Modifier.PUBLIC) && !method.getModifiers().contains(Modifier.STATIC)
                        && method.getTypeParameters().isEmpty()).toList();
        if (matches.size() != 1) {
            throw new IllegalArgumentException("native dispatcher accessor must resolve to one public no-argument instance method: " + name);
        }
        return ((ExecutableType) processingEnv.getTypeUtils().asMemberOf(route, matches.getFirst())).getReturnType();
    }

    private boolean stringCollection(TypeMirror type, Set<String> visiting) {
        if (!(type instanceof DeclaredType declared) || !visiting.add(type.toString())) return false;
        if (((TypeElement) declared.asElement()).getQualifiedName().contentEquals("java.util.Collection")) {
            return declared.getTypeArguments().size() == 1
                    && declared.getTypeArguments().getFirst().toString().equals("java.lang.String");
        }
        return processingEnv.getTypeUtils().directSupertypes(type).stream()
                .anyMatch(parent -> stringCollection(parent, visiting));
    }

    private void collectDeclarations(Element element) {
        try {
            for (AnnotationMirror declaration : annotations.find(element, "PermissionDefinition")) {
                definitions.add(new PermissionManifest.PermissionDefinition(annotations.text(declaration, "code"),
                        annotations.text(declaration, "meaning"), i18n(declaration),
                        DefinitionLifecycle.valueOf(annotations.enumeration(declaration, "lifecycle"))));
            }
            for (AnnotationMirror declaration : annotations.find(element, "PermissionReferences")) {
                references.addAll(annotations.strings(declaration, "value"));
            }
            for (AnnotationMirror declaration : annotations.find(element, "PermissionMessage")) {
                Map<String, String> defaults = new TreeMap<>();
                for (AnnotationValue value : annotations.array(declaration, "defaults")) {
                    AnnotationMirror localized = (AnnotationMirror) value.getValue();
                    if (defaults.putIfAbsent(annotations.text(localized, "locale"), annotations.text(localized, "text")) != null) {
                        throw new IllegalArgumentException("duplicate source locale");
                    }
                }
                messages.add(new PermissionManifest.Message(annotations.text(declaration, "pageCode"),
                        annotations.text(declaration, "key"), annotations.text(declaration, "defaultLocale"), defaults));
            }
        } catch (IllegalArgumentException failure) {
            error(element, failure.getMessage());
        }
    }

    private void field(TypeElement owner, Element field, List<? extends Element> declarations,
                       AnnotationMirror resource, TypeMirror valueType) {
        if (!annotations.enumeration(resource, "type").equals("FIELD")) {
            error(field, "only API methods and DTO FIELD resources are supported by Java export");
            return;
        }
        if (owner.getKind() == ElementKind.RECORD && field.getKind() == ElementKind.METHOD
                && owner.getRecordComponents().stream().anyMatch(component -> component.getSimpleName().equals(field.getSimpleName()))) {
            return;
        }
        AnnotationMirror rules = annotations.unique(declarations, "FieldPermissions");
        boolean protectedField = annotations.enumeration(resource, "access").equals("PROTECTED");
        if (protectedField && rules == null) throw new IllegalArgumentException("protected FIELD resource requires @FieldPermissions");
        if (!protectedField && rules != null) throw new IllegalArgumentException("PUBLIC/INTERNAL FIELD cannot erase field rules");
        PermissionManifest.FieldPolicy policy = null;
        if (rules != null) {
            PermissionManifest.JsonFieldType declared = PermissionManifest.JsonFieldType.valueOf(annotations.enumeration(rules, "valueType"));
            verifyFieldType(field, valueType, declared);
            policy = new PermissionManifest.FieldPolicy(declared,
                    fieldGroup(rules, "plainRead"), fieldGroup(rules, "maskedRead"), fieldGroup(rules, "write"),
                    annotations.text(rules, "masker").isEmpty() ? null : annotations.text(rules, "masker"));
        }
        String property = field.getSimpleName().toString();
        if (field.getKind() == ElementKind.METHOD) {
            if (property.startsWith("get") && property.length() > 3) property = decapitalize(property.substring(3));
            else if (property.startsWith("is") && property.length() > 2) property = decapitalize(property.substring(2));
            else if (owner.getKind() != ElementKind.RECORD) throw new IllegalArgumentException("FIELD method is not a bean getter");
        }
        for (AnnotationMirror annotation : serializationMembers(field).stream()
                .flatMap(member -> member.getAnnotationMirrors().stream()).toList()) {
            if (annotations.name(annotation).equals("com.fasterxml.jackson.annotation.JsonProperty")) {
                String jsonName = annotations.text(annotation, "value");
                if (!jsonName.isEmpty()) property = jsonName;
            }
            if (annotations.name(annotation).equals("com.fasterxml.jackson.annotation.JsonIgnore")) {
                throw new IllegalArgumentException("ignored JSON fields cannot declare resources");
            }
        }
        resources.add(resource(resource, Map.of("dto", owner.getQualifiedName().toString(), "property", property), null, policy));
    }

    private String decapitalize(String name) {
        return name.length() > 1 && Character.isUpperCase(name.charAt(0)) && Character.isUpperCase(name.charAt(1))
                ? name : Character.toLowerCase(name.charAt(0)) + name.substring(1);
    }

    private List<Element> serializationMembers(Element field) {
        List<Element> members = new ArrayList<>();
        members.add(field);
        if (field.getKind() == ElementKind.RECORD_COMPONENT) {
            for (Element member : field.getEnclosingElement().getEnclosedElements()) {
                if (member != field && member.getSimpleName().equals(field.getSimpleName())
                        && (member.getKind() == ElementKind.FIELD || member.getKind() == ElementKind.METHOD)) {
                    members.add(member);
                }
            }
        }
        return List.copyOf(members);
    }

    private void verifyFieldType(Element field, TypeMirror type, PermissionManifest.JsonFieldType declared) {
        if (type.getKind() == TypeKind.TYPEVAR || type.getKind() == TypeKind.ERROR) {
            throw new IllegalArgumentException("unresolved generic FIELD type");
        }
        String name = processingEnv.getTypeUtils().erasure(type).toString();
        Element typeElement = processingEnv.getTypeUtils().asElement(type);
        List<Element> sources = new ArrayList<>(serializationMembers(field));
        if (typeElement != null) sources.add(typeElement);
        String shape = null;
        boolean stringSerializer = false;
        for (Element source : sources) {
            for (AnnotationMirror annotation : source.getAnnotationMirrors()) {
                String annotationName = annotations.name(annotation);
                if (annotationName.equals("com.fasterxml.jackson.databind.annotation.JsonSerialize")
                        || annotationName.equals("tools.jackson.databind.annotation.JsonSerialize")) {
                    String serializer = annotations.values(annotation).get("using").getValue().toString();
                    if (serializer.endsWith("JsonSerializer.None")) continue;
                    if (!Set.of("com.fasterxml.jackson.databind.ser.std.ToStringSerializer",
                            "tools.jackson.databind.ser.std.ToStringSerializer").contains(serializer)) {
                        throw new IllegalArgumentException("custom FIELD serializer has no statically supported JSON type");
                    }
                    stringSerializer = true;
                }
                if (shape == null && annotationName.equals("com.fasterxml.jackson.annotation.JsonFormat")) {
                    String configured = annotations.enumeration(annotation, "shape");
                    if (!Set.of("ANY", "NATURAL", "SCALAR").contains(configured)) shape = configured;
                }
            }
        }
        List<Element> jsonValues = typeElement instanceof TypeElement declaredType ? jsonValueMembers(declaredType) : List.of();
        PermissionManifest.JsonFieldType actual;
        if (stringSerializer) {
            actual = PermissionManifest.JsonFieldType.STRING;
        } else if (!jsonValues.isEmpty()) {
            List<Element> values = jsonValues;
            if (values.size() != 1 || values.getFirst().getModifiers().contains(Modifier.STATIC)) {
                throw new IllegalArgumentException("FIELD JsonValue must have one static scalar type");
            }
            Element value = values.getFirst();
            TypeMirror valueType = value.asType();
            if (value instanceof ExecutableElement method) {
                if (!method.getParameters().isEmpty()) throw new IllegalArgumentException("FIELD JsonValue getter must have no parameters");
                valueType = method.getReturnType();
            }
            String scalar = processingEnv.getTypeUtils().erasure(valueType).toString();
            if (Set.of("java.lang.String", "char", "java.lang.Character").contains(scalar)) {
                actual = PermissionManifest.JsonFieldType.STRING;
            } else if (Set.of("boolean", "java.lang.Boolean").contains(scalar)) {
                actual = PermissionManifest.JsonFieldType.BOOLEAN;
            } else if (Set.of("byte", "short", "int", "long", "float", "double", "java.lang.Byte", "java.lang.Short",
                    "java.lang.Integer", "java.lang.Long", "java.lang.Float", "java.lang.Double",
                    "java.math.BigDecimal", "java.math.BigInteger").contains(scalar)) {
                actual = PermissionManifest.JsonFieldType.NUMBER;
            } else throw new IllegalArgumentException("FIELD JsonValue has no statically supported JSON scalar type");
        } else if (name.equals("byte[]")) {
            // Jackson writes binary values as Base64 even when JsonFormat requests ARRAY.
            actual = PermissionManifest.JsonFieldType.STRING;
        } else if (shape != null) {
            boolean scalar = type.getKind().isPrimitive() || name.startsWith("java.lang.")
                    || name.startsWith("java.math.") || name.startsWith("java.time.")
                    || Set.of("java.util.Date", "java.sql.Date", "java.sql.Time", "java.sql.Timestamp",
                            "java.util.Calendar", "java.net.URI", "java.net.URL", "java.util.UUID").contains(name)
                    || typeElement != null && typeElement.getKind() == ElementKind.ENUM;
            if (!scalar) throw new IllegalArgumentException("custom FIELD JsonFormat has no statically supported JSON type");
            actual = switch (shape) {
                case "STRING" -> PermissionManifest.JsonFieldType.STRING;
                case "NUMBER", "NUMBER_INT", "NUMBER_FLOAT" -> PermissionManifest.JsonFieldType.NUMBER;
                case "BOOLEAN" -> PermissionManifest.JsonFieldType.BOOLEAN;
                case "ARRAY" -> PermissionManifest.JsonFieldType.ARRAY;
                case "OBJECT" -> PermissionManifest.JsonFieldType.OBJECT;
                default -> throw new IllegalArgumentException("unsupported FIELD JSON shape");
            };
        } else if (name.startsWith("java.time.") || Set.of("java.util.Date", "java.sql.Date",
                "java.sql.Time", "java.sql.Timestamp", "java.util.Calendar").contains(name)) {
            // A producer's mapper can choose timestamps or arrays; javac must not guess its runtime configuration.
            throw new IllegalArgumentException("temporal FIELD requires explicit @JsonFormat shape");
        } else if (name.equals("java.lang.String") || name.equals("char") || name.equals("java.lang.Character")
                || name.equals("java.net.URI") || name.equals("java.net.URL") || name.equals("java.util.UUID")
                || typeElement != null && typeElement.getKind() == ElementKind.ENUM) {
            actual = PermissionManifest.JsonFieldType.STRING;
        } else if (name.equals("boolean") || name.equals("java.lang.Boolean")) {
            actual = PermissionManifest.JsonFieldType.BOOLEAN;
        } else if (type.getKind().isPrimitive() || Set.of("java.lang.Byte", "java.lang.Short", "java.lang.Integer",
                "java.lang.Long", "java.lang.Float", "java.lang.Double", "java.math.BigDecimal", "java.math.BigInteger").contains(name)) {
            actual = PermissionManifest.JsonFieldType.NUMBER;
        } else if (type.getKind() == TypeKind.ARRAY || assignable(type, "java.util.Collection")) {
            actual = PermissionManifest.JsonFieldType.ARRAY;
        } else actual = PermissionManifest.JsonFieldType.OBJECT;
        if (actual != declared) throw new IllegalArgumentException("FIELD JSON type does not match its Java type: "
                + field.getEnclosingElement() + "." + field.getSimpleName() + " declares " + declared + " but serializes as " + actual);
    }

    private List<Element> jsonValueMembers(TypeElement owner) {
        List<Element> result = new ArrayList<>();
        List<TypeElement> hierarchy = hierarchy(owner);
        for (TypeElement type : hierarchy) {
            for (Element field : ElementFilter.fieldsIn(type.getEnclosedElements())) {
                if (enabledJsonValue(field)) result.add(field);
            }
        }
        for (ExecutableElement method : ElementFilter.methodsIn(processingEnv.getElementUtils().getAllMembers(owner))) {
            List<ExecutableElement> declarations = methodHierarchy(owner, method, hierarchy);
            for (ExecutableElement declaration : declarations) {
                AnnotationMirror value = declaration.getAnnotationMirrors().stream().filter(annotation ->
                        annotations.name(annotation).equals("com.fasterxml.jackson.annotation.JsonValue")).findFirst().orElse(null);
                if (value != null) {
                    if (Boolean.TRUE.equals(annotations.values(value).get("value").getValue())) result.add(method);
                    break;
                }
            }
        }
        return List.copyOf(result);
    }

    private boolean enabledJsonValue(Element element) {
        return element.getAnnotationMirrors().stream().anyMatch(annotation ->
                annotations.name(annotation).equals("com.fasterxml.jackson.annotation.JsonValue")
                        && Boolean.TRUE.equals(annotations.values(annotation).get("value").getValue()));
    }

    private boolean assignable(TypeMirror type, String target) {
        return processingEnv.getTypeUtils().isAssignable(processingEnv.getTypeUtils().erasure(type),
                processingEnv.getTypeUtils().erasure(processingEnv.getElementUtils().getTypeElement(target).asType()));
    }

    private PermissionRequirement fieldGroup(AnnotationMirror rules, String operation) {
        AnnotationMirror group = annotations.nested(rules, operation);
        List<String> codes = annotations.strings(group, "codes");
        return codes.isEmpty() ? null : new PermissionRequirement(PermissionMode.valueOf(annotations.enumeration(group, "mode")), codes);
    }

    private PermissionRequirement requirement(List<? extends Element> declarations) {
        List<PermissionRequirement> groups = new ArrayList<>();
        for (Element declaration : declarations) for (AnnotationMirror annotation : annotations.find(declaration, "RequiresPermissions")) {
            PermissionRequirement group = new PermissionRequirement(PermissionMode.valueOf(annotations.enumeration(annotation, "mode")),
                    annotations.strings(annotation, "codes"));
            if (!groups.contains(group)) groups.add(group);
        }
        return groups.isEmpty() ? null : groups.size() == 1 ? groups.getFirst() : PermissionRequirement.allOf(groups);
    }

    private PermissionManifest.ResourceDefinition resource(AnnotationMirror annotation, Map<String, Object> target,
                                                          PermissionRequirement requirement, PermissionManifest.FieldPolicy fieldPolicy) {
        List<PermissionManifest.PrincipalType> principals = annotations.array(annotation, "allowedPrincipals").stream()
                .map(value -> PermissionManifest.PrincipalType.valueOf(((Element) value.getValue()).getSimpleName().toString())).toList();
        return new PermissionManifest.ResourceDefinition(annotations.text(annotation, "key"),
                ResourceType.valueOf(annotations.enumeration(annotation, "type")), target,
                ResourceAccess.valueOf(annotations.enumeration(annotation, "access")), requirement, fieldPolicy, principals,
                annotations.strings(annotation, "oauthScopes"), i18n(annotation),
                DefinitionLifecycle.valueOf(annotations.enumeration(annotation, "lifecycle")));
    }

    private PermissionManifest.I18nReference i18n(AnnotationMirror annotation) {
        return new PermissionManifest.I18nReference(annotations.text(annotation, "labelPage"), annotations.text(annotation, "labelKey"));
    }

    private List<TypeElement> hierarchy(TypeElement type) {
        Map<String, TypeElement> result = new LinkedHashMap<>();
        collectHierarchy(type, result);
        return List.copyOf(result.values());
    }

    private void collectHierarchy(TypeElement type, Map<String, TypeElement> result) {
        if (type.getQualifiedName().contentEquals("java.lang.Object") || result.putIfAbsent(type.getQualifiedName().toString(), type) != null) return;
        for (TypeMirror parent : processingEnv.getTypeUtils().directSupertypes(type.asType())) {
            if (parent instanceof DeclaredType declared) collectHierarchy((TypeElement) declared.asElement(), result);
        }
    }

    private List<ExecutableElement> methodHierarchy(TypeElement owner, ExecutableElement method, List<TypeElement> hierarchy) {
        List<ExecutableElement> result = new ArrayList<>();
        ExecutableType actual = (ExecutableType) processingEnv.getTypeUtils().asMemberOf((DeclaredType) owner.asType(), method);
        for (TypeElement type : hierarchy) for (ExecutableElement candidate : ElementFilter.methodsIn(type.getEnclosedElements())) {
            if (!candidate.getSimpleName().equals(method.getSimpleName()) || candidate.getModifiers().contains(Modifier.STATIC)
                    || !(candidate.equals(method) || processingEnv.getElementUtils().overrides(method, candidate, owner))) continue;
            ExecutableType inherited = (ExecutableType) processingEnv.getTypeUtils().asMemberOf((DeclaredType) owner.asType(), candidate);
            if (processingEnv.getTypeUtils().isSubsignature(actual, inherited)) result.add(candidate);
        }
        return result;
    }

    private boolean managed(TypeElement type) {
        String name = type.getQualifiedName().toString();
        return listOption("managedPackages").stream().anyMatch(prefix -> name.startsWith(prefix + "."));
    }

    private String option(String key) {
        String value = processingEnv.getOptions().get("pac." + key);
        if (value == null || value.isBlank() || value.contains("${") || value.contains("#{")) {
            throw new IllegalArgumentException("missing or unresolved processor option pac." + key);
        }
        return value;
    }

    private List<String> listOption(String key) {
        List<String> values = Arrays.asList(option(key).split(",", -1));
        if (values.stream().anyMatch(String::isBlank) || values.stream().distinct().count() != values.size()) {
            throw new IllegalArgumentException("invalid processor option pac." + key);
        }
        return values;
    }

    private void writeFragment() throws IOException {
        PermissionManifest manifest = new PermissionManifest(PermissionManifest.SCHEMA_VERSION,
                new PermissionManifest.Application(option("business"), option("application")),
                new PermissionManifest.Producer(option("producer"), PermissionManifest.ProducerKind.JAVA,
                        PermissionManifest.SnapshotMode.PARTIAL, listOption("ownedKeyPrefixes"),
                        listOption("expectedModules"), List.of(option("module")), false),
                new PermissionManifest.Artifact(option("repository"), option("commit"), option("buildId"), option("version")),
                definitions, List.copyOf(references), resources, List.of(), messages);
        String json = new PermissionManifestCanonicalizer().canonicalize(manifest);
        if (json.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > PermissionManifest.MAX_BYTES) {
            throw new IllegalArgumentException("permission fragment exceeds manifest byte limit");
        }
        try (Writer writer = processingEnv.getFiler().createResource(StandardLocation.CLASS_OUTPUT, "", FRAGMENT).openWriter()) {
            writer.write(json);
        }
    }

    private void error(Element element, String message) {
        failed = true;
        processingEnv.getMessager().printMessage(Diagnostic.Kind.ERROR, "permission-manifest: " + message, element);
    }
}
