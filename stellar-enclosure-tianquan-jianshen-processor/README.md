# Permission manifest compiler

The processor reads compiler symbols and the shared contract. It does not start Spring, load application classes, register resources, or contact a server. Declare API identities with `@PermissionResource` on mapped controller methods, permission groups with repeatable `@RequiresPermissions` on types or methods, and DTO field rules with `@FieldPermissions`. Definitions, explicit references and source messages belong on a type or `package-info.java`.

Every nonempty ALL/ANY group from the controller hierarchy and method hierarchy is retained and combined with AND. PUBLIC cannot erase an inherited group. Field plain-read, masked-read and write groups are independent; an omitted operation denies access. Explicit PUBLIC/INTERNAL fields carry no protected field rules; their classification never makes a read-only response property writable. A FIELD getter must be a bean getter or a record accessor. The exporter rejects unresolved generic field types, unsupported resource targets, ambiguous mappings, dynamic Spring placeholders and incompatible mask output types.

Configure `stellar-enclosure-tianquan-jianshen-processor` explicitly in the producer's existing `maven-compiler-plugin.annotationProcessorPaths`, retaining Lombok, MapStruct and other processors. Pass all of these non-secret compiler options:

```text
-Apac.business=<businessCode>
-Apac.application=<applicationCode>
-Apac.producer=<producerId>
-Apac.module=<currentModule>
-Apac.expectedModules=<comma-separated-complete-module-list>
-Apac.ownedKeyPrefixes=<comma-separated-resource-key-prefixes>
-Apac.managedPackages=<comma-separated-controller-package-prefixes>
-Apac.repository=<repository>
-Apac.commit=<full-lowercase-git-object-id>
-Apac.buildId=<buildId>
-Apac.version=<artifactVersion>
```

The build must use filesystem `CLASS_OUTPUT`. A new processing run invalidates its previous fragment. The compiler emits `META-INF/permissions/fragment-v1.json` with `snapshotMode=PARTIAL`; it never emits FULL. Java body errors can be reported after annotation processing, so a fragment is not proof that compilation succeeded. Packaging/aggregation must run only after the compiler and package command return success, and must exclude stale artifacts from failed or skipped modules.

`PermissionManifestAggregator` accepts fragments extracted from successfully built, digest-checked module artifacts. It rejects missing/duplicate modules, differing provenance, conflicting keys and empty FULL manifests without explicit clear intent. The caller supplies the SHA-256 of each actual built artifact and owns the successful-build gate. Aggregation resolves references to definitions owned by another module of the same producer. Its result is the shared canonical Manifest, not a runtime permission grant.

Supported Spring targets preserve multiple paths, HTTP methods (including GET's HEAD matching), params, headers, consumes, produces and API version. Class/method HTTP methods follow Spring's union semantics. Composed mappings can use compiler-visible `AliasFor` directly to a Spring mapping; unresolved alias chains fail rather than export a guessed target. A controller mapping inside `managedPackages` requires a resource declaration even when PUBLIC or INTERNAL. Full producer builds should invoke a clean compile of every expected module; incremental processing cannot establish that untouched source files were scanned.

Run the compiler-only tests without starting any application:

```sh
./mvnw -B -ntp -pl :stellar-enclosure-tianquan-jianshen-processor -am test
```

FIELD wire types follow compiler-visible Jackson metadata, including record backing fields/accessors and JSON property aliases. Standard enums, URI/URL/UUID and unique scalar `@JsonValue` getters are supported; inherited getters are resolved without executing them. Temporal values need an explicit `@JsonFormat` shape because a runtime mapper may select text, arrays or numeric timestamps. Known `ToStringSerializer` output takes precedence; arbitrary serializers, ambiguous/multiple `@JsonValue` members and dynamic value types fail compilation. Unresolved Maven-style placeholders in compiler provenance options are rejected. Empty method paths retain the class path without inventing a trailing slash; a root mapping must explicitly declare `/`.
