package top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Set;

/** Owner-only local files form the explicit command boundary, outside normal host startup. */
public final class PermissionBootstrapFiles {
    private static final Set<PosixFilePermission> FILE = PosixFilePermissions.fromString("rw-------");
    private static final Set<PosixFilePermission> DIRECTORY = PosixFilePermissions.fromString("rwx------");

    private PermissionBootstrapFiles() { }

    public static Path path(String value) {
        if (value == null) { throw rejected(); }
        Path path = Path.of(value);
        if (!path.isAbsolute() || !path.equals(path.normalize())) { throw rejected(); }
        return path;
    }

    public static void directory(Path path) throws IOException {
        resolvedDirectory(path);
    }

    private static Path resolvedDirectory(Path path) throws IOException {
        if (path == null || !path.isAbsolute() || !path.equals(path.normalize())) throw rejected();
        if (Files.isSymbolicLink(path) || !Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)
                || !Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS).equals(DIRECTORY)
                || !Files.getOwner(path, LinkOption.NOFOLLOW_LINKS).equals(path.getFileSystem()
                        .getUserPrincipalLookupService().lookupPrincipalByName(System.getProperty("user.name")))) {
            throw rejected();
        }
        var owner = Files.getOwner(path, LinkOption.NOFOLLOW_LINKS);
        trustedAncestors(path, owner, true);
        Path resolved = path.toRealPath();
        trustedAncestors(resolved, owner, false);
        // All opens use this trusted resolved path, independently of aliases in the operator input.
        return resolved;
    }

    private static void trustedAncestors(Path directory, java.nio.file.attribute.UserPrincipal owner, boolean allowAliases) throws IOException {
        for (Path ancestor = directory; ancestor != null; ancestor = ancestor.getParent()) {
            var attributes = Files.readAttributes(ancestor, java.nio.file.attribute.PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            boolean root = ((Number) Files.getAttribute(ancestor, "unix:uid", LinkOption.NOFOLLOW_LINKS)).longValue() == 0;
            boolean alias = attributes.isSymbolicLink();
            boolean writable = attributes.permissions().contains(PosixFilePermission.GROUP_WRITE)
                    || attributes.permissions().contains(PosixFilePermission.OTHERS_WRITE);
            boolean stickyRoot = !ancestor.equals(directory) && root
                    && (((Number) Files.getAttribute(ancestor, "unix:mode", LinkOption.NOFOLLOW_LINKS)).intValue() & 01000) != 0;
            if (!attributes.owner().equals(owner) && !root || !attributes.isDirectory() && !(allowAliases && alias)
                    || !alias && writable && !stickyRoot) throw rejected();
        }
    }

    public static void file(Path path) throws IOException {
        privateFile(path);
    }

    private static Path privateFile(Path path) throws IOException {
        path = resolvedDirectory(path.getParent()).resolve(path.getFileName());
        if (Files.isSymbolicLink(path) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                || !Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS).equals(FILE)
                || !Files.getOwner(path, LinkOption.NOFOLLOW_LINKS).equals(Files.getOwner(path.getParent()))) {
            throw rejected();
        }
        return path;
    }

    public static byte[] read(Path path, int limit) throws IOException {
        path = privateFile(path);
        try (var input = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
            byte[] bytes = input.readNBytes(limit + 1);
            if (bytes.length > limit) { Arrays.fill(bytes, (byte) 0); throw rejected(); }
            return bytes;
        }
    }

    public static void create(Path path, byte[] bytes) throws IOException {
        path = resolvedDirectory(path.getParent()).resolve(path.getFileName());
        try (var output = FileChannel.open(path, Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE,
                LinkOption.NOFOLLOW_LINKS), PosixFilePermissions.asFileAttribute(FILE))) {
            var buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) { output.write(buffer); }
            output.force(true);
        }
    }

    public static void receipt(Path path, byte[] bytes) throws IOException {
        path = resolvedDirectory(path.getParent()).resolve(path.getFileName());
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            if (!MessageDigest.isEqual(read(path, 1048576), bytes)) { throw rejected(); }
            return;
        }
        Path temporary = path.resolveSibling("." + path.getFileName() + "." + java.util.UUID.randomUUID());
        try {
            create(temporary, bytes);
            try { Files.createLink(path, temporary); }
            catch (java.nio.file.FileAlreadyExistsException concurrent) {
                if (!MessageDigest.isEqual(read(path, 1048576), bytes)) throw rejected();
            }
        } finally { Files.deleteIfExists(temporary); }
    }

    public static String digest(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }

    public static IllegalArgumentException rejected() { return new IllegalArgumentException("PERMISSION_BOOTSTRAP_INPUT_UNSAFE"); }
}
