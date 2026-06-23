@GetMapping("/files")
public ResponseEntity<byte[]> getFile(@RequestParam String name) throws IOException {
    Path base = Paths.get("/var/data");
    Path target = base.resolve(name).normalize();
    if (!target.startsWith(base)) {
        return ResponseEntity.status(403).build();
    }
    return ResponseEntity.ok(Files.readAllBytes(target));
}
