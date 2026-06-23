@GetMapping("/files")
public ResponseEntity<byte[]> getFile(@RequestParam String name) throws IOException {
    Path filePath = Paths.get("/var/data").resolve(name);
    return ResponseEntity.ok(Files.readAllBytes(filePath));
}
