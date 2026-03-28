# Reproducible build orchestration for Continuum Ghost crypto-core.
#
# Key properties:
#   - Bit-identical output across builds (same source → same binary)
#   - SBOM generation (CycloneDX) for supply chain transparency
#   - SHA-256 manifest for build verification
#   - dudect constant-time verification
#
# Usage:
#   make build              — reproducible release build
#   make verify             — build twice, compare SHA-256 (must match)
#   make sbom               — generate CycloneDX SBOM
#   make manifest           — SHA-256 checksums of all build artifacts
#   make dudect             — run constant-time timing verification
#   make all                — build + sbom + manifest
#   make clean              — remove build artifacts

SHELL := /bin/bash
.PHONY: build verify sbom manifest dudect all clean test

# --- Reproducibility flags ---
# These eliminate sources of non-determinism in the Rust compiler output.

export CARGO_INCREMENTAL    := 0
export SOURCE_DATE_EPOCH    := 0
export RUSTFLAGS            := -C codegen-units=1 -C strip=symbols
export CARGO_ENCODED_RUSTFLAGS :=

# Artifact directories
BUILD_DIR    := target/release
MANIFEST     := build-manifest.sha256
SBOM_FILE    := sbom-crypto-core.cdx.json

# --- Targets ---

all: build sbom manifest

build:
	@echo "=== Reproducible build: crypto-core ==="
	cargo build --release --locked
	@echo "=== Build complete ==="

test:
	cargo test --locked

dudect:
	@echo "=== dudect constant-time verification ==="
	cargo bench --bench dudect_constant_time --locked 2>/dev/null || true
	$(BUILD_DIR)/deps/dudect_constant_time-* 2>&1 | tee dudect-results.txt
	@echo "=== dudect complete (check dudect-results.txt) ==="

verify:
	@echo "=== Reproducibility verification: build #1 ==="
	$(MAKE) clean
	$(MAKE) build
	@echo "=== Capturing checksums from build #1 ==="
	find $(BUILD_DIR) -maxdepth 1 \( -name '*.rlib' -o -name '*.so' -o -name '*.a' \) \
		-exec sha256sum {} \; | sort -k2 > /tmp/ghost-build-1.sha256
	@echo "=== Reproducibility verification: build #2 ==="
	$(MAKE) clean
	$(MAKE) build
	@echo "=== Capturing checksums from build #2 ==="
	find $(BUILD_DIR) -maxdepth 1 \( -name '*.rlib' -o -name '*.so' -o -name '*.a' \) \
		-exec sha256sum {} \; | sort -k2 > /tmp/ghost-build-2.sha256
	@echo "=== Comparing builds ==="
	@if diff -q /tmp/ghost-build-1.sha256 /tmp/ghost-build-2.sha256 > /dev/null 2>&1; then \
		echo "✅ REPRODUCIBLE: builds are bit-identical"; \
		cat /tmp/ghost-build-1.sha256; \
	else \
		echo "❌ NOT REPRODUCIBLE: builds differ"; \
		diff /tmp/ghost-build-1.sha256 /tmp/ghost-build-2.sha256; \
		exit 1; \
	fi

sbom:
	@echo "=== Generating SBOM (CycloneDX) ==="
	cargo cyclonedx --format json
	@mv bom.json $(SBOM_FILE) 2>/dev/null || mv twofapi-crypto-core.cdx.json $(SBOM_FILE) 2>/dev/null || \
		find . -maxdepth 1 -name '*.cdx.json' -o -name 'bom.json' | head -1 | xargs -I{} mv {} $(SBOM_FILE)
	@echo "=== SBOM written to $(SBOM_FILE) ==="
	@echo "Components: $$(python3 -c "import json; d=json.load(open('$(SBOM_FILE)')); print(len(d.get('components',[])))" 2>/dev/null || echo '?')"

manifest:
	@echo "=== Generating build manifest ==="
	@echo "# Continuum Ghost crypto-core build manifest" > $(MANIFEST)
	@echo "# Generated: $$(date -u -Iseconds)" >> $(MANIFEST)
	@echo "# Rust: $$(rustc --version)" >> $(MANIFEST)
	@echo "# Platform: $$(uname -srm)" >> $(MANIFEST)
	@echo "" >> $(MANIFEST)
	find $(BUILD_DIR) -maxdepth 1 \( -name '*.rlib' -o -name '*.so' -o -name '*.a' -o -name '*.rmeta' \) \
		-exec sha256sum {} \; | sort -k2 >> $(MANIFEST)
	@echo "" >> $(MANIFEST)
	@echo "# Source files" >> $(MANIFEST)
	find src/ -name '*.rs' -exec sha256sum {} \; | sort -k2 >> $(MANIFEST)
	@echo "=== Manifest written to $(MANIFEST) ==="

clean:
	cargo clean
	rm -f $(MANIFEST) $(SBOM_FILE) dudect-results.txt
