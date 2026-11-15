# Android native HMOD architecture

Status: design contract; implementation is incomplete. A green APK build is not evidence that native HMOD compilation works.

## Goals

- Keep Horizon's upstream native-mod format, manifest semantics, hook API and mixin semantics. Do not invent an Android-only mod API.
- Build for Android ARM64 (aarch64-linux-android) on the device, using the app-private embedded toolchain. No separate Termux installation is required.
- Reuse a verified, immutable SDK for an exact Horizon game commit. A mod-only rebuild must not rebuild the complete game.
- Keep content .hmod, native .hmod (where the upstream format declares native code), legacy .hnmod, and .hpack distinct. Never route one format through another parser.
- Preserve the existing full-game .hnmod build as an explicit compatibility fallback until the new path is proven.
- Never merge, activate, or execute untrusted native code silently.

## Compatibility contract

Every native build is bound to all of the following, not just a version label:

1. Minecraft/game version and exact Horizon source commit.
2. horizon-mixins exact commit and patch digest.
3. Native hooks API level and a digest of the public native API surface.
4. Android target triple, ABI (arm64-v8a), Android API floor, NDK revision, linker identity and Rust toolchain identity.
5. SDK schema/package format and hashes of every downloaded slice.
6. Mod IDs, versions, archive hashes, dependency graph and enabled profile.
7. Build profile and all feature/configuration inputs that can affect generated code.

A mismatch is a typed refusal with a useful diagnostic. Never silently substitute a desktop SDK, a newer engine, a different NDK, or a different mod version. Never use a timestamp as a substitute for a commit identity.

## SDK release model

Publish one immutable SDK per compatible Horizon commit and Android build identity. The index is signed and has a monotonically versioned schema. It describes three separately downloadable slices:

- runtime: Android-compatible runtime libraries and the exact runtime/link contract.
- api: public mod API crates, proc-macro metadata/templates and the public API surface description.
- engine: the reusable prebuilt engine/game dependency artifacts needed by the native build.

The index must include the target triple, ABI, Android API level, NDK and Rust versions, linker identity, engine/mixins commits, hooks API, API-surface digest, package format, archive sizes and SHA-256 hashes. The installer verifies the release signature, index digest, archive digests and extracted tree before marking an SDK usable. A local install receipt is not a replacement for signature verification.

SDKs are content-addressed and immutable. A new upstream commit, hook/API surface, compiler, NDK, linker, target or package schema produces a new SDK identity; it must never overwrite an older SDK in place. Keep the last known-good SDK available for rollback. Do not fetch or build SDKs for unsupported targets.

## On-device build pipeline

1. Import into an immutable staging directory; reject path traversal, duplicate IDs, oversized archives and malformed manifests.
2. Resolve all selected mods and dependencies deterministically. Validate game/engine/mixins/API pins before extracting executable source.
3. Show the complete native-code trust prompt before any build script, proc macro or native code can execute. The build is not a sandbox.
4. Verify/select the exact signed Android SDK and toolchain. Install or reuse the app-private ARM64 toolchain; never rely on the host shell or user-installed Termux.
5. Compile mod crates in dependency order against the SDK and locked dependency graph.
6. Apply upstream mixin semantics to the exact pinned source/API and produce the native patch artifact.
7. Link the final Android game library using the SDK's declared link contract. Validate ELF machine, Android API requirements, NEEDED libraries, exported JNI/runtime entry points and package hashes.
8. Install to a new versioned build directory, atomically switch the selected profile only after all checks pass, and retain the previous working build for rollback.
9. Launch with the selected profile. A failed compile/link/import must leave the active build untouched.

The key performance acceptance criterion is that a mod-only rebuild reuses the SDK and unchanged engine dependencies. It may rebuild the mod crates, generated patch artifact and final Android link target. It must not rerun the complete Horizon game build. If the SDK cannot support that contract yet, report the legacy full-game build path honestly rather than labelling it an SDK build.

## Cache identity and invalidation

Use a deterministic SHA-256 build key over canonical, length-delimited values for every compatibility-contract item, the sorted mod archive hashes, dependency lock data, build profile and SDK index digest. Do not include mutable paths, wall-clock time, UI labels or unordered map iteration. Store a machine-readable build receipt beside every output. Verify the receipt and library hash before reuse.

Separate caches by target triple, ABI, Android API floor, NDK/linker identity, Rust toolchain, engine commit, mixins commit, SDK schema and build profile. Prune only unreferenced cache entries; never delete the active build or the last known-good rollback target.

## Android runtime and ABI boundary

Keep Android lifecycle, JNI, input, audio, surfaces and Vulkan integration in the Android module/overlay. Do not add Android-only conditionals throughout upstream game logic when an adapter or isolated crate can own the platform boundary.

Prefer linking native mod code into the versioned game library using upstream's supported build model. Do not invent a dlopen plugin ABI unless upstream explicitly defines a stable registration/ABI contract. Rust trait objects and Rust symbol layouts are not stable cross-library ABIs. If a separate shared library is ever required, define and version a narrow C ABI with explicit ownership, error and lifecycle rules first.

## Format and profile behavior

- Content .hmod: validate and install data only; do not invoke Cargo.
- Native .hmod: validate native manifest and build against the matching Android SDK.
- Legacy .hnmod: retain the existing compatibility pipeline until migration is complete; clearly label its full-game rebuild behavior.
- .hpack: resolve and verify package contents, then install into a profile. Installation is not activation. Profile activation is an explicit atomic operation.
- Multiple mods: resolve dependency order, reject duplicate IDs and incompatible pins, and build one profile as one transaction.
- Disable/remove: produce or select a profile without the mod; do not mutate an already-built active library in place.

## Required CI and device tests

Before declaring Android native HMOD support complete:

- SDK producer reproducibility test: same pinned inputs yield the same SDK identity and verified hashes.
- Signature, archive hash, extracted-tree hash, wrong-key and tampered-file rejection tests.
- Cross-target refusal tests: desktop SDK, wrong ABI, wrong Android API floor, wrong NDK/linker, wrong engine/mixins/API surface.
- Resolver tests: one mod, two independent mods, dependency ordering, cycles, duplicate IDs, conflicting pins and optional dependencies.
- Build tests: clean build, warm-cache build, change one mod, disable one mod, rollback, interrupted build and low-storage failure.
- Runtime tests on physical ARM64 devices: cold launch, relaunch, crash diagnostics, Vulkan startup, touch/input, audio and world load.
- Confirm by build logs and artifact hashes that changing a mod does not rebuild the complete game.
- Test at least one Qualcomm/Adreno and one Mali device before claiming broad Android GPU compatibility.

## Current implementation gap

The repository already contains an SDK identity/verification model, an Android-target resolver and multi-mod planning tests. However, the current android/termux/build-with-mods.sh still applies mixins to an engine source tree and builds horizon-android-game; that is the legacy full-game rebuild path. The Android SDK producer, complete native build executor, SDK-driven linker integration and end-to-end native HMOD runtime activation are not yet proven. Keep this status visible until the tests above pass.
