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

The index must include the target triple, ABI, Android API level, NDK and Rust versions, linker identity, engine/mixins commits, hooks API, API-surface digest, package format, archive sizes and SHA-256 hashes. The installer verifies the release signature, index digest, archive digests and extracted tree before marking an SDK usable. A local install receipt is not a replacement for signature verification. The Rust SDK reader now independently re-verifies the Ed25519 signature over the release checksum inventory whenever it consumes an installed SDK; it does not accept the receipt's `signature_verified` flag as cryptographic proof. This requires the embedded `base64` and `openssl` verification tools at SDK-consumption time as well as install time. The regression test rejects a forged positive receipt when the signed inventory is absent. A full valid-signature fixture test and extracted-tree re-derivation are still outstanding.

SDKs are content-addressed and immutable. A new upstream commit, hook/API surface, compiler, NDK, linker, target or package schema produces a new SDK identity; it must never overwrite an older SDK in place. Keep the last known-good SDK available for rollback. Do not fetch or build SDKs for unsupported targets.

## Verified upstream producer boundary

The upstream SDK publishing workflow has been inspected, not assumed:

- `prebuilt-game-build.yml` creates the SDK slices in separate target-specific build legs, then uploads them as `sdk-leg-*` artifacts.
- Its current target matrix contains Linux x86-64, Linux server x86-64, Windows GNU x86-64 and macOS ARM64. It does **not** contain `aarch64-linux-android`.
- `sdk-publish.yml` gathers those already-built artifacts, creates the API-source archive and index, signs the checksum manifest, then publishes `sdk-<commit>`. It is a pack/sign/publish stage, not an Android cross-compilation implementation.
- This repository's installer requires `runtime`, `api` and `engine` archives for `aarch64-linux-android`. With the upstream matrix as inspected, a normal published SDK cannot satisfy that requirement; the installer must refuse it.

Therefore, adding an Android target name to the installer or publishing desktop slices under an Android filename would be incorrect. The producer itself also assumes a desktop executable model: `tools/prebuilt_game.py` chooses the Rust host triple (`rustc -vV`), derives linker/library naming from the runner's `sys.platform`, and smoke-tests a standalone `horizon-client` executable. Our Android integration instead launches `libhorizon_android_game.so` through Android's native activity/host path. An Android leg therefore needs an Android-specific build/pack/smoke adapter and an explicit mod-link contract; merely adding `aarch64-linux-android` to the matrix would still produce the wrong runtime artifact. The next engineering gate is a real Android ARM64 producer leg that builds and smoke-tests the exact Android runtime/link artifacts using a pinned NDK, Rust toolchain and Android API floor. It must produce all three slices in the layout expected by the installer and prove that the final Android game library links against them. Only then should the SDK be published and consumed by the phone.

The pinned upstream has two related but distinct native extension mechanisms. They must not be conflated:

- The ordinary `.hnmod` native-mod format is a **source-mixin bundle**. The upstream `horizon-native-mod-template` packages `horizon-native.json` plus `mixins/<id>/horizon-mixin.toml` and its Rust helper/module files. `horizon-mixins` plans and applies those declarations to a pristine export of the exact pinned Horizon source before Cargo compiles the resulting game workspace. Injection helpers compile in the target game's crate/module, so they can use that module's normal Rust visibility, borrowing and dependency rules. This is the primary activation model for source-mixin `.hnmod` bundles; it does not require a runtime plugin loader or a non-empty `Mods` collection merely to activate the injected code.
- Separately, `horizon-client::mod_api` exposes a trait-based dispatch API: `Hooks` and `Mods = Arc<[Box<dyn Hooks>]>`. `entry::main_with(mods)` installs that process-wide collection before registering and sealing engine hooks. This is relevant only when an integration deliberately compiles and registers `Hooks` implementors. It is not a generic loader for source-mixin bundles and is not a stable shared-library ABI.
- The Android game still starts through Winit's `android_main(AndroidApp)` inside `libhorizon_android_game.so`, not the upstream standalone `horizon-client` executable. The Android build must preserve that NativeActivity entry point and its input, surface, audio and lifecycle behavior while compiling the planned mixin stage into the Android library.
- The checked-in Android `android_main(AndroidApp)` currently calls `horizon_client::entry::main_with(Default::default())`. That is the empty default when no trait-API crate is attached. The existing `hnmod-core::pc_api::stage` path already handles bundles that declare an `[api]` crate: it stages those crates as workspace members in dependency order, adds them to `horizon-android-game`, and rewrites the staged Android entry point to build `horizon_client::mod_api::Mods` from each crate's `hooks()` before calling `main_with(mods)`. Its unit test covers this generated Android bridge. Ordinary source-mixin bundles without `[api]` do not need this trait list.
- Rust trait objects must not cross an independently compiled shared-library boundary: Rust ABI/layout is not stable. The current `[api]` path compiles the trait crates into the same Android game library, which preserves that boundary. A future dynamically loaded native module would require a deliberately designed, versioned C ABI and lifecycle contract first.

The required Android acceptance gate is therefore a real, reproducible `horizon-mixins plan/apply` stage against the exact pinned source, followed by a successful Android-target compile/link of the resulting workspace while preserving the NativeActivity entry point. The current legacy `build-with-mods.sh` does apply mixins, stages optional trait-API crates and then rebuilds `horizon-android-game`; that proves only the full-game rebuild path, not the SDK-driven incremental/mod-only pipeline.

There is also a repository-identity boundary: the Android game build fetches `horizon-rust/horizon`, while the SDK installer fetches releases from `arismoko/horizon`. For the current pin `d1b6cd286ea4ebafd4e454829e199a867937b77a`, both repositories resolve the commit to the same Git tree `038e808bead7c05f7038dcf5c216ee807036c1bd`; this confirms source-tree identity for this pin, not for future pins automatically. Every SDK producer run must repeat that tree-identity check and attest the Android overlay, patches, toolchain and build inputs as well. A commit string match alone is not sufficient.

## Repository automation

`.github/workflows/android-native-sdk.yml` is the automation entry point:

- It listens for a completed `Android build` workflow so it can follow the repository's rolling Nightly release, which is created by the APK workflow with the repository token.
- It also listens for published version-tag APK builds through the same workflow completion path and supports a manual dispatch for a selected rustMC commit.
- Before any build, it resolves both the exact rustMC commit and the full upstream Horizon commit in `android/UPSTREAM_PIN`.
- It is fail-closed. Until the executable `android/ci/build-native-sdk.sh` producer exists, the run reports that no SDK was published and skips publication. It never relabels desktop SDK files as Android.
- Once implemented, that producer must own the complete pinned NDK/Rust build, SDK slice packaging, reproducibility and Android ELF/link smoke tests, signature verification and immutable publication. A successful APK build alone is not evidence that the native SDK is valid.

The workflow file can be reviewed on a feature branch, but GitHub only activates `workflow_run` triggers after the workflow definition is present on the repository's default branch. Do not merge this PR merely to test the workflow; use a manual run after the producer is complete and merge is explicitly approved.

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
