(async () => {
    "use strict";

    const PREFIX = "[STAR-AGE-DIAGNOSTICS]";

    const log = (...args) => console.log(PREFIX, ...args);
    const warn = (...args) => console.warn(PREFIX, ...args);
    const fail = (...args) => console.error(PREFIX, ...args);

    function section(title) {
        console.group(`${PREFIX} ${title}`);
    }

    function endSection() {
        console.groupEnd();
    }

    function safe(fn, fallback = "unavailable") {
        try {
            return fn();
        } catch {
            return fallback;
        }
    }

    try {
        // ============================================================
        // 1. PAGE / BROWSER ENVIRONMENT
        // ============================================================

        section("Environment");

        console.table({
            href: location.href,
            origin: location.origin,
            protocol: location.protocol,
            readyState: document.readyState,
            userAgent: navigator.userAgent,
            language: navigator.language,
            platform: navigator.platform,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            timezoneOffset: new Date().getTimezoneOffset(),
            cookiesEnabled: navigator.cookieEnabled,
            webdriver: navigator.webdriver,
            hardwareConcurrency: navigator.hardwareConcurrency,
            deviceMemory: navigator.deviceMemory ?? "unavailable",
            online: navigator.onLine
        });

        endSection();

        // ============================================================
        // 2. MEDIA PERMISSIONS / CAMERA ENUMERATION
        // ============================================================

        section("Camera / Media Devices");

        if (!navigator.mediaDevices) {
            warn("navigator.mediaDevices is unavailable.");
        } else {
            if (navigator.permissions?.query) {
                for (const name of ["camera", "microphone"]) {
                    try {
                        const permission =
                            await navigator.permissions.query({ name });

                        log(`${name} permission:`, permission.state);

                        permission.onchange = () => {
                            log(`${name} permission changed:`, permission.state);
                        };
                    } catch (error) {
                        warn(`Unable to query ${name} permission:`, error.message);
                    }
                }
            }

            try {
                const devices =
                    await navigator.mediaDevices.enumerateDevices();

                console.table(
                    devices.map((device, index) => ({
                        index,
                        kind: device.kind,
                        label: device.label || "(permission required)",
                        deviceIdPresent: Boolean(device.deviceId),
                        groupIdPresent: Boolean(device.groupId)
                    }))
                );

                const cameras =
                    devices.filter(d => d.kind === "videoinput");

                const microphones =
                    devices.filter(d => d.kind === "audioinput");

                log("Cameras detected:", cameras.length);
                log("Microphones detected:", microphones.length);
            } catch (error) {
                fail("Device enumeration failed:", error);
            }
        }

        endSection();

        // ============================================================
        // 3. CAMERA ACCESS TEST
        // ============================================================

        section("Camera Access Test");

        if (!navigator.mediaDevices?.getUserMedia) {
            warn("getUserMedia() is unavailable.");
        } else {
            try {
                const stream = await navigator.mediaDevices.getUserMedia({
                    video: true,
                    audio: false
                });

                const tracks = stream.getVideoTracks();

                console.table(
                    tracks.map(track => ({
                        label: track.label,
                        enabled: track.enabled,
                        muted: track.muted,
                        readyState: track.readyState,
                        settings: JSON.stringify(track.getSettings())
                    }))
                );

                // Diagnostic only: immediately release the camera.
                for (const track of tracks) {
                    track.stop();
                }

                log("Camera access succeeded.");
            } catch (error) {
                fail("Camera access failed:", {
                    name: error?.name,
                    message: error?.message
                });

                if (error?.name === "NotAllowedError") {
                    warn("Camera permission was denied or blocked.");
                }

                if (error?.name === "NotFoundError") {
                    warn("No usable camera was found.");
                }

                if (error?.name === "NotReadableError") {
                    warn("Camera exists but could not be opened.");
                }
            }
        }

        endSection();

        // ============================================================
        // 4. DISPLAY / GRAPHICS CAPABILITIES
        // ============================================================

        section("Display / Graphics");

        const canvas = document.createElement("canvas");
        const gl =
            canvas.getContext("webgl") ||
            canvas.getContext("experimental-webgl");

        console.table({
            screenWidth: screen.width,
            screenHeight: screen.height,
            devicePixelRatio: window.devicePixelRatio,
            colorDepth: screen.colorDepth,
            canvasWebGL: Boolean(gl),
            webGLVendor: safe(
                () => gl.getParameter(gl.VENDOR)
            ),
            webGLRenderer: safe(
                () => gl.getParameter(gl.RENDERER)
            )
        });

        endSection();

        // ============================================================
        // 5. WEBPACK / DISCORD RUNTIME DISCOVERY
        // ============================================================
        //
        // Diagnostic only.
        // Does not call internal APIs or alter application state.
        // ============================================================

        section("Discord Runtime");

        let webpackRuntime = null;

        for (const key of Object.keys(window)) {
            if (
                key.startsWith("webpackChunk") &&
                Array.isArray(window[key])
            ) {
                webpackRuntime = window[key];
                log("Webpack chunk detected:", key);
                break;
            }
        }

        if (!webpackRuntime) {
            warn("Webpack chunk runtime was not discovered.");
        } else {
            log("Discord webpack runtime is present.");
        }

        endSection();

        // ============================================================
        // 6. VERIFICATION-RELATED DOM INSPECTION
        // ============================================================

        section("Verification UI");

        const text = document.body?.innerText || "";

        const keywords = [
            "age verification",
            "verify your age",
            "verification",
            "identity",
            "camera",
            "date of birth"
        ];

        const matches = keywords.filter(keyword =>
            text.toLowerCase().includes(keyword)
        );

        console.table(
            keywords.map(keyword => ({
                keyword,
                detected: matches.includes(keyword)
            }))
        );

        const frames = [...document.querySelectorAll("iframe")];

        log("iframes detected:", frames.length);

        if (frames.length) {
            console.table(
                frames.map((frame, index) => ({
                    index,
                    src: frame.src || "(no src)",
                    title: frame.title || "(no title)"
                }))
            );
        }

        endSection();

        // ============================================================
        // 7. NETWORK RESOURCE OBSERVATION
        // ============================================================
        //
        // We inspect resources already loaded by the page.
        // No requests are generated and no verification request is sent.
        // ============================================================

        section("Loaded Verification-Related Resources");

        const resources = performance.getEntriesByType("resource");

        const relevant = resources.filter(resource => {
            const name = resource.name.toLowerCase();

            return (
                name.includes("verify") ||
                name.includes("verification") ||
                name.includes("age") ||
                name.includes("identity")
            );
        });

        if (relevant.length) {
            console.table(
                relevant.map(resource => ({
                    name: resource.name,
                    durationMs: Math.round(resource.duration),
                    transferSize: resource.transferSize,
                    initiatorType: resource.initiatorType
                }))
            );
        } else {
            log("No matching verification resources were found.");
        }

        endSection();

        // ============================================================
        // 8. LOCAL STORAGE / SESSION STORAGE KEYS
        // ============================================================
        //
        // Keys only — values are intentionally not printed.
        // ============================================================

        section("Browser Storage");

        console.table({
            localStorageKeys: safe(
                () => Object.keys(localStorage).length,
                "unavailable"
            ),
            sessionStorageKeys: safe(
                () => Object.keys(sessionStorage).length,
                "unavailable"
            )
        });

        log(
            "Storage values are intentionally not displayed."
        );

        endSection();

        // ============================================================
        // 9. FINAL DIAGNOSTIC SUMMARY
        // ============================================================

        section("Summary");

        const cameraAvailable =
            Boolean(navigator.mediaDevices);

        const secureContext =
            window.isSecureContext;

        const online =
            navigator.onLine;

        console.table({
            secureContext,
            mediaDevicesAPI: cameraAvailable,
            networkOnline: online,
            documentReady: document.readyState === "complete",
            verificationTextDetected: matches.length > 0,
            iframeCount: frames.length
        });

        log(
            "Diagnostic scan complete."
        );

        log(
            "No age-verification result was generated, modified, forged, " +
            "or submitted by this script."
        );

        endSection();

    } catch (error) {
        fail("Unexpected diagnostic failure:", error);
    }
})();