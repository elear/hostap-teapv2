# Dockerfile for building and testing hostapd + wpa_supplicant
# (including the in-tree EAP-TEAPv2 work)
#
# Based on Debian Bookworm. Designed for a Linux host.
#
# ---------------------------------------------------------------------------
# BUILD
# ---------------------------------------------------------------------------
#   docker build -t hostap-test .
#
# During the build the image will:
#   1. install all build + test dependencies
#   2. build hostapd, wpa_supplicant, wlantest, hlr_auc_gw, hs20-osu-client
#      and the TNC helper tools (via tests/hwsim/build.sh)
#   3. build and run the in-tree unit-test suite under tests/  (fails the
#      build if any unit test fails)
#
# ---------------------------------------------------------------------------
# RUN modes
# ---------------------------------------------------------------------------
# The container's entrypoint is /usr/local/bin/hostap-test-entrypoint.
# Supported invocations:
#
#   docker run --rm hostap-test unit
#       Rebuild + run the unit-test suite under tests/. Requires no
#       special host kernel state.
#
#   docker run --rm --privileged \
#              --cap-add=NET_ADMIN --cap-add=SYS_ADMIN \
#              -v /lib/modules:/lib/modules:ro \
#              -v /sys/kernel/debug:/sys/kernel/debug \
#              hostap-test hwsim [ap_open ap_wpa2_psk ...]
#       Run the mac80211_hwsim-based integration suite. See
#       "Driver management" below.  With no test names, runs the full
#       suite via tests/hwsim/run-all.sh.
#
#   docker run --rm hostap-test shell
#   docker run -it --rm hostap-test bash
#       Interactive shell inside the built image.
#
# ---------------------------------------------------------------------------
# Driver management (host Linux -> container)
# ---------------------------------------------------------------------------
# The hwsim suite in tests/hwsim/ requires the mac80211_hwsim kernel
# module. The module lives on the *host* kernel; the container reuses
# the host's kernel via bind-mounted /lib/modules and elevated caps.
#
# 1. Host: ensure the module is available for your running kernel.
#      apt install linux-modules-extra-$(uname -r)        # Debian/Ubuntu
#      # or:
#      dnf install kernel-modules-extra                    # Fedora/RHEL
#    Verify:
#      modinfo mac80211_hwsim
#
# 2. Host: (recommended) do NOT preload the module. tests/hwsim/start.sh
#    calls `modprobe mac80211_hwsim radios=7 channels=1 support_p2p_device=0`
#    from inside the container.  If you *did* preload it, unload first:
#      sudo rmmod mac80211_hwsim
#
# 3. Host: mask systemd-rfkill so hwsim radios are not blocked:
#      sudo systemctl mask systemd-rfkill.service
#      sudo systemctl stop systemd-rfkill.service
#    (see tests/hwsim/example-setup.txt for the failure signature.)
#
# 4. Host: stop NetworkManager/wpa_supplicant on the host while tests
#    run, otherwise they will steal the hwsim wlanN interfaces:
#      sudo systemctl stop NetworkManager wpa_supplicant
#
# 5. Container flags required for mac80211_hwsim + iproute2 + tshark:
#      --privileged                  (needed for modprobe + nl80211 ops)
#      --cap-add=NET_ADMIN
#      --cap-add=SYS_ADMIN
#      -v /lib/modules:/lib/modules:ro
#      -v /sys/kernel/debug:/sys/kernel/debug
#    Optional but useful:
#      --tmpfs /run
#      --network host              (only if you need to reach a host RADIUS)
#
# 6. Kernel config on the host must include:
#      CONFIG_MAC80211_HWSIM=m
#      CONFIG_CFG80211=y or m
#      CONFIG_MAC80211=y or m
#      CONFIG_NL80211_TESTMODE=y   (a handful of tests use this)
#    Most stock distro kernels already satisfy this.
#
# 7. Cleanup after a run:
#      # inside container, run by the entrypoint automatically:
#      tests/hwsim/stop.sh
#      # on host, if the module was loaded by the container:
#      sudo rmmod mac80211_hwsim
#
# The unit-test target does not need any of this — the "unit" entrypoint
# runs happily inside an unprivileged container.
#
# ---------------------------------------------------------------------------

FROM debian:bookworm

LABEL description="hostapd + wpa_supplicant build/test image (EAP-TEAPv2)"

ENV DEBIAN_FRONTEND=noninteractive

# ---------------------------------------------------------------------------
# 1. Install build + test dependencies
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core build tools
    build-essential \
    pkg-config \
    git \
    make \
    # OpenSSL (TLS, crypto)
    libssl-dev \
    # netlink (nl80211 driver)
    libnl-3-dev \
    libnl-genl-3-dev \
    libnl-route-3-dev \
    # D-Bus (ctrl iface + dbus tests)
    libdbus-1-dev \
    dbus \
    # SQLite (EAP-SIM DB, HS20)
    libsqlite3-dev \
    # binutils BFD (WPA_TRACE_BFD backtraces)
    binutils-dev \
    libiberty-dev \
    # zlib (needed by bfd/trace)
    zlib1g-dev \
    # libpcap (wlantest / hwsim)
    libpcap-dev \
    # MACsec
    libmnl-dev \
    # readline (hostapd_cli / wpa_cli)
    libreadline-dev \
    # Runtime tools required by tests/hwsim
    iw \
    iproute2 \
    bridge-utils \
    ebtables \
    iptables \
    tshark \
    tcpdump \
    kmod \
    socat \
    procps \
    psmisc \
    net-tools \
    ethtool \
    hostname \
    openssl \
    sudo \
    # Python + libraries the hwsim scripts import
    python3 \
    python3-pip \
    python3-cryptography \
    python3-pyrad \
    python3-netifaces \
    python3-openssl \
    python3-dbus \
    python3-gi \
    # Misc utilities
    ca-certificates \
    wget \
    curl \
    file \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# 2. Copy source tree
# ---------------------------------------------------------------------------
WORKDIR /hostap
COPY . /hostap

# ---------------------------------------------------------------------------
# 3. Build hostapd (with hwsim example config)
# ---------------------------------------------------------------------------
RUN cp tests/hwsim/example-hostapd.config hostapd/.config && \
    make -C hostapd -j"$(nproc)" 2>&1 | tee /tmp/hostapd-build.log && \
    install -m 755 hostapd/hostapd     /usr/local/sbin/hostapd && \
    install -m 755 hostapd/hostapd_cli /usr/local/sbin/hostapd_cli && \
    if [ -x hostapd/hlr_auc_gw ]; then \
        install -m 755 hostapd/hlr_auc_gw /usr/local/sbin/hlr_auc_gw; \
    fi

# ---------------------------------------------------------------------------
# 4. Build wpa_supplicant (with hwsim example config)
# ---------------------------------------------------------------------------
RUN cp tests/hwsim/example-wpa_supplicant.config wpa_supplicant/.config && \
    make -C wpa_supplicant -j"$(nproc)" 2>&1 | tee /tmp/wpa_supplicant-build.log && \
    install -m 755 wpa_supplicant/wpa_supplicant /usr/local/sbin/wpa_supplicant && \
    install -m 755 wpa_supplicant/wpa_cli        /usr/local/sbin/wpa_cli

# ---------------------------------------------------------------------------
# 5. Build wlantest, hs20-osu-client, TNC helpers, and hlr_auc_gw explicitly
#    (mirrors tests/hwsim/build.sh — needed by the hwsim harness)
# ---------------------------------------------------------------------------
RUN make -C wlantest -j"$(nproc)" && \
    install -m 755 wlantest/wlantest      /usr/local/sbin/wlantest && \
    install -m 755 wlantest/wlantest_cli  /usr/local/sbin/wlantest_cli

RUN make -C hostapd -j"$(nproc)" hostapd_cli hlr_auc_gw && \
    install -m 755 hostapd/hlr_auc_gw /usr/local/sbin/hlr_auc_gw

RUN make -C hs20/client -j"$(nproc)" CONFIG_NO_BROWSER=1

RUN make -C tests/hwsim/tnc -j"$(nproc)"

# ---------------------------------------------------------------------------
# 6. Build + run the unit-test suite in tests/
#    (fails the docker build if any test binary returns non-zero)
# ---------------------------------------------------------------------------
RUN make -C tests -j"$(nproc)" 2>&1 | tee /tmp/unit-build.log

RUN set -eux; \
    cd tests; \
    fail=0; \
    for t in test-base64 test-md4 test-milenage test-rsa-sig-ver \
             test-sha1 test-sha256 test-aes test-x509v3 test-list \
             test-rc4 test-bss; do \
        if [ -x "./$t" ]; then \
            echo "=== running $t ==="; \
            if ! "./$t"; then \
                echo "*** unit test $t FAILED"; \
                fail=1; \
            fi; \
        else \
            echo "*** unit test binary $t not built" >&2; \
            fail=1; \
        fi; \
    done; \
    [ $fail -eq 0 ]

# ---------------------------------------------------------------------------
# 7. sudo configuration (hwsim scripts use `sudo` unconditionally)
# ---------------------------------------------------------------------------
RUN echo 'root ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/root-nopasswd && \
    chmod 0440 /etc/sudoers.d/root-nopasswd

# ---------------------------------------------------------------------------
# 8. Smoke test: verify binaries link and version-print
# ---------------------------------------------------------------------------
RUN hostapd -v         2>&1 | head -n 3 && \
    wpa_supplicant -v  2>&1 | head -n 3 && \
    wlantest -h        2>&1 | head -n 3 || true

# ---------------------------------------------------------------------------
# 9. Entrypoint
# ---------------------------------------------------------------------------
COPY <<'EOF' /usr/local/bin/hostap-test-entrypoint
#!/bin/sh
# Dispatcher for the hostap test image.
set -e
cd /hostap

mode="${1:-shell}"
shift || true

case "$mode" in
    unit)
        echo "=== hostap unit tests ==="
        make -C tests -j"$(nproc)"
        cd tests
        fail=0
        for t in test-base64 test-md4 test-milenage test-rsa-sig-ver \
                 test-sha1 test-sha256 test-aes test-x509v3 test-list \
                 test-rc4 test-bss; do
            if [ -x "./$t" ]; then
                echo "--- $t ---"
                "./$t" || fail=1
            fi
        done
        exit $fail
        ;;

    hwsim)
        echo "=== hostap mac80211_hwsim integration tests ==="

        # Verify the driver is reachable.
        if ! modinfo mac80211_hwsim >/dev/null 2>&1; then
            cat >&2 <<'MSG'
ERROR: mac80211_hwsim module not visible inside the container.
       Start the container with:
         --privileged --cap-add=NET_ADMIN --cap-add=SYS_ADMIN \
         -v /lib/modules:/lib/modules:ro \
         -v /sys/kernel/debug:/sys/kernel/debug
       and make sure the host has linux-modules-extra installed for
       $(uname -r).
MSG
            exit 2
        fi

        # start.sh will modprobe hwsim and spin up the daemons.
        cd tests/hwsim
        ./start.sh
        trap './stop.sh || true' EXIT INT TERM

        if [ "$#" -eq 0 ]; then
            ./run-all.sh
        else
            sudo ./run-tests.py "$@"
        fi
        ;;

    shell|bash|sh)
        exec /bin/bash "$@"
        ;;

    *)
        # Anything else: run it verbatim.
        exec "$mode" "$@"
        ;;
esac
EOF

RUN chmod 0755 /usr/local/bin/hostap-test-entrypoint

ENTRYPOINT ["/usr/local/bin/hostap-test-entrypoint"]
CMD ["shell"]
