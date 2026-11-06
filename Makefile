# cliairplay - Unified AirPlay streaming binary
# Supports both RAOP (AirPlay 1) and AirPlay 2 protocols

ifeq ($(CC),cc)
CC=$(lastword $(subst /, ,$(shell readlink -f `which cc` 2>/dev/null || which cc)))
endif

ifeq ($(findstring gcc,$(CC)),gcc)
CFLAGS  += -Wno-stringop-truncation -Wno-stringop-overflow -Wno-format-truncation -Wno-multichar
LDFLAGS += -lstdc++ -latomic
# Sanitizer reports need the symbols, so only strip regular builds.
ifeq ($(SANITIZE),)
LDFLAGS += -s
endif
else
CFLAGS += -fno-temp-file
LDFLAGS += -lc++
endif

PLATFORM ?= $(firstword $(subst -, ,$(CC)))
HOST ?= $(word 2, $(subst -, ,$(CC)))

# Default host detection for native builds
ifeq ($(HOST),)
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_S),Darwin)
HOST = macos
ifeq ($(UNAME_M),arm64)
PLATFORM = arm64
else
PLATFORM = x86_64
endif
else
HOST = linux
PLATFORM = $(UNAME_M)
endif
endif

# Directories
SRC         = src
LIBRAOP     = libraop
BINDIR      = bin

# FULL_STATIC is deliberately a distinct Linux-only artifact: the ordinary
# STATIC=1 builds retain their dynamic libc ABI and artifact names.
BUILD_SUFFIX :=
ifneq ($(FULL_STATIC),)
ifeq ($(HOST),linux)
else
$(error FULL_STATIC=1 is supported only for Linux)
endif
ifeq ($(STATIC),)
$(error FULL_STATIC=1 requires STATIC=1)
endif
BUILD_SUFFIX := -static
LDFLAGS += -static -static-libgcc -static-libstdc++
endif
BUILDDIR    = build/$(HOST)/$(PLATFORM)$(BUILD_SUFFIX)

# Output binary
EXECUTABLE  = $(BINDIR)/cliairplay-$(HOST)-$(PLATFORM)$(BUILD_SUFFIX)
IO_TEST       = build/tests/test_ap2_io
TIMELINE_TEST = build/tests/test_ap2_timeline
EVENT_TEST    = build/tests/test_ap2_event
CLIENT_TEST   = build/tests/test_ap2_client
SESSION_TEST  = build/tests/test_ap2_session
PTP_TEST      = build/tests/test_ap2_ptp
PTP_POLICY_TEST = build/tests/test_ap2_ptp_policy
TEST_CFLAGS   = -Wall -Wextra -Werror -O2 $(CPPFLAGS) $(EXTRA_CFLAGS)

# Compiler flags
DEFINES  = -DNDEBUG -D_GNU_SOURCE -DOPENSSL_SUPPRESS_DEPRECATED
CFLAGS  += -Wall -fPIC -ggdb -O2 $(DEFINES) -fdata-sections -ffunction-sections
# The C++ sources (ours and libraop's) use C++11 features (lambdas, auto, range-for);
# pin the standard since some compilers still default to an older one. Use the GNU
# dialect (g++'s default) so GNU extensions in libraop's sources keep working.
CXXFLAGS += -std=gnu++17
LDFLAGS += -lpthread -ldl -lm -L.

# Version string reported by --check/--help (src/cliairplay.c). CI overrides this
# with the exact tag (e.g. VERSION=0.3.3) when building a tagged release; local/dev
# builds fall back to `git describe`. Strip a leading "v" either way since
# cliairplay.c already prints its own "v" prefix. If git or tags aren't available
# (shallow clone, no .git) this resolves to empty and the compiled-in literal in
# cliairplay.c is used instead.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null)
VERSION := $(patsubst v%,%,$(VERSION))
ifneq ($(VERSION),)
DEFINES += -DCLIAIRPLAY_VERSION='"$(VERSION)"'
endif

# POSIX shared memory (shm_open/shm_unlink) for the --ptp-daemon shared clock:
# glibc exposes these via librt; macOS has them in libSystem, so link -lrt on
# Linux only.
ifeq ($(HOST),linux)
LDFLAGS += -lrt
endif

# Extra flags for cross-compilation, e.g. building macOS x86_64 on an arm64 host:
#   make HOST=macos PLATFORM=x86_64 EXTRA_CFLAGS="-arch x86_64" EXTRA_LDFLAGS="-arch x86_64"
CFLAGS  += $(EXTRA_CFLAGS)
LDFLAGS += $(EXTRA_LDFLAGS)

# Sanitizer build for the tests (Linux only); run `make clean` first when
# switching from a regular build, e.g.:
#   make test STATIC=1 SANITIZE=address,undefined
ifneq ($(SANITIZE),)
SANITIZE_FLAGS = -fsanitize=$(SANITIZE) -fno-omit-frame-pointer -g
CFLAGS      += $(SANITIZE_FLAGS)
TEST_CFLAGS += $(SANITIZE_FLAGS)
LDFLAGS     += -fsanitize=$(SANITIZE)
endif

# Paths into libraop submodule
TOOLS       = $(LIBRAOP)/crosstools/src
DMAP_PARSER = $(LIBRAOP)/dmap-parser
MDNS        = $(LIBRAOP)/libmdns/targets
CODECS      = $(LIBRAOP)/libcodecs/targets
OPENSSL     = $(LIBRAOP)/libopenssl/targets/$(HOST)/$(PLATFORM)

vpath %.c $(TOOLS):$(LIBRAOP)/src:$(DMAP_PARSER):$(SRC)
vpath %.cpp $(TOOLS):$(LIBRAOP)/src:$(SRC)

INCLUDE = -Ibuild/patched/raop-media/src -I$(TOOLS) \
	-I$(DMAP_PARSER) \
	-I$(MDNS)/include/mdnssvc -I$(MDNS)/include/mdnssd \
	-I$(OPENSSL)/include \
	-I$(CODECS)/include/addons -I$(CODECS)/include/flac \
	-I$(CODECS)/include/shine -I$(CODECS)/include/faac \
	-I$(CODECS)/include/alac \
	-I$(LIBRAOP)/src -I$(LIBRAOP)/src/inc \
	-I$(LIBRAOP)/crosstools/src \
	-I$(SRC)

# libraop core sources (RAOP protocol)
RAOP_SOURCES = raop_client.c rtsp_client.c \
	aes.c aes_ctr.c \
	dmap_parser.c \
	alac.c

# AirPlay 2 sources (new)
AP2_SOURCES = ap2_client.c ap2_hap.c ap2_io.c ap2_ptp.c ap2_ptp_shm.c ap2_plist.c ap2_mrp.c ap2_session.c

# Common/CLI sources
CLI_SOURCES = cross_log.c cross_ssl.c cross_util.c cross_net.c platform.c host_clock.c \
	attestation.c media_receipt.c cliairplay.c net_address.c raop_response.c raop_session.c artwork.c announce.c pairing.cpp bplist.cpp ap2_bplist.cpp alac_ext.cpp

# Pre-built static libraries
# We use a patched copy of libcodecs.a with the buggy alac_create_encoder removed,
# replaced by our alac_ext.cpp which properly handles 24-bit audio.
# Keep the copy next to the original: on some platforms libcodecs.a is a "thin"
# archive that references its member libraries by path relative to its own
# directory, so copying it elsewhere would break those references at link time.
LIBCODECS_PATCHED = $(CODECS)/$(HOST)/$(PLATFORM)/libcodecs_patched.a
LIBRARY = $(LIBCODECS_PATCHED) $(MDNS)/$(HOST)/$(PLATFORM)/libmdns.a

ifeq ($(STATIC),)
LDFLAGS += -lcrypto
else
LIBRARY += $(OPENSSL)/libopenssl.a
DEFINES += -DSSL_STATIC_LIB
endif

# Object files
OBJECTS_RAOP = $(patsubst %.c,$(BUILDDIR)/%.o,$(RAOP_SOURCES))
OBJECTS_AP2  = $(patsubst %.c,$(BUILDDIR)/%.o,$(AP2_SOURCES))
OBJECTS_CLI  = $(patsubst %.c,$(BUILDDIR)/%.o,$(filter %.c,$(CLI_SOURCES)))
OBJECTS_CLI += $(patsubst %.cpp,$(BUILDDIR)/%.o,$(filter %.cpp,$(CLI_SOURCES)))

OBJECTS_ALL = $(OBJECTS_RAOP) $(OBJECTS_AP2) $(OBJECTS_CLI)
CLIENT_TEST_OBJECTS = $(filter-out $(BUILDDIR)/ap2_client.o \
	$(BUILDDIR)/cliairplay.o $(BUILDDIR)/cross_ssl.o,$(OBJECTS_ALL))

TEST_EXECUTABLE = $(BUILDDIR)/test-mrp-artwork
TEST_OBJECTS = $(BUILDDIR)/test_mrp_artwork.o \
	$(BUILDDIR)/ap2_mrp.o $(BUILDDIR)/ap2_io.o $(BUILDDIR)/ap2_plist.o \
	$(BUILDDIR)/ap2_bplist.o $(BUILDDIR)/bplist.o \
	$(BUILDDIR)/artwork.o $(BUILDDIR)/cross_log.o
RAOP_LIFECYCLE_TEST_EXECUTABLE = $(BUILDDIR)/test-ap2-raop-lifecycle
RAOP_LIFECYCLE_TEST_OBJECTS = $(BUILDDIR)/test_ap2_raop_lifecycle.o \
	$(BUILDDIR)/ap2_client_raop_lifecycle_test.o \
	$(BUILDDIR)/raop_session_raop_lifecycle_test.o \
	build/tests/cross_ssl.o \
	$(filter-out $(BUILDDIR)/ap2_client.o $(BUILDDIR)/cliairplay.o \
		$(BUILDDIR)/raop_session.o $(BUILDDIR)/cross_ssl.o,$(OBJECTS_ALL))
RAOP_LIFECYCLE_TEST_DEFINES = \
	-Draopcl_create=ap2_test_raopcl_create \
	-Draopcl_connect=ap2_test_raopcl_connect \
	-Draopcl_disconnect=ap2_test_raopcl_disconnect \
	-Draopcl_destroy=ap2_test_raopcl_destroy \
	-Draopcl_state=ap2_test_raopcl_state \
	-Draopcl_stop=ap2_test_raopcl_stop \
	-Draopcl_flush=ap2_test_raopcl_flush \
	-Draopcl_start_at=ap2_test_raopcl_start_at \
	-Draopcl_get_ntp=ap2_test_raopcl_get_ntp \
	-Draopcl_latency=ap2_test_raopcl_latency \
	-Draopcl_sample_rate=ap2_test_raopcl_sample_rate
RAOP_SESSION_TEST = build/tests/test_raop_session
ANNOUNCE_TEST = build/tests/test_announce
RAOP_EARLY_FAILURE_TEST = build/tests/test_raop_early_failure
ATTESTATION_TEST = build/tests/test_attestation

# libraop 81c2182 joins RTP threads that were never created when raopcl_connect
# fails early (a zeroed pthread_t can crash Linux). The submodule stays pristine:
# the fix is a patch applied to a build-local copy of raop_client.c.
RAOP_CLIENT_PATCH = patches/libraop-raop-client-thread-join.patch
RAOP_CLIENT_PATCHED = build/patched/raop-media/src/raop_client.c
RAOP_MEDIA_PATCH = patches/libraop-media-write-callback.patch
RAOP_RACES_PATCH = patches/libraop-raop-client-thread-races.patch
RAOP_MEDIA_STAMP = build/patched/raop-media/.stamp
RTSP_CLIENT_PATCH = patches/libraop-rtsp-setup-cleanup.patch
RTSP_CLIENT_PATCHED = build/patched/rtsp_client.c
CROSS_NET_PATCH = patches/libraop-http-read-poll.patch
CROSS_NET_PATCHED = build/patched/cross_net.c
CROSS_LOG_PATCH = patches/libraop-logtime-bounds.patch
CROSS_LOG_PATCHED = build/patched/cross_log.c

all: directory $(EXECUTABLE)

# The waiver in .gitattributes covers only unified-diff context encoding; an
# ADDED source line with trailing whitespace is still a real defect.
check-patch-whitespace:
	@if grep -nE '^\+.*[[:space:]]+$$' patches/*.patch; then \
		echo "trailing whitespace on an added patch line"; exit 1; fi

test: check-patch-whitespace
.PHONY: check-patch-whitespace

# libraop's raopcl_get_ntp reads crosstools' gettime_us. Rename crosstools'
# definition so the one in host_clock.c serves libraop instead (crosstools'
# own gettime_ms keeps the renamed wall clock version).
$(BUILDDIR)/cross_util.o: CPPFLAGS += -Dgettime_us=crosstools_gettime_us

directory:
	@mkdir -p $(BUILDDIR)
	@mkdir -p $(BINDIR)

# Create patched libcodecs without the buggy alac_create_encoder
$(LIBCODECS_PATCHED): $(CODECS)/$(HOST)/$(PLATFORM)/libcodecs.a
	cp $< $@
	ar d $@ alac_wrapper.o 2>/dev/null || true

$(EXECUTABLE): $(OBJECTS_ALL) $(LIBCODECS_PATCHED)
	$(CXX) $(OBJECTS_ALL) $(LIBRARY) $(LDFLAGS) -o $@

$(TEST_EXECUTABLE): $(TEST_OBJECTS) $(OPENSSL)/libopenssl.a
	$(CXX) $(TEST_OBJECTS) $(OPENSSL)/libopenssl.a $(LDFLAGS) -o $@

$(RAOP_LIFECYCLE_TEST_EXECUTABLE): $(RAOP_LIFECYCLE_TEST_OBJECTS) $(LIBCODECS_PATCHED) $(OPENSSL)/libopenssl.a
	$(CXX) $(RAOP_LIFECYCLE_TEST_OBJECTS) \
		$(filter-out $(OPENSSL)/libopenssl.a,$(LIBRARY)) $(OPENSSL)/libopenssl.a \
		$(LDFLAGS) -o $@

$(BUILDDIR)/test_mrp_artwork.o: tests/test_mrp_artwork.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) $< -c -o $@

$(BUILDDIR)/test_ap2_raop_lifecycle.o: tests/test_ap2_raop_lifecycle.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) $< -c -o $@

$(BUILDDIR)/ap2_client_raop_lifecycle_test.o: $(SRC)/ap2_client.c Makefile
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) $(RAOP_LIFECYCLE_TEST_DEFINES) $< -c -o $@

$(BUILDDIR)/raop_session_raop_lifecycle_test.o: $(SRC)/raop_session.c Makefile
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) $(RAOP_LIFECYCLE_TEST_DEFINES) $< -c -o $@

# Apply the fifth local patch AFTER the existing thread-join fix, then the
# sixth (RTP thread data races) on top of both. Never modify submodule sources
# or its gitlink. Generate both public header copies together.
$(RAOP_MEDIA_STAMP): $(LIBRAOP)/src/raop_client.c $(RAOP_CLIENT_PATCH) \
		$(RAOP_MEDIA_PATCH) $(RAOP_RACES_PATCH) $(LIBRAOP)/src/raop_client.h \
		$(LIBRAOP)/targets/include/raop_client.h Makefile
	@mkdir -p build/patched/raop-media/src build/patched/raop-media/targets/include
	patch -s -o $(RAOP_CLIENT_PATCHED) $(LIBRAOP)/src/raop_client.c $(RAOP_CLIENT_PATCH)
	cp $(LIBRAOP)/src/raop_client.h build/patched/raop-media/src/
	cp $(LIBRAOP)/targets/include/raop_client.h build/patched/raop-media/targets/include/
	patch -s -d build/patched/raop-media -p1 < $(RAOP_MEDIA_PATCH)
	patch -s -d build/patched/raop-media -p1 < $(RAOP_RACES_PATCH)
	cmp build/patched/raop-media/src/raop_client.h build/patched/raop-media/targets/include/raop_client.h
	@touch $@

$(RAOP_CLIENT_PATCHED): $(RAOP_MEDIA_STAMP)
	@test -f $@

$(RTSP_CLIENT_PATCHED): $(LIBRAOP)/src/rtsp_client.c $(RTSP_CLIENT_PATCH)
	@mkdir -p $(dir $@)
	patch -s -o $@ $< $(RTSP_CLIENT_PATCH)

$(CROSS_NET_PATCHED): $(TOOLS)/cross_net.c $(CROSS_NET_PATCH)
	@mkdir -p $(dir $@)
	patch -s -o $@ $< $(CROSS_NET_PATCH)

$(BUILDDIR)/cross_net.o: $(CROSS_NET_PATCHED)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) $< -c -o $@

$(CROSS_LOG_PATCHED): $(TOOLS)/cross_log.c $(CROSS_LOG_PATCH)
	@mkdir -p $(dir $@)
	patch -s -o $@ $< $(CROSS_LOG_PATCH)

$(BUILDDIR)/cross_log.o: $(CROSS_LOG_PATCHED)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) $< -c -o $@

$(BUILDDIR)/rtsp_client.o: $(RTSP_CLIENT_PATCHED)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) $< -c -o $@

$(BUILDDIR)/raop_client.o: $(RAOP_CLIENT_PATCHED)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) $< -c -o $@

# All translation units see the same generated public API before compiling.
$(OBJECTS_ALL) build/tests/ap2_client.o build/tests/test_ap2_client_main.o \
		build/tests/cross_ssl.o: $(RAOP_MEDIA_STAMP)

# The generic rules above track no header dependencies. These are the headers
# of the media receipt API (media_receipt.h pulls in ap2_client.h; the applied
# callback lives in ap2_session.h): an edit must rebuild every consumer.
RECEIPT_HEADERS = src/media_receipt.h src/ap2_client.h src/ap2_session.h
$(BUILDDIR)/cliairplay.o $(BUILDDIR)/media_receipt.o $(BUILDDIR)/ap2_client.o \
		$(BUILDDIR)/ap2_session.o build/tests/ap2_client.o: $(RECEIPT_HEADERS)

$(BUILDDIR)/%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) $< -c -o $@

$(BUILDDIR)/%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) $< -c -o $@

clean:
	rm -rf $(BUILDDIR) $(EXECUTABLE) $(LIBCODECS_PATCHED) build/tests build/patched

# The CLI checks in `test` expect the binary to fail and swallow its exit
# status, so they rely on this to fail on a sanitizer report (and show it).
no_sanitizer_report = case "$(1)" in *Sanitizer*|*"runtime error:"*) \
	printf '%s\n' "$(1)" >&2; false;; esac

test: directory $(EXECUTABLE) $(TIMELINE_TEST) $(EVENT_TEST) $(IO_TEST) $(CLIENT_TEST) \
		$(SESSION_TEST) $(PTP_TEST) $(PTP_POLICY_TEST) $(TEST_EXECUTABLE) $(RAOP_LIFECYCLE_TEST_EXECUTABLE) \
		$(RAOP_SESSION_TEST) $(ANNOUNCE_TEST) $(RAOP_EARLY_FAILURE_TEST) $(ATTESTATION_TEST)
	$(TIMELINE_TEST)
	$(EVENT_TEST)
	$(IO_TEST)
	$(CLIENT_TEST)
	$(SESSION_TEST)
	$(PTP_TEST)
	$(PTP_POLICY_TEST)
	$(TEST_EXECUTABLE)
	$(RAOP_LIFECYCLE_TEST_EXECUTABLE)
	$(RAOP_SESSION_TEST)
	$(ANNOUNCE_TEST)
	$(RAOP_EARLY_FAILURE_TEST) $(EXECUTABLE)
	$(ATTESTATION_TEST)
	python3 tests/attestation_cli.py $(EXECUTABLE)
	python3 tests/mrp_artwork_matrix.py --help >/dev/null
	@missing_pipe="$$($(EXECUTABLE) --protocol raop \
		127.0.0.1 2>&1 || true)"; \
		$(call no_sanitizer_report,$$missing_pipe) && \
		printf '%s\n' "$$missing_pipe" | grep -q "Streaming requires --cmdpipe"
	@argv_audio="$$($(EXECUTABLE) --protocol raop --cmdpipe \
		/tmp/cliairplay-test-unused 127.0.0.1 - 2>&1 || true)"; \
		$(call no_sanitizer_report,$$argv_audio) && \
		printf '%s\n' "$$argv_audio" | \
		grep -q "Streaming audio must be provided on stdin, not argv"
# Both greps are chained with && on purpose: a recipe line reports only its
# last command's status, so separating them with ; would leave the coded-line
# assertion unenforced.
	@auth_required="$$($(EXECUTABLE) --protocol raop --pw true \
		127.0.0.1 2>&1 || true)"; \
		$(call no_sanitizer_report,$$auth_required) && \
		printf '%s\n' "$$auth_required" | \
		grep -q '^\[STATUS\] error code=auth_required http=0 detail="[^"]*"$$' && \
		printf '%s\n' "$$auth_required" | \
		grep -q "Password required but not supplied"
# A connect-path setup failure must carry its code too: without one the caller
# has nothing to fail fast on and waits out its connect timeout instead.
	@setup_failed="$$($(EXECUTABLE) --protocol raop --cmdpipe \
		/nonexistent-cliairplay-test-dir/pipe 127.0.0.1 2>&1 || true)"; \
		$(call no_sanitizer_report,$$setup_failed) && \
		printf '%s\n' "$$setup_failed" | \
		grep -q '^\[STATUS\] error code=connect_failed http=0 detail="[^"]*"$$' && \
		printf '%s\n' "$$setup_failed" | \
		grep -q "Failed to create command pipe"
# An Apple TV advertising a public key may still accept unpaired RAOP, so no
# secret is demanded up front: the connect attempt (to a closed port) must run.
# The failed connect must also exit normally: libraop used to join RTP threads
# it never started there, which killed the process with SIGSEGV on Linux.
	@pipe_dir="$$(mktemp -d)"; \
		appletv_pk="$$($(EXECUTABLE) --protocol raop --port 1 --cmdpipe \
		"$$pipe_dir/pipe" --am AppleTV2,1 \
		--pk 0000000000000000000000000000000000000000000000000000000000000000 \
		127.0.0.1 < /dev/null 2>&1; echo "exit=$$?")"; \
		rm -rf "$$pipe_dir"; \
		$(call no_sanitizer_report,$$appletv_pk) && \
		printf '%s\n' "$$appletv_pk" | grep -q 'detail="RAOP connect failed"' && \
		printf '%s\n' "$$appletv_pk" | grep -q '^exit=1$$'

$(ATTESTATION_TEST): tests/test_attestation.c src/attestation.c src/attestation.h Makefile
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(INCLUDE) tests/test_attestation.c \
		$(OPENSSL)/libopenssl.a $(EXTRA_LDFLAGS) -o $@

$(RAOP_SESSION_TEST): tests/test_raop_session.c src/raop_session.c \
		src/raop_session.h Makefile
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(INCLUDE) tests/test_raop_session.c \
		src/raop_session.c $(EXTRA_LDFLAGS) -o $@

$(ANNOUNCE_TEST): tests/test_announce.c src/announce.c src/announce.h Makefile
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -Isrc tests/test_announce.c src/announce.c \
		$(EXTRA_LDFLAGS) -lm -o $@

$(SESSION_TEST): tests/test_ap2_session.c src/ap2_session.c src/ap2_session.h \
		src/ap2_io.c src/ap2_io.h $(CROSS_LOG_PATCHED) Makefile
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(INCLUDE) -Dpoll=ap2_session_test_poll \
		-c src/ap2_session.c -o build/tests/ap2_session_fifo_test.o
	$(CC) $(TEST_CFLAGS) $(INCLUDE) tests/test_ap2_session.c \
		build/tests/ap2_session_fifo_test.o src/ap2_io.c $(CROSS_LOG_PATCHED) \
		$(EXTRA_LDFLAGS) -lpthread -o $@

# ap2_ptp.c binds ephemeral ports and records datagrams instead of sending them.
$(PTP_TEST): tests/test_ap2_ptp.c src/ap2_ptp.c src/ap2_ptp.h src/ap2_ptp_shm.c \
		src/ap2_ptp_shm.h src/host_clock.c src/host_clock.h $(CROSS_LOG_PATCHED) Makefile
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) -Dbind=ap2_ptp_test_bind \
		-Dsendto=ap2_ptp_test_sendto -c src/ap2_ptp.c -o build/tests/ap2_ptp_test.o
	$(CC) $(TEST_CFLAGS) $(INCLUDE) tests/test_ap2_ptp.c \
		build/tests/ap2_ptp_test.o src/ap2_ptp_shm.c src/host_clock.c $(CROSS_LOG_PATCHED) \
		$(LDFLAGS) -o $@

# Include the real receive/daemon implementation behind inert I/O boundaries.
# Use the same patched production logger as the binary and other PTP tests.
$(PTP_POLICY_TEST): tests/test_ap2_ptp_policy.c src/ap2_ptp.c src/ap2_ptp.h \
		src/ap2_ptp_shm.c src/ap2_ptp_shm.h src/host_clock.c src/host_clock.h \
		$(CROSS_LOG_PATCHED) Makefile
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(INCLUDE) tests/test_ap2_ptp_policy.c \
		src/ap2_ptp_shm.c src/host_clock.c $(CROSS_LOG_PATCHED) $(LDFLAGS) -o $@

$(TIMELINE_TEST): tests/test_ap2_timeline.c src/ap2_timeline.h Makefile
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -Isrc $< $(EXTRA_LDFLAGS) -o $@

$(EVENT_TEST): tests/test_ap2_event.c tests/mrp_event_fixture.h $(BUILDDIR)/ap2_mrp.o \
		$(BUILDDIR)/ap2_io.o $(BUILDDIR)/ap2_plist.o \
		$(BUILDDIR)/ap2_bplist.o $(BUILDDIR)/bplist.o \
		$(BUILDDIR)/cross_log.o Makefile
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(INCLUDE) \
		$< $(BUILDDIR)/ap2_mrp.o $(BUILDDIR)/ap2_io.o \
		$(BUILDDIR)/ap2_plist.o $(BUILDDIR)/ap2_bplist.o \
		$(BUILDDIR)/bplist.o $(BUILDDIR)/cross_log.o \
		$(OPENSSL)/libopenssl.a $(LDFLAGS) -o $@

$(IO_TEST): tests/test_ap2_io.c src/ap2_io.c src/ap2_io.h Makefile
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -Isrc tests/test_ap2_io.c src/ap2_io.c \
		$(EXTRA_LDFLAGS) -lpthread -o $@

build/tests/ap2_client.o: src/ap2_client.c Makefile
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) -DAP2_TESTING $< -c -o $@

build/tests/cross_ssl.o: $(TOOLS)/cross_ssl.c Makefile
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) -DSSL_STATIC_LIB $< -c -o $@

build/tests/test_ap2_client_main.o: tests/test_ap2_client.c Makefile
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(INCLUDE) $< -c -o $@

$(CLIENT_TEST): build/tests/test_ap2_client_main.o build/tests/ap2_client.o \
		build/tests/cross_ssl.o \
		$(CLIENT_TEST_OBJECTS) $(LIBCODECS_PATCHED) Makefile
	@mkdir -p $(dir $@)
	$(CXX) build/tests/test_ap2_client_main.o build/tests/ap2_client.o \
		build/tests/cross_ssl.o \
		$(CLIENT_TEST_OBJECTS) $(LIBCODECS_PATCHED) \
		$(MDNS)/$(HOST)/$(PLATFORM)/libmdns.a \
		$(OPENSSL)/libopenssl.a $(LDFLAGS) -o $@

# Same raop_client.c as the binary, with its thread calls routed via the hooks.
build/tests/raop_client_early_failure.o: $(RAOP_CLIENT_PATCHED) \
		tests/raop_thread_hooks.h Makefile
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) -include tests/raop_thread_hooks.h \
		$< -c -o $@

$(RAOP_EARLY_FAILURE_TEST): tests/test_raop_early_failure.c \
		build/tests/raop_client_early_failure.o build/tests/cross_ssl.o \
		$(filter-out $(BUILDDIR)/raop_client.o,$(CLIENT_TEST_OBJECTS)) \
		$(LIBCODECS_PATCHED) Makefile
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(INCLUDE) tests/test_raop_early_failure.c -c \
		-o build/tests/test_raop_early_failure.o
	$(CXX) build/tests/test_raop_early_failure.o \
		build/tests/raop_client_early_failure.o build/tests/cross_ssl.o \
		$(filter-out $(BUILDDIR)/raop_client.o,$(CLIENT_TEST_OBJECTS)) \
		$(LIBCODECS_PATCHED) $(MDNS)/$(HOST)/$(PLATFORM)/libmdns.a \
		$(OPENSSL)/libopenssl.a $(LDFLAGS) -o $@

.PHONY: all directory clean test

CLI_STOP_HEALTH_TEST = build/tests/test_cli_stop_health
$(CLI_STOP_HEALTH_TEST): tests/test_cli_stop_health.c src/cliairplay.c \
		$(filter-out $(BUILDDIR)/cliairplay.o,$(OBJECTS_ALL)) $(LIBCODECS_PATCHED)
	@mkdir -p build/tests
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) $< -c -o build/tests/test_cli_stop_health.o
	$(CXX) build/tests/test_cli_stop_health.o \
		$(filter-out $(BUILDDIR)/cliairplay.o,$(OBJECTS_ALL)) $(LIBRARY) $(LDFLAGS) -o $@

test-stop-health: directory $(CLI_STOP_HEALTH_TEST)
	$(CLI_STOP_HEALTH_TEST)

test: test-stop-health
.PHONY: test-stop-health

NET_ADDRESS_TEST = build/tests/test_net_address
$(NET_ADDRESS_TEST): tests/test_net_address.c src/net_address.c src/net_address.h Makefile
	@mkdir -p build/tests
	$(CC) $(TEST_CFLAGS) -Isrc -Dgetaddrinfo=test_getaddrinfo \
		-Dfreeaddrinfo=test_freeaddrinfo -c src/net_address.c -o build/tests/net_address_test.o
	$(CC) $(TEST_CFLAGS) -Isrc tests/test_net_address.c build/tests/net_address_test.o \
		$(EXTRA_LDFLAGS) -o $@

test-net-address: $(NET_ADDRESS_TEST)
	$(NET_ADDRESS_TEST)

test: test-net-address
.PHONY: test-net-address

# Link the full production translation unit, not a copied read implementation.
# Dead stripping keeps unrelated network utilities out of this focused fixture.
ifeq ($(HOST),macos)
HTTP_TEST_GC = -Wl,-dead_strip
else
HTTP_TEST_GC = -Wl,--gc-sections
endif
HTTP_READ_SOURCE ?= $(CROSS_NET_PATCHED)
build/tests/cross_net_read_test.o: $(HTTP_READ_SOURCE) tests/http_read_hooks.h Makefile
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) -include tests/http_read_hooks.h $< -c -o $@

build/tests/test_http_read_line: tests/test_http_read_line.c build/tests/cross_net_read_test.o $(BUILDDIR)/cross_log.o Makefile
	$(CC) $(TEST_CFLAGS) $(INCLUDE) tests/test_http_read_line.c build/tests/cross_net_read_test.o $(BUILDDIR)/cross_log.o $(HTTP_TEST_GC) $(LDFLAGS) -o $@

test-http-read: directory build/tests/test_http_read_line
	build/tests/test_http_read_line

.PHONY: test-http-read
test: test-http-read

build/tests/rtsp_response_fixture.o: tests/rtsp_response_fixture.c tests/rtsp_response_fixture.h src/raop_response.c src/raop_response.h $(RTSP_CLIENT_PATCHED) Makefile
	@mkdir -p build/tests
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) -c $< -o $@

build/tests/test_rtsp_response_failure: tests/test_rtsp_response_failure.c $(RTSP_CLIENT_PATCHED) build/tests/rtsp_response_fixture.o $(BUILDDIR)/cross_net.o $(BUILDDIR)/cross_util.o $(BUILDDIR)/cross_log.o Makefile
	$(CC) $(TEST_CFLAGS) -DOPENSSL_SUPPRESS_DEPRECATED $(INCLUDE) -ffunction-sections -fdata-sections tests/test_rtsp_response_failure.c build/tests/rtsp_response_fixture.o $(BUILDDIR)/cross_net.o $(BUILDDIR)/cross_util.o $(BUILDDIR)/cross_log.o $(OPENSSL)/libopenssl.a $(HTTP_TEST_GC) $(LDFLAGS) -o $@

test-rtsp-response: directory build/tests/test_rtsp_response_failure
	build/tests/test_rtsp_response_failure

.PHONY: test-rtsp-response
test: test-rtsp-response

RAOP_MEDIA_TEST = build/tests/test_raop_media_write
RAOP_MEDIA_TEST_OBJECTS = $(filter-out $(BUILDDIR)/raop_client.o,$(CLIENT_TEST_OBJECTS))

build/tests/test_raop_media_write.o: tests/test_raop_media_write.c $(RAOP_CLIENT_PATCHED) Makefile
	@mkdir -p build/tests
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) -std=gnu11 $< -c -o $@

$(RAOP_MEDIA_TEST): build/tests/test_raop_media_write.o build/tests/cross_ssl.o \
		$(RAOP_MEDIA_TEST_OBJECTS) $(LIBCODECS_PATCHED) Makefile
	$(CXX) build/tests/test_raop_media_write.o build/tests/cross_ssl.o \
		$(RAOP_MEDIA_TEST_OBJECTS) $(filter-out $(OPENSSL)/libopenssl.a,$(LIBRARY)) \
		$(OPENSSL)/libopenssl.a $(LDFLAGS) -o $@

test-raop-media: directory $(RAOP_MEDIA_TEST)
	$(RAOP_MEDIA_TEST)

# This matched behavioral control retains the new API so the old behavior
# fails at the successful-callback assertion, NOT at compilation/link/import.
build/tests/raop_media_no_notification.c: $(RAOP_CLIENT_PATCHED) tests/raop_media_no_notification.patch
	@mkdir -p build/tests
	patch -s -o $@ $(RAOP_CLIENT_PATCHED) tests/raop_media_no_notification.patch

build/tests/raop_media_no_notification.o: tests/test_raop_media_write.c build/tests/raop_media_no_notification.c Makefile
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) -std=gnu11 \
		-DRAOP_MEDIA_SOURCE='"../build/tests/raop_media_no_notification.c"' $< -c -o $@

build/tests/test_raop_media_no_notification: build/tests/raop_media_no_notification.o \
		build/tests/cross_ssl.o $(RAOP_MEDIA_TEST_OBJECTS) $(LIBCODECS_PATCHED) Makefile
	$(CXX) build/tests/raop_media_no_notification.o build/tests/cross_ssl.o \
		$(RAOP_MEDIA_TEST_OBJECTS) $(filter-out $(OPENSSL)/libopenssl.a,$(LIBRARY)) \
		$(OPENSSL)/libopenssl.a $(LDFLAGS) -o $@

test-raop-media-red: directory build/tests/test_raop_media_no_notification
	@set +e; build/tests/test_raop_media_no_notification > build/tests/raop-media-red.log 2>&1; \
		rc=$$?; set -e; test $$rc -eq 1; \
		if grep -Eq 'Sanitizer|runtime error:' build/tests/raop-media-red.log; then exit 1; fi; \
		grep -Eq '^FAIL line [0-9]+: atomic_load\(&capture.calls\) == 1$$' build/tests/raop-media-red.log; \
		printf 'Matched baseline behavior: intended successful-callback assertion failed (exit 1)\n'

test: test-raop-media test-raop-media-red
.PHONY: test-raop-media test-raop-media-red

AP2_MEDIA_TEST = build/tests/test_ap2_media_write
AP2_MEDIA_OBJECTS = $(filter-out $(BUILDDIR)/ap2_io.o,$(CLIENT_TEST_OBJECTS))

# Include the production client unit to exercise its private pending/quiesce
# paths; compile the real IO unit with only syscall boundaries interposed.
build/tests/test_ap2_media_write.o: tests/test_ap2_media_write.c src/ap2_client.c $(RECEIPT_HEADERS) $(RAOP_MEDIA_STAMP) Makefile
	@mkdir -p build/tests
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) -std=gnu11 $< -c -o $@

build/tests/ap2_media_io.o: src/ap2_io.c src/ap2_io.h Makefile
	@mkdir -p build/tests
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) -Dsend=media_test_send \
		-Dsendto=media_test_sendto -Dpoll=media_test_poll $< -c -o $@

$(AP2_MEDIA_TEST): build/tests/test_ap2_media_write.o build/tests/ap2_media_io.o \
		build/tests/cross_ssl.o $(AP2_MEDIA_OBJECTS) $(LIBCODECS_PATCHED) Makefile
	$(CXX) build/tests/test_ap2_media_write.o build/tests/ap2_media_io.o \
		build/tests/cross_ssl.o $(AP2_MEDIA_OBJECTS) \
		$(filter-out $(OPENSSL)/libopenssl.a,$(LIBRARY)) \
		$(OPENSSL)/libopenssl.a $(LDFLAGS) -o $@

test-ap2-media: directory $(AP2_MEDIA_TEST)
	$(AP2_MEDIA_TEST)

# Same compiled production path: demonstrate the queued counter cannot stand
# in for completion. Require the specific assertion, never a build failure.
test-ap2-media-red: directory $(AP2_MEDIA_TEST)
	@set +e; $(AP2_MEDIA_TEST) --counter-is-completion > build/tests/ap2-media-red.log 2>&1; \
		rc=$$?; set -e; \
		if test $$rc -ne 1 || \
			grep -Eq 'Sanitizer|runtime error:' build/tests/ap2-media-red.log || \
			! grep -Eq '^FAIL line [0-9]+: c.count == 1$$' build/tests/ap2-media-red.log; then \
			printf 'Native AP2 negative control rejected: exit=%s\n' "$$rc" >&2; \
			LC_ALL=C awk 'NR <= 20 { gsub(/\/[^[:space:]]+/, "<path>"); print substr($$0, 1, 240) } NR == 21 { print "[negative log truncated]"; exit }' build/tests/ap2-media-red.log >&2; \
			exit 1; \
		fi; \
		printf 'Queued counter advanced with unwritten tail: intended completion assertion failed (exit 1)\n'

test: test-ap2-media test-ap2-media-red
.PHONY: test-ap2-media test-ap2-media-red

# The terminal emitter and collector with its fcntl/fflush/write seams routed
# through test hooks; the real syscalls still back every positive case.
MEDIA_RECEIPT_TEST = build/tests/test_media_receipt
MR_SEAM_DEFS = -Dfcntl=mr_test_fcntl -Dfflush=mr_test_fflush -Dwrite=mr_test_write
build/tests/media_receipt_seams.o: src/media_receipt.c $(RECEIPT_HEADERS) \
		$(RAOP_MEDIA_STAMP) Makefile
	@mkdir -p build/tests
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) $(MR_SEAM_DEFS) $< -c -o $@

$(MEDIA_RECEIPT_TEST): tests/test_media_receipt.c $(RECEIPT_HEADERS) \
		build/tests/media_receipt_seams.o Makefile
	$(CC) $(TEST_CFLAGS) $(INCLUDE) tests/test_media_receipt.c \
		build/tests/media_receipt_seams.o $(EXTRA_LDFLAGS) -o $@

test-media-receipt: directory $(MEDIA_RECEIPT_TEST)
	$(MEDIA_RECEIPT_TEST)

# Matched baseline: a success-only observer (no outcome accounting) must fail
# the failure-fault assertion, NOT compilation or a sanitizer report.
build/tests/media_receipt_success_only.c: src/media_receipt.c tests/media_receipt_success_only.patch
	@mkdir -p build/tests
	patch -s -o $@ src/media_receipt.c tests/media_receipt_success_only.patch

build/tests/media_receipt_success_only.o: build/tests/media_receipt_success_only.c \
		src/media_receipt.h $(RAOP_MEDIA_STAMP) Makefile
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) -Isrc $(MR_SEAM_DEFS) $< -c -o $@

build/tests/test_media_receipt_success_only: tests/test_media_receipt.c \
		build/tests/media_receipt_success_only.o Makefile
	$(CC) $(TEST_CFLAGS) $(INCLUDE) tests/test_media_receipt.c \
		build/tests/media_receipt_success_only.o $(EXTRA_LDFLAGS) -o $@

test-media-receipt-red: directory build/tests/test_media_receipt_success_only
	@set +e; build/tests/test_media_receipt_success_only > build/tests/media-receipt-red.log 2>&1; \
		rc=$$?; set -e; \
		if test $$rc -ne 1 || \
			grep -Eq 'Sanitizer|runtime error:' build/tests/media-receipt-red.log || \
			! grep -Eq '^FAIL line [0-9]+: mr.fault && mr.fresh_units == 1$$' build/tests/media-receipt-red.log; then \
			printf 'Media receipt negative control rejected: exit=%s\n' "$$rc" >&2; \
			LC_ALL=C awk 'NR <= 20 { gsub(/\/[^[:space:]]+/, "<path>"); print substr($$0, 1, 240) } NR == 21 { exit }' build/tests/media-receipt-red.log >&2; \
			exit 1; \
		fi; \
		printf 'Success-only baseline: select-error fault assertion failed (exit 1)\n'

test: test-media-receipt test-media-receipt-red
.PHONY: test-media-receipt test-media-receipt-red

CLI_MEDIA_RECEIPT_TEST = build/tests/test_cli_media_receipt
# The AP2_TESTING ap2_client.o carries the hook that starts the production
# feedback worker, which the real-worker teardown cases need.
$(CLI_MEDIA_RECEIPT_TEST): tests/test_cli_media_receipt.c src/cliairplay.c $(RECEIPT_HEADERS) \
		tests/mrp_event_fixture.h build/tests/ap2_client.o \
		$(filter-out $(BUILDDIR)/cliairplay.o $(BUILDDIR)/ap2_client.o,$(OBJECTS_ALL)) \
		$(LIBCODECS_PATCHED) Makefile
	@mkdir -p build/tests
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) $< -c -o build/tests/test_cli_media_receipt.o
	$(CXX) build/tests/test_cli_media_receipt.o build/tests/ap2_client.o \
		$(filter-out $(BUILDDIR)/cliairplay.o $(BUILDDIR)/ap2_client.o,$(OBJECTS_ALL)) \
		$(LIBRARY) $(LDFLAGS) -o $@

test-cli-media-receipt: directory $(CLI_MEDIA_RECEIPT_TEST)
	$(CLI_MEDIA_RECEIPT_TEST)

test: test-cli-media-receipt
.PHONY: test-cli-media-receipt

# Real patched libraop nested in the real ap2_client (AirPlay 2 RAOP-compatible
# flow); a single translation unit, with only select/sendto routed via seams.
COMPAT_MEDIA_TEST = build/tests/test_compat_media_receipt
build/tests/test_compat_media_receipt.o: tests/test_compat_media_receipt.c src/ap2_client.c \
		$(RECEIPT_HEADERS) $(RAOP_MEDIA_STAMP) Makefile
	@mkdir -p build/tests
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDE) -std=gnu11 $< -c -o $@

$(COMPAT_MEDIA_TEST): build/tests/test_compat_media_receipt.o build/tests/cross_ssl.o \
		$(RAOP_MEDIA_TEST_OBJECTS) $(LIBCODECS_PATCHED) Makefile
	$(CXX) build/tests/test_compat_media_receipt.o build/tests/cross_ssl.o \
		$(RAOP_MEDIA_TEST_OBJECTS) $(filter-out $(OPENSSL)/libopenssl.a,$(LIBRARY)) \
		$(OPENSSL)/libopenssl.a $(LDFLAGS) -o $@

test-compat-media: directory $(COMPAT_MEDIA_TEST)
	$(COMPAT_MEDIA_TEST)

test: test-compat-media
.PHONY: test-compat-media

# The real executable, driven through a real command FIFO, PCM pipe and stdout
# pipe against owned loopback receivers on the legacy RAOP, AirPlay 2 compat
# and native AirPlay 2 routes (tests/native_ap2_peer.c is the native one).
CLI_REAL_RECEIPT_TEST = build/tests/test_cli_real_receipt
$(CLI_REAL_RECEIPT_TEST): tests/test_cli_real_receipt.c tests/native_ap2_peer.c \
		tests/native_ap2_peer.h $(BUILDDIR)/ap2_plist.o $(OPENSSL)/libopenssl.a Makefile
	@mkdir -p build/tests
	$(CC) $(TEST_CFLAGS) $(INCLUDE) tests/test_cli_real_receipt.c tests/native_ap2_peer.c \
		$(BUILDDIR)/ap2_plist.o $(OPENSSL)/libopenssl.a -lpthread -ldl -o $@

test-cli-real-receipt: directory $(EXECUTABLE) $(CLI_REAL_RECEIPT_TEST)
	$(CLI_REAL_RECEIPT_TEST) $(EXECUTABLE)

test: test-cli-real-receipt
.PHONY: test-cli-real-receipt
