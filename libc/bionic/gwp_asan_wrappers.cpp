/*
 * Copyright (C) 2020 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

// GWP-ASan for the Android 10 libc, as backported in the factory PICO OS 5.13.7
// libc: the Android 11 dispatch wrappers and android_mallopt(M_INITIALIZE_GWP_ASAN)
// entry point, with options read from the environment and system properties
// (libc.debug.gwp_asan.{sample_rate,process_sampling,max_allocs}.<name> /
// .system_default, their persist. variants, GWP_ASAN_*), and GWP-ASan enabled
// only when one of those options is set.

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/system_properties.h>
#include <sys/types.h>

#include <private/android_unsafe_frame_pointer_chase.h>
#include <private/bionic_arc4random.h>
#include <private/bionic_globals.h>
#include <private/bionic_malloc_dispatch.h>

#include "gwp_asan/guarded_pool_allocator.h"
#include "gwp_asan/options.h"
#include "gwp_asan_wrappers.h"
#include "malloc_common.h"
#include "malloc_common_dynamic.h"

extern "C" const char* __gnu_basename(const char* path);

static gwp_asan::GuardedPoolAllocator GuardedAlloc;
static const MallocDispatch* prev_dispatch;

using Options = gwp_asan::options::Options;

// ============================================================================
// Implementation of GWP-ASan malloc wrappers.
// ============================================================================

void* gwp_asan_calloc(size_t n_elements, size_t elem_size) {
  if (__predict_false(GuardedAlloc.shouldSample())) {
    size_t bytes;
    if (!__builtin_mul_overflow(n_elements, elem_size, &bytes)) {
      if (void* result = GuardedAlloc.allocate(bytes)) {
        return result;
      }
    }
  }
  return prev_dispatch->calloc(n_elements, elem_size);
}

void gwp_asan_free(void* mem) {
  if (__predict_false(GuardedAlloc.pointerIsMine(mem))) {
    GuardedAlloc.deallocate(mem);
    return;
  }
  prev_dispatch->free(mem);
}

void* gwp_asan_malloc(size_t bytes) {
  if (__predict_false(GuardedAlloc.shouldSample())) {
    if (void* result = GuardedAlloc.allocate(bytes)) {
      return result;
    }
  }
  return prev_dispatch->malloc(bytes);
}

size_t gwp_asan_malloc_usable_size(const void* mem) {
  if (__predict_false(GuardedAlloc.pointerIsMine(mem))) {
    return GuardedAlloc.getSize(mem);
  }
  return prev_dispatch->malloc_usable_size(mem);
}

void* gwp_asan_realloc(void* old_mem, size_t bytes) {
  if (__predict_false(GuardedAlloc.pointerIsMine(old_mem))) {
    size_t old_size = GuardedAlloc.getSize(old_mem);
    void* new_ptr = gwp_asan_malloc(bytes);
    if (new_ptr) memcpy(new_ptr, old_mem, (bytes < old_size) ? bytes : old_size);
    GuardedAlloc.deallocate(old_mem);
    return new_ptr;
  }
  return prev_dispatch->realloc(old_mem, bytes);
}

int gwp_asan_malloc_iterate(uintptr_t base, size_t size,
                            void (*callback)(uintptr_t base, size_t size, void* arg), void* arg) {
  if (__predict_false(GuardedAlloc.pointerIsMine(reinterpret_cast<void*>(base)))) {
    // TODO(mitchp): GPA::iterate() returns void, but should return int.
    // TODO(mitchp): GPA::iterate() should take uintptr_t, not void*.
    GuardedAlloc.iterate(reinterpret_cast<void*>(base), size, callback, arg);
    return 0;
  }
  return prev_dispatch->iterate(base, size, callback, arg);
}

void gwp_asan_malloc_disable() {
  GuardedAlloc.disable();
  prev_dispatch->malloc_disable();
}

void gwp_asan_malloc_enable() {
  GuardedAlloc.enable();
  prev_dispatch->malloc_enable();
}

static const MallocDispatch gwp_asan_dispatch __attribute__((unused)) = {
  gwp_asan_calloc,
  gwp_asan_free,
  Malloc(mallinfo),
  gwp_asan_malloc,
  gwp_asan_malloc_usable_size,
  Malloc(memalign),
  Malloc(posix_memalign),
#if defined(HAVE_DEPRECATED_MALLOC_FUNCS)
  Malloc(pvalloc),
#endif
  gwp_asan_realloc,
#if defined(HAVE_DEPRECATED_MALLOC_FUNCS)
  Malloc(valloc),
#endif
  gwp_asan_malloc_iterate,
  gwp_asan_malloc_disable,
  gwp_asan_malloc_enable,
  Malloc(mallopt),
  Malloc(aligned_alloc),
  Malloc(malloc_info),
};

// ============================================================================
// GWP-ASan "shared library" entry points, installed in gFunctions so that the
// malloc debug style android_mallopt() queries see GWP-ASan.
// ============================================================================

// The factory version takes the GWP-ASan options by value and only falls back
// to the defaults below when they carry no sample rate.
bool gwp_asan_initialize(const MallocDispatch* dispatch, bool*, const char*, Options opts) {
  prev_dispatch = dispatch;

  Options Opts;
  Opts.Enabled = true;
  Opts.MaxSimultaneousAllocations = 32;
  Opts.SampleRate = 1;
  Opts.InstallSignalHandlers = false;
  Opts.InstallForkHandlers = true;
  Opts.Backtrace = android_unsafe_frame_pointer_chase;
  if (opts.SampleRate != 0) {
    Opts = opts;
  }

  GuardedAlloc.init(Opts);
  // TODO(b/149790891): The log line below causes ART tests to fail as they're
  // not expecting any output. Disable the output for now.
  // info_log("GWP-ASan has been enabled.");

  __libc_shared_globals()->gwp_asan_state = GuardedAlloc.getAllocatorState();
  __libc_shared_globals()->gwp_asan_metadata = GuardedAlloc.getMetadataRegion();
  return true;
}

void gwp_asan_finalize() {
}

void gwp_asan_get_malloc_leak_info(uint8_t**, size_t*, size_t*, size_t*, size_t*) {
}

void gwp_asan_free_malloc_leak_info(uint8_t*) {
}

ssize_t gwp_asan_malloc_backtrace(void*, uintptr_t*, size_t) {
  // TODO(mitchp): GWP-ASan might be able to return the backtrace for the
  // provided address.
  return -1;
}

bool gwp_asan_write_malloc_leak_info(FILE*) {
  return false;
}

void* gwp_asan_gfunctions[] = {
  (void*) gwp_asan_initialize,           (void*) gwp_asan_finalize,
  (void*) gwp_asan_get_malloc_leak_info, (void*) gwp_asan_free_malloc_leak_info,
  (void*) gwp_asan_malloc_backtrace,     (void*) gwp_asan_write_malloc_leak_info,
};

// ============================================================================
// Options.
// ============================================================================

static constexpr unsigned kDefaultSampleRate = 2500;
static constexpr unsigned kDefaultMaxAllocs = 32;

static const char* kSampleRateSystemSysprop = "libc.debug.gwp_asan.sample_rate.system_default";
static const char* kSampleRateTargetedSyspropPrefix = "libc.debug.gwp_asan.sample_rate.";
static const char* kSampleRateEnvVar = "GWP_ASAN_SAMPLE_RATE";

static const char* kProcessSamplingSystemSysprop =
    "libc.debug.gwp_asan.process_sampling.system_default";
static const char* kProcessSamplingTargetedSyspropPrefix = "libc.debug.gwp_asan.process_sampling.";
static const char* kProcessSamplingEnvVar = "GWP_ASAN_PROCESS_SAMPLING";

static const char* kMaxAllocsSystemSysprop = "libc.debug.gwp_asan.max_allocs.system_default";
static const char* kMaxAllocsTargetedSyspropPrefix = "libc.debug.gwp_asan.max_allocs.";
static const char* kMaxAllocsEnvVar = "GWP_ASAN_MAX_ALLOCS";

static const char kPersistPrefix[] = "persist.";

// The environment variable wins over the system properties, which are tried in
// the given order; null names are skipped.
static bool get_config_from_env_or_sysprops(const char* env_var_name,
                                            const char* const* sys_prop_names,
                                            size_t sys_prop_names_size, char* options,
                                            size_t options_size) {
  const char* env = getenv(env_var_name);
  if (env && *env != '\0') {
    strncpy(options, env, options_size);
    options[options_size - 1] = '\0';  // Ensure null-termination.
    return true;
  }

  for (size_t i = 0; i < sys_prop_names_size; ++i) {
    if (sys_prop_names[i] == nullptr) continue;
    if (__system_property_get(sys_prop_names[i], options) != 0) return true;
  }
  return false;
}

// Reads one GWP-ASan option for this program (basename of getprogname()), in
// order of precedence: the environment variable, then
// '<targeted_sysprop_prefix><program>', 'persist.<targeted_sysprop_prefix><program>',
// '<system_sysprop>' and 'persist.<system_sysprop>'.
bool GetGwpAsanOption(unsigned long long* result, const char* system_sysprop,
                      const char* targeted_sysprop_prefix, const char* env_var,
                      const char* descriptive_name) {
  const char* basename = __gnu_basename(getprogname());

  constexpr size_t kSyspropMaxLen = 512;
  char program_specific_sysprop[kSyspropMaxLen] = {};
  char persist_program_specific_sysprop[kSyspropMaxLen] = {};
  char persist_default_sysprop[kSyspropMaxLen] = {};
  const char* sysprop_names[4] = {};
  // Tests use a blank program name to specify that system properties should not
  // be used. Tests still continue to use the environment variable though.
  if (*basename != '\0') {
    async_safe_format_buffer(&program_specific_sysprop[0], kSyspropMaxLen, "%s%s",
                             targeted_sysprop_prefix, basename);
    async_safe_format_buffer(&persist_program_specific_sysprop[0], kSyspropMaxLen, "%s%s",
                             kPersistPrefix, program_specific_sysprop);
    async_safe_format_buffer(&persist_default_sysprop[0], kSyspropMaxLen, "%s%s",
                             kPersistPrefix, system_sysprop);

    // In order of precedence, always take the program-specific sysprop (e.g.
    // '[persist.]libc.debug.gwp_asan.sample_rate.cameraserver') over the
    // generic sysprop (e.g. '[persist.]libc.debug.gwp_asan.sample_rate.system_default').
    // In addition, always take the non-persistent option over the persistent option.
    sysprop_names[0] = program_specific_sysprop;
    sysprop_names[1] = persist_program_specific_sysprop;
    sysprop_names[2] = system_sysprop;
    sysprop_names[3] = persist_default_sysprop;
  }

  char settings_buf[PROP_VALUE_MAX];
  if (!get_config_from_env_or_sysprops(env_var, sysprop_names,
                                       sizeof(sysprop_names) / sizeof(sysprop_names[0]),
                                       settings_buf, PROP_VALUE_MAX)) {
    return false;
  }

  char* end;
  unsigned long long value = strtoull(settings_buf, &end, 10);
  if (value == ULLONG_MAX || *end != '\0') {
    warning_log("Invalid GWP-ASan %s: \"%s\". Using default value instead.", descriptive_name,
                settings_buf);
    return false;
  }

  *result = value;
  return true;
}

// Selects this process for sampling with a probability of 1 / sample_rate.
static bool ShouldGwpAsanSampleProcess(unsigned sample_rate) {
  uint8_t random_number;
  __libc_safe_arc4random_buf(&random_number, sizeof(random_number));
  return random_number % sample_rate == 0;
}

bool MaybeInitGwpAsanFromLibc(libc_globals* globals) {
  // Never initialize the Zygote here. A Zygote chosen for sampling would also
  // have all of its children sampled. Instead, the Zygote child will choose
  // whether it samples or not just after the Zygote forks. For
  // libc_scudo-preloaded executables (like mediaswcodec), the program name
  // might not be available yet.
  const char* progname = getprogname();
  if (progname && strncmp(progname, "app_process", 11) == 0) {
    return false;
  }
  return MaybeInitGwpAsan(globals);
}

static bool GwpAsanInitialized = false;

// The probability (1 / SampleRate) that an allocation gets chosen to be put
// into the special GWP-ASan pool, the number of slots of that pool and the
// probability (1 / process_sample_rate) that a process gets GWP-ASan come from
// the options above. Without any of them GWP-ASan stays off; without a process
// sampling rate (or with a zero option) it stays off as well.
bool MaybeInitGwpAsan(libc_globals* globals, bool force_init) {
  if (GwpAsanInitialized) {
    error_log("GWP-ASan was already initialized for this process.");
    return false;
  }

  Options options;
  options.Enabled = true;
  options.MaxSimultaneousAllocations = kDefaultMaxAllocs;
  options.SampleRate = kDefaultSampleRate;
  options.Backtrace = android_unsafe_frame_pointer_chase;
  unsigned process_sample_rate = 0;

  bool had_overrides = false;
  unsigned long long buf;
  if (GetGwpAsanOption(&buf, kSampleRateSystemSysprop, kSampleRateTargetedSyspropPrefix,
                       kSampleRateEnvVar, "sample rate")) {
    options.SampleRate = buf;
    had_overrides = true;
  }

  if (GetGwpAsanOption(&buf, kProcessSamplingSystemSysprop, kProcessSamplingTargetedSyspropPrefix,
                       kProcessSamplingEnvVar, "process sampling rate")) {
    process_sample_rate = buf;
    had_overrides = true;
  }

  if (GetGwpAsanOption(&buf, kMaxAllocsSystemSysprop, kMaxAllocsTargetedSyspropPrefix,
                       kMaxAllocsEnvVar, "maximum simultaneous allocations")) {
    options.MaxSimultaneousAllocations = buf;
  } else if (had_overrides) {
    // Multiply the number of slots available, such that the ratio between
    // sampling rate and slots is kept the same as the default. For example, a
    // sampling rate of 1000 is 2.5x more frequent than default, and so
    // requires 80 slots (32 * 2.5).
    float frequency_multiplier = static_cast<float>(options.SampleRate) / kDefaultSampleRate;
    options.MaxSimultaneousAllocations =
        static_cast<int>(/* default */ kDefaultMaxAllocs / frequency_multiplier);
  } else {
    return false;
  }

  warning_log("Options: sample_rate=%d, process_sample_rate=%d, max_slots=%d", options.SampleRate,
              process_sample_rate, options.MaxSimultaneousAllocations);

  // If the caller hasn't forced GWP-ASan on, check whether we should sample
  // this process.
  if (!force_init && !ShouldGwpAsanSampleProcess(process_sample_rate)) {
    return false;
  }

  if (options.SampleRate == 0 || process_sample_rate == 0 ||
      options.MaxSimultaneousAllocations == 0) {
    return false;
  }

  // GWP-ASan is compatible with heapprofd/malloc_debug/malloc_hooks iff
  // GWP-ASan was installed first. If one of these other libraries was already
  // installed, we don't enable GWP-ASan. These libraries are normally enabled
  // in libc_init after GWP-ASan, but if the new process is a zygote child and
  // trying to initialize GWP-ASan through mallopt(), one of these libraries may
  // be installed. It may be possible to change this in future by modifying the
  // internal dispatch pointers of these libraries at this point in time, but
  // given that they're all debug-only, we don't really mind for now.
  if (GetDefaultDispatchTable() != nullptr) {
    // Something else is installed.
    return false;
  }

  // GWP-ASan's initialization is always called in a single-threaded context, so
  // we can initialize lock-free.
  // Set GWP-ASan as the malloc dispatch table.
  globals->malloc_dispatch_table = gwp_asan_dispatch;
  atomic_store(&globals->default_dispatch_table, &gwp_asan_dispatch);

  // If malloc_limit isn't installed, we can skip the default_dispatch_table
  // lookup.
  if (GetDispatchTable() == nullptr) {
    atomic_store(&globals->current_dispatch_table, &gwp_asan_dispatch);
  }

#ifndef LIBC_STATIC
  SetGlobalFunctions(gwp_asan_gfunctions);
#endif  // LIBC_STATIC

  GwpAsanInitialized = true;

  gwp_asan_initialize(NativeAllocatorDispatch(), nullptr, nullptr, options);

  warning_log("Finish gwp_asan init!");
  return true;
}
