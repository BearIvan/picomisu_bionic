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

#include "private/android_unsafe_frame_pointer_chase.h"

#include <signal.h>

#include "pthread_internal.h"

// As on the factory PICO OS 5.13.7 libc: the end of the walk is the calling thread's
// pthread_internal_t::stack_top (set by pthread_create; 0 on the main thread, which then stops
// after the first frame) or the top of the alternate signal stack when running on it.
__attribute__((no_sanitize("address", "hwaddress"))) size_t android_unsafe_frame_pointer_chase(
    uintptr_t* buf, size_t num_entries) {
  struct frame_record {
    uintptr_t next_frame, return_addr;
  };

  auto begin = reinterpret_cast<uintptr_t>(__builtin_frame_address(0));
  uintptr_t end = __get_thread()->stack_top;

  stack_t ss;
  if (sigaltstack(nullptr, &ss) == 0 && (ss.ss_flags & SS_ONSTACK)) {
    end = reinterpret_cast<uintptr_t>(ss.ss_sp) + ss.ss_size;
  }

  size_t num_frames = 0;
  while (1) {
    auto* frame = reinterpret_cast<frame_record*>(begin);
    if (num_frames < num_entries) {
      buf[num_frames] = frame->return_addr;
    }
    ++num_frames;
    if (frame->next_frame < begin + sizeof(frame_record) || frame->next_frame >= end ||
        frame->next_frame % sizeof(void*) != 0) {
      break;
    }
    begin = frame->next_frame;
  }

  return num_frames;
}
