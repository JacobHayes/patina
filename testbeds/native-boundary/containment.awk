    function trusted_path(a) {
      return (a ~ /\.so(\.|"|$)/) || (a ~ /"\/etc\/ld\.so\.cache"/) || (a ~ /"\/etc\/ld\.so\.preload"/) || (a ~ /"\/proc\/self\/maps"/)
    }
    {
      line = $0
      sub(/^[0-9]+ +/, "", line)
      if (line ~ /^--- / || line ~ /^\+\+\+ /) next
      syscall = line
      sub(/\(.*/, "", syscall)
      args = line
      sub(/^[^(]*\(/, "", args)
      # Track fds opened on a trusted prelude path; release them on close so a
      # reused fd number is not carried over to application code.
      if (syscall ~ /^(openat|openat2|open)$/ && trusted_path(args) && line ~ /= *[0-9]+$/) {
        ret = line; sub(/^.*= */, "", ret); sub(/[^0-9].*/, "", ret); if (ret != "") trusted[ret] = 1
      }
      if (syscall == "close") { cfd = args; sub(/[^0-9].*/, "", cfd); if (cfd != "") delete trusted[cfd] }
      if (syscall ~ /^(execve|brk|arch_prctl|mmap|mmap2|munmap|mprotect|madvise|futex|sched_yield|sigaltstack|rt_sigaction|rt_sigprocmask|rt_sigreturn|exit|exit_group|close)$/) next
      if (syscall == "getrandom" && args ~ /GRND_NONBLOCK/) next
      if (syscall ~ /^(openat|openat2|open|newfstatat|readlink|readlinkat)$/ && trusted_path(args)) next
      if (syscall ~ /^(faccessat|faccessat2|access)$/ && args ~ /"\/etc\/ld\.so\.preload"/) next
      if (syscall ~ /^(read|pread64|fstat|fcntl|lseek)$/) {
        fd = args; sub(/[^0-9].*/, "", fd)
        if (fd ~ /^[0-3]$/ || (fd != "" && (fd in trusted))) next
      }
      if (syscall == "write" && args ~ /^[0-3][,)]/) next
      print line
    }
