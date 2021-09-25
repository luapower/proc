---
tagline: processes and IPC
---

## `local proc = require'proc'`

A library for creating, controlling and communicating with child processes.
Works on Windows, Linux and OSX.

## Status

<warn>Needs more testing.</warn>

Missing features:

  * named mutexes, semaphores and events.
  * setting CPU and RAM limits.
  * CPU and RAM monitoring.

## API

--------------------------------------------------- --------------------------
`proc.exec(args,...) -> p`                          spawn a child process
`proc.exec_luafile(file,[args],...) -> p`           spawn a process running a Lua script
`p:kill()`                                          kill process
`p:wait([expires]) -> status`                       wait for a process to finish
`p:status() -> active|finished|killed|forgotten`    process status
`p:exit_code() -> code | nil,status`                get process exit code
`p:forget()`                                        close process handles
`proc.env(k) -> v`                                  get env. var
`proc.setenv(k, v)`                                 set env. var
`proc.setenv(k)`                                    delete env. var
`proc.env() -> env`                                 get all env. vars
--------------------------------------------------- --------------------------

### `proc.exec(args,[env],[cur_dir],[stdin],[stdout],[stderr],[autokill]) -> p`

Spawn a child process and return a process object to query and control the
process. Options can be given as separate args or in a table.

  * `cmd` can be either a string or an array containing the filepath of the
  executable to run and its command-line arguments..
  * `env` is a table of environment variables (if not given, the current
  environment is inherited).
  * `cur_dir` is the directory to start the process in.
  * `stdin`, `stdout`, `stderr` are pipe ends created with `fs.pipe()`
  to redirect the standard input, output and error streams of the process;
  you can also set any of these to `true` to have them opened (and closed) for you.
  * `autokill` kills the process when the calling process exits.

## Programming Notes

#### Env vars

Only use uppercase env. var names because like file names, env. vars
are case-sensitive on POSIX, but case-insensitive on Windows.

If using `proc.setenv()`, use `proc.env()` to read back variables instead
of `os.getenv()` because the latter won't see the changes.

#### Exit codes

Only use exit status codes in the 0..255 range because Windows exit
codes are int32 but POSIX codes are limited to a byte.

In Windows, if you kill a process from Task Manager, `exit_code()` returns 1
instead of `nil, 'killed'`, and `status()` returns `'finished'` instead
of `'killed'`. You only get `'killed'` when you kill the process yourself
by calling `kill()`.

#### Standard I/O redirection

The only way to safely redirect both stdin and stdout of child processes
without potentially causing deadlocks is to use async pipes and perform
the writes and the reads in separate [sock] threads.

Don't forget to close the stdin file when you're done with it to signal
end-of-input to the child process.

Don't forget to check for a zero-length read which can happen any time
and signals that the child process closed its end of the pipe.

#### Cleaning up

Always call forget() when you're done with the process, even after you killed it.

#### Autkill caveats

In Linux, if you start your autokilled process from a thread other than
the main thread, the process is killed when the thread finishes, IOW
autokill is only portable if you start processes from the main thread.

In Windows, the autokill behavior is by default inherited by the child
processes. In Linux it isn't. IOW autkill inheritance is not portable.

