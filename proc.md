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
  * kill child process automatically when the parent process exits.
  * setting CPU and RAM limits.
  * CPU and RAM monitoring.

## API

--------------------------------------------------- --------------------------
`proc.exec(cmd,[args],...) -> p`                    spawn a child process
`proc.exec_luafile(file,[args],...) -> p`           spawn a process running a Lua script
`p:kill()`                                          kill process
`p:exit_code() -> code | nil,'active'|'killed'`     get process status or exit code
`p:forget()`                                        close process handles
`proc.env(k) -> v`                                  get env. var
`proc.setenv(k, v)`                                 set env. var
`proc.setenv(k)`                                    delete env. var
`proc.env() -> env`                                 get all env. vars
`proc.popen_async(cmd,[args],...) -> ap`            exec with async stdin/stdout/stderr pipes
`ap:read_stdout('*a' | buf,sz, [expires]) -> len`   read from process's stdout
`ap:read_stderr('*a' | buf,sz, [expires]) -> len`   read from process's stderr
`ap:write_stdin(s | buf,sz, [expires) -> len`       write to process's stdin
--------------------------------------------------- --------------------------

### `proc.exec(cmd,[args],[env],[cur_dir],[stdin],[stdout],[stderr],[autokill]) -> p`

Spawn a child process and return a process object to query and control the
process. Options can be given as separate args or in a table.

  * `cmd` is the filepath of the executable to run.
  * `args` is an array of strings representing command-line arguments.
  * `env` is a table of environment variables (if not given, the current
  environment is inherited).
  * `cur_dir` is the directory to start the process in.
  * `stdin`, `stdout`, `stderr` are pipe ends created with `fs.pipe()`
  to redirect the standard input, output and error streams of the process.
  * `autokill` kills the process when the calling process exits.

### `proc.popen_async(cmd,[args],[env],[cur_dir],[open_stdin],[open_stdout],[open_stderr],[autokill]) -> p`

Async popen, i.e. exec with added `read_stdout`, `read_stderr` and `write_stdin`
methods that you can use to perform async stdin/stdout/stderr I/O inside
a [sock] thread. Don't forget to use different threads for input and output
to avoid deadlock.

## Programming Notes

* only use uppercase env. var names because like file names, env. vars
  are case-sensitive on POSIX, but case-insensitive on Windows.
* only use exit status codes in the 0..255 range because Windows exit
  codes are int32 but POSIX codes are limited to a byte.
* if using `proc.setenv()`, use `proc.env()` to read back variables instead
of `os.getenv()` because the latter won't see the changes.
