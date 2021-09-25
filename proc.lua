
--Process & IPC API for Windows & POSIX.
--Written by Cosmin Apreutesei. Public Domain.

if not ... then require'proc_test'; return end

local ffi = require'ffi'
local bit = require'bit'
local M = {}
local proc = {}

local function inherit(t, super)
	return setmetatable(t, {__index = super})
end

local function extend(dt, t)
	if not t then return dt end
	local j = #dt
	for i=1,#t do dt[j+i]=t[i] end
end

if ffi.os == 'Windows' then --------------------------------------------------

--TODO: move relevant ctypes here and get rid of the huge dependency.
local winapi = require'winapi'
require'winapi.process'
require'winapi.thread'

function M.env(k)
	if k then
		return winapi.GetEnvironmentVariable(k)
	end
	local t = {}
	for i,s in ipairs(winapi.GetEnvironmentStrings()) do
		local k,v = s:match'^([^=]*)=(.*)'
		if k and k ~= '' then --the first two ones are internal and invalid.
			t[k] = v
		end
	end
	return t
end

--NOTE: don't use os.getenv() after proc.setenv(), use only proc.env().
function M.setenv(k, v)
	winapi.SetEnvironmentVariable(k, v)
end

--TODO: could probably spend more time on this...
local function esc(s)
	s = s:gsub('(["&<>^|])', '^%1')
	if s:find'%s' then
		s = '"'..s..'"'
	end
	return s
end

local INVALID_HANDLE_VALUE = ffi.cast('HANDLE', -1)

local autokill_job

local error_classes = {
	[0x002] = 'not_found', --ERROR_FILE_NOT_FOUND
	[0x005] = 'access_denied', --ERROR_ACCESS_DENIED
}

function M.exec(cmd, env, dir, stdin, stdout, stderr, autokill, async, inherit_handles)

	if type(cmd) == 'table' then
		local t = {}
		for i,s in ipairs(cmd) do
			t[i] = esc(s)
		end
		cmd = table.concat(t, ' ')
	end

	local inp_rf, inp_wf
	local out_rf, out_wf
	local err_rf, err_wf

	local function close_all()
		if inp_rf then inp_rf:close() end
		if inp_wf then inp_wf:close() end
		if out_rf then out_rf:close() end
		if out_wf then out_wf:close() end
		if err_rf then err_rf:close() end
		if err_wf then err_wf:close() end
	end

	local self = inherit({async = async}, proc)

	if async then
		local sock = require'sock'
		self._sleep = sock.sleep
		self._clock = sock.clock
	else
		local time = require'time'
		self._sleep = time.sleep
		self._clock = time.clock
	end

	local si, err, errcode

	if stdin or stdout or stderr then

		if stdin == true then
			local fs = require'fs'
			inp_rf, inp_wf, errcode = fs.pipe{
				write_async = async,
				read_inheritable = true,
			}
			if not inp_rf then
				close_all()
				return nil, inp_wf, errcode
			end
			stdin = inp_wf
			self.own_stdin = true
		elseif stdin then
			assert(stdin.is_pipe_end)
			assert(not stdin.write_async == not async)
		end

		if stdout == true then
			local fs = require'fs'
			out_rf, out_wf, errcode = fs.pipe{
				read_async = async,
				write_inheritable = true,
			}
			if not out_rf then
				close_all()
				return nil, out_wf, errcode
			end
			stdout = out_rf
			self.own_stdout = true
		elseif stdout then
			assert(stdout.is_pipe_end)
			assert(not stdout.read_async == not async)
		end

		if stderr == true then
			local fs = require'fs'
			err_rf, err_wf, errcode = fs.pipe{
				read_async = async,
				write_inheritable = true,
			}
			if not err_rf then
				close_all()
				return nil, err_wf, errcode
			end
			stderr = err_rf
			self.own_stderr = true
		elseif stderr then
			assert(stderr.is_pipe_end)
			assert(not stderr.read_async == not async)
		end

		self.stdin  = stdin
		self.stdout = stdout
		self.stderr = stderr

		si = winapi.STARTUPINFO()
		si.hStdInput  = stdin  and stdin .handle or INVALID_HANDLE_VALUE
		si.hStdOutput = stdout and stdout.handle or INVALID_HANDLE_VALUE
		si.hStdError  = stderr and stderr.handle or INVALID_HANDLE_VALUE
		si.dwFlags = winapi.STARTF_USESTDHANDLES

		--NOTE: there's no way to inherit only the std handles: all handles
		--declared inheritable in the parent process will be inherited!
		inherit_handles = true
	end

	if autokill and not autokill_job then
		autokill_job = winapi.CreateJobObject()
		local jeli = winapi.JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
		jeli.BasicLimitInformation.LimitFlags = winapi.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
		winapi.SetInformationJobObject(autokill_job, winapi.C.JobObjectExtendedLimitInformation, jeli)
	end

	local is_in_job = autokill and winapi.IsProcessInJob(winapi.GetCurrentProcess(), nil)

	local pi, err, errcode = winapi.CreateProcess(
		cmd, env, dir, si, inherit_handles,
			autokill
				and bit.bor(
					winapi.CREATE_SUSPENDED, --so we have time to assign it to a job
					is_in_job and winapi.CREATE_BREAKAWAY_FROM_JOB or 0
				)
				or nil)

	if not pi then
		close_all()
		err = error_classes[errcode] or err
		return nil, err, errcode
	end

	if autokill then
		winapi.AssignProcessToJobObject(autokill_job, pi.hProcess)
		winapi.ResumeThread(pi.hThread)
	end

	--let the child process have the only handles to their pipe ends,
	--otherwise when the child process exits, the pipes will stay open on
	--account of us (the parent process) holding a handle to them.
	if inp_rf then inp_rf:close() end
	if out_wf then out_wf:close() end
	if err_wf then err_wf:close() end

	self.handle             = pi.hProcess
	self.main_thread_handle = pi.hThread
	self.id                 = pi.dwProcessId
	self.main_thread_id     = pi.dwThreadId

	return self
end

function proc:forget()
	if self.stdin  and self.own_stdin  then self.stdin :close() end
	if self.stdout and self.own_stdout then self.stdout:close() end
	if self.stderr and self.own_stderr then self.stderr:close() end
	if self.handle then
		assert(winapi.CloseHandle(self.handle))
		assert(winapi.CloseHandle(self.main_thread_handle))
		self.handle = false
		self.id = false
		self.main_thread_handle = false
		self.main_thread_id = false
	end
end

--compound the STILL_ACTIVE hack with another hack to signal killed status.
local EXIT_CODE_KILLED = winapi.STILL_ACTIVE + 1

function proc:kill()
	if not self.handle then
		return nil, 'forgotten'
	end
	return winapi.TerminateProcess(self.handle, EXIT_CODE_KILLED)
end

function proc:exit_code()
	if self._exit_code then
		return self._exit_code
	elseif self._killed then
		return nil, 'killed'
	end
	if not self.handle then
		return nil, 'forgotten'
	end
	local exitcode = winapi.GetExitCodeProcess(self.handle)
	if not exitcode then
		return nil, 'active'
	end
	--save the exit status so we can forget the process.
	if exitcode == EXIT_CODE_KILLED then
		self._killed = true
	else
		self._exit_code = exitcode
	end
	self:forget()
	return self:exit_code()
end

function proc:wait(expires)
	if not self.handle then
		return nil, 'forgotten'
	end
	while self:status() == 'active' and self._clock() < expires do
		self._sleep(0.01)
	end
	local exit_code, err = self:exit_code()
	if exit_code then
		return exit_code
	else
		return nil, err
	end
end

function proc:status() --finished | killed | active | forgotten
	local x, err = self:exit_code()
	return x and 'finished' or err
end

elseif ffi.os == 'Linux' or ffi.os == 'OSX' then -----------------------------

ffi.cdef[[
extern char **environ;
int setenv(const char *name, const char *value, int overwrite);
int unsetenv(const char *name);
int execve(const char *file, char *const argv[], char *const envp[]);
typedef int pid_t;
pid_t fork(void);
int kill(pid_t pid, int sig);
typedef int idtype_t;
typedef int id_t;
pid_t waitpid(pid_t pid, int *status, int options);
void _exit(int status);
int pipe(int[2]);
int fcntl(int fd, int cmd, ...);
int close(int fd);
ssize_t write(int fd, const void *buf, size_t count);
ssize_t read(int fd, void *buf, size_t count);
int chdir(const char *path);
char *getcwd(char *buf, size_t size);
int dup2(int oldfd, int newfd);
pid_t getpid(void);
pid_t getppid(void);
int prctl(int option, unsigned long arg2, unsigned long arg3,
	unsigned long arg4, unsigned long arg5);
]]

local F_GETFD = 1
local F_SETFD = 2
local FD_CLOEXEC = 1
local PR_SET_PDEATHSIG = 1
local SIGTERM = 15
local SIGKILL = 9
local WNOHANG = 1
local EAGAIN = 11
local EINTR  = 4
local ERANGE = 34

local error_classes = {
	[ 1] = 'access_denied', --EPERM (need root)
	[ 2] = 'not_found', --ENOENT
	[13] = 'access_denied', --EACCES (file perms)
}

local C = ffi.C

local char     = ffi.typeof'char[?]'
local char_ptr = ffi.typeof'char*[?]'
local int      = ffi.typeof'int[?]'

local function err(func)
	local errno = ffi.errno()
	local s = C.strerror(errno)
	local s = s ~= nil and ffi.string(s) or 'Error '..errno
	return nil, func .. '() failed: ' .. s, errno
end

function M.env(k)
	if k then
		return os.getenv(k)
	end
	local e = C.environ
	local t = {}
	local i = 0
	while e[i] ~= nil do
		local s = ffi.string(e[i])
		local k,v = s:match'^([^=]*)=(.*)'
		if k and k ~= '' then
			t[k] = v
		end
		i = i + 1
	end
	return t
end

function M.setenv(k, v)
	assert(k)
	if v then
		assert(C.setenv(k, v, 1) == 0)
	else
		assert(C.unsetenv(k) == 0)
	end
end

function getcwd()
	local sz = 256
	local buf = char(sz)
	while true do
		if C.getcwd(buf, sz) == nil then
			if ffi.errno() ~= ERANGE then
				return err'getcwd'
			else
				sz = sz * 2
				buf = char(sz)
			end
		end
		return ffi.string(buf)
	end
end

function M.exec(t, env, dir, stdin, stdout, stderr, autokill, async, inherit_handles)

	local cmd, args
	if type(t) == 'table' then
		cmd = t[1]
		if #t > 1 then
			args = {}
			for i = 2, #t do
				args[i-1] = t[i]
			end
		end
	else
		for s in t:gmatch'[^%s]+' do
			if not cmd then
				cmd = s
			else
				if not args then
					args = {}
				end
				args[#args+1] = s
			end
		end
	end

	if dir and cmd:sub(1, 1) ~= '/' then
		cmd = getcwd() .. '/' .. cmd
	end

	--copy the args list to a char*[] buffer.
	local arg_buf, arg_ptrs
	if args then
		local n = #cmd + 1
		local m = #args + 1
		for i,s in ipairs(args) do
			n = n + #s + 1
		end
		arg_buf = char(n)
		arg_ptr = char_ptr(m + 1)
		local n = 0
		ffi.copy(arg_buf, cmd, #cmd + 1)
		arg_ptr[0] = arg_buf
		n = n + #cmd + 1
		for i,s in ipairs(args) do
			ffi.copy(arg_buf + n, s, #s + 1)
			arg_ptr[i] = arg_buf + n
			n = n + #s + 1
		end
		arg_ptr[m] = nil
	end

	--copy the env. table to a char*[] buffer.
	local env_buf, env_ptrs
	if env then
		local n = 0
		local m = 0
		for k,v in pairs(env) do
			v = tostring(v)
			n = n + #k + 1 + #v + 1
			m = m + 1
		end
		env_buf = char(n)
		env_ptr = char_ptr(m + 1)
		local i = 0
		local n = 0
		for k,v in pairs(env) do
			v = tostring(v)
			env_ptr[i] = env_buf + n
			ffi.copy(env_buf + n, k, #k)
			n = n + #k
			env_buf[n] = string.byte('=')
			n = n + 1
			ffi.copy(env_buf + n, v, #v + 1)
			n = n + #v + 1
		end
		env_ptr[m] = nil
	end

	--see https://stackoverflow.com/questions/1584956/how-to-handle-execvp-errors-after-fork
	local pipefds = int(2)
	if C.pipe(pipefds) ~= 0 then
		return err'pipe'
	end
	local flags = C.fcntl(pipefds[1], F_GETFD)
	local flags = bit.bor(flags, FD_CLOEXEC)
	if C.fcntl(pipefds[1], F_SETFD, ffi.cast('int', flags)) ~= 0 then
		return err'fcnt'
 	end

	local ppid_before_fork = autokill and C.getpid()
	local pid = C.fork()

	if pid == -1 then --in parent process

		return err'fork'

	elseif pid == 0 then --in child process

		--see https://stackoverflow.com/questions/284325/how-to-make-child-process-die-after-parent-exits/36945270#36945270
		--TODO: prctl() must be called from the main thread. If instead it is
		--called from a secondary thread, the process will die with that thread !!
		if autokill then
			if C.prctl(PR_SET_PDEATHSIG, SIGTERM, 0, 0, 0) == -1 then
				return err'prctl'
			end
			-- test if the original parent exited just before the prctl() call.
			if C.getppid() ~= ppid_before_fork then
				C._exit(0)
			end
		end

		C.close(pipefds[0])

		if dir and C.chdir(dir) ~= 0 then
			--chdir failed: put errno on the pipe and exit.
			local err = int(1, ffi.errno())
			C.write(pipefds[1], err, ffi.sizeof(err))
			C._exit(0)
		end

		if stdin  then C.dup2(stdin .fd, 0) end
		if stdout then C.dup2(stdout.fd, 1) end
		if stderr then C.dup2(stderr.fd, 2) end

		C.execve(cmd, arg_ptr, env_ptr)

		--exec failed: put errno on the pipe and exit.
		local err = int(1, ffi.errno())
		C.write(pipefds[1], err, ffi.sizeof(err))
		C._exit(0)

	else --in parent process

		--check if exec failed by reading from the errno pipe.
		C.close(pipefds[1])
		local err = int(1)
		local n
		repeat
			n = C.read(pipefds[0], err, ffi.sizeof(err))
		until not (n == -1 and (ffi.errno() == EAGAIN or ffi.errno() == EINTR))
		C.close(pipefds[0])
		if n > 0 then
			local errno = err[0]
			local err = error_classes[errno] or 'exec() failed'
			return nil, err, errno
		end

		local self = inherit({id = pid}, proc)

		if async then
			local sock = require'sock'
			self._sleep = sock.sleep
			self._clock = sock.clock
		else
			local time = require'time'
			self._sleep = time.sleep
			self._clock = time.clock
		end

		return self
	end
end

function proc:forget()
	self.id = false
end

function proc:kill()
	if not self.id then
		return nil, 'forgotten'
	end
	if C.kill(self.id, SIGKILL) ~= 0 then
		return err'kill'
	end
	return true
end

function proc:exit_code()
	if self._exit_code then
		return self._exit_code
	elseif self._killed then
		return nil, 'killed'
	end
	if not self.id then
		return nil, 'forgotten'
	end
	local status = int(1)
	local pid = C.waitpid(self.id, status, WNOHANG)
	if pid < 0 then
		return err'waitpid'
	end
	if pid == 0 then
		return nil, 'active'
	end
	--save the exit status so we can forget the process.
	if bit.band(status[0], 0x7f) == 0 then --exited with exit code
		self._exit_code = bit.rshift(bit.band(status[0], 0xff00), 8)
	else
		self._killed = true
	end
	self:forget()
	return self:exit_code()
end

function proc:wait(expires)
	if not self.id then
		return nil, 'forgotten'
	end
	while self:status() == 'active' and self._clock() < expires do
		self._sleep(0.01)
	end
	local exit_code, err = self:exit_code()
	if exit_code then
		return exit_code
	else
		return nil, err
	end
end

function proc:status() --finished | killed | active | forgotten
	local x, err = self:exit_code()
	return x and 'finished' or err
end

else
	error('unsupported OS '..ffi.os)
end

--wrappers -------------------------------------------------------------------

local exec = M.exec
function M.exec(t, ...)
	if type(t) == 'table' then
		return exec(t.cmd, t.env, t.dir, t.stdin, t.stdout, t.stderr,
			t.autokill, t.async, t.inherit_handles)
	else
		return exec(t, ...)
	end
end

function M.exec_luafile(arg, ...)
	local exepath = require'package.exepath'
	local script = type(arg) == 'string' and arg or arg.script
	local cmd = type(script) == 'string' and {exepath, script} or extend({exepath}, script)
	if type(arg) == 'string' then
		return M.exec(cmd, ...)
	else
		local t = {cmd = cmd}
		for k,v in pairs(arg) do t[k] = v end
		return M.exec(t)
	end
end

return M
