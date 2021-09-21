
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

--TODO: autokill with job objects:
--https://stackoverflow.com/questions/2345034/terminate-all-grandchildren-when-terminating-a-child-process
--NOTE: with this solution you can't run processes that use jobs themselves until Win8.

--TODO: could probably spend some more time on this...
local function esc(s)
	s = s:gsub('(["&\\<>^|])', '^%1')
	if s:find'%s' then
		s = '"'..s..'"'
	end
	return s
end

local INVALID_HANDLE_VALUE = ffi.cast('HANDLE', -1)

function M.exec(cmd, args, env, dir, stdin, stdout, stderr, autokill, inherit_all_handles)
	if args then
		local t = {esc(cmd)}
		for i,s in ipairs(args) do
			t[i+1] = esc(s)
		end
		cmd = table.concat(t, ' ')
	end
	local si
	if stdin or stdout or stderr then
		si = winapi.STARTUPINFO()
		si.hStdInput  = stdin  and stdin .handle or INVALID_HANDLE_VALUE
		si.hStdOutput = stdout and stdout.handle or INVALID_HANDLE_VALUE
		si.hStdError  = stderr and stderr.handle or INVALID_HANDLE_VALUE
		si.dwFlags = winapi.STARTF_USESTDHANDLES
		--NOTE: there's no way to inherit only these std handles: all handles
		--declared inheritable in the parent process will be inherited!
		inherit_all_handles = true
	end
	local proc_info, err, code = winapi.CreateProcess(cmd, env, dir, si, inherit_all_handles)
	if not proc_info then
		return nil, err, code
	end
	local proc = inherit({}, proc)
	proc.handle = proc_info.hProcess
	proc.main_thread_handle = proc_info.hThread
	proc.id = proc_info.dwProcessId
	proc.main_thread_id = proc_info.dwThreadId
	return proc
end

function proc:forget()
	if not self.handle then return end
	assert(winapi.CloseHandle(self.handle))
	assert(winapi.CloseHandle(self.main_thread_handle))
	self.handle = false
	self.id = false
	self.main_thread_handle = false
	self.main_thread_id = false
end

--compound the STILL_ACTIVE hack with another hack to signal killed status.
local EXIT_CODE_KILLED = winapi.STILL_ACTIVE + 1

function proc:kill()
	if not self.handle then
		return nil, 'invalid handle'
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
		return nil, 'invalid handle'
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

function M.popen_async(cmd, args, env, dir,
	open_stdin, open_stdout, open_stderr, autokill, inherit_all_handles)

	local fs = require'fs'

	local in_rf, in_wf
	local out_rf, out_wf
	local err_rf, err_wf
	local p, err, errno

	local function close_all()
		if in_rf  then in_rf :close() end
		if in_wf  then in_wf :close() end
		if out_rf then out_rf:close() end
		if out_wf then out_wf:close() end
		if err_rf then err_rf:close() end
		if err_wf then err_wf:close() end
	end

	local function try(ret, ...)
		if not ret then
			close_all()
		end
		return ret, ...
	end

	if open_stdin then
		in_rf, in_wf, errno = try(fs.pipe{
			write_async = true,
			read_inheritable = true,
		})
		if not in_rf then
			return nil, in_wf, errno
		end
	end

	if open_stdout then
		out_rf, out_wf, errcode = try(fs.pipe{
			read_async = true,
			write_inheritable = true,
		})
		if not out_rf then
			return nil, out_wf, errno
		end
	end

	if open_stderr then
		err_rf, err_wf, errno = try(fs.pipe{
			read_async = true,
			write_inheritable = true,
		})
		if not err_rf then
			return nil, err_wf, errno
		end
	end

	p, err, errno = try(M.exec(cmd, args, env, dir,
		in_rf, out_wf, err_wf, autokill, inherit_all_handles))
	if not p then
		return nil, err, errno
	end

	local forget = p.forget
	function p:forget()
		close_all()
		return forget(p)
	end

	local kill = p.kill
	function p:kill()
		close_all()
		return kill(p)
	end

	--let the child process have the only handles to these pipe end points,
	--otherwise when the child process exits, the pipes will stay open on
	--account of us (the parent process) holding a handle to them.
	if in_rf then in_rf:close() end
	if out_wf then out_wf:close() end
	if err_wf then err_wf:close() end

	--allow a function's `buf, sz` args to be `s, [len]`.
	local function stringdata(buf, sz)
		if type(buf) == 'string' then
			if sz then
				assert(sz <= #buf, 'string too short')
			else
				sz = #buf
			end
			return ffi.cast('char*', buf), sz
		else
			assert(type(buf) == 'cdata', type(buf))
			assert(type(sz) == 'number', type(sz))
			return buf, sz
		end
	end

	local function writeall(wf, s, len, expires)
		local buf, sz = stringdata(s, len)
		while sz > 0 do
			local len, err, errno = wf:write_async(buf, sz, expires)
			if not len then return nil, err, errno end
			buf = buf + len
			sz  = sz  - len
		end
		return true
	end

	local function write_func(wf)
		return wf and function(self, s, len, expires)
			if not s then
				wf:close()
				return true
			end
			local ok, err, errno = writeall(wf, s, len, expires)
			if not ok then
				wf:close()
				return nil, err, errno
			end
			return ok
		end
	end

	local function read_func(rf)
		return rf and function(self, buf, sz, expires)
			if buf == '*a' then --read all till the pipe breaks.
				local t = {}
				local sz = 4096
				local buf = ffi.new('char[?]', sz)
				while true do
					local len, err, errno = rf:read_async(buf, sz, expires)
					if not len then
						if err == 'broken_pipe' then
							break
						else
							rf:close()
							return nil, err, errno
						end
					end
					t[#t+1] = ffi.string(buf, len)
				end
				rf:close()
				return table.concat(t)
			else
				return rf:read_async(buf, sz, expires)
			end
		end
	end

	p.read_stdout = read_func(out_rf)
	p.read_stderr = read_func(err_rf)
	p.write_stdin = write_func(in_wf)

	return p
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

function M.exec(cmd, args, env, dir, stdin, stdout, stderr, autokill, inherit_all_handles)

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
		if autokill then
			if C.prctl(PR_SET_PDEATHSIG, SIGTERM) == -1 then
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
			return nil, 'exec() failed', err[0]
		end

		return inherit({id = pid}, proc)

	end
end

function proc:forget()
	self.id = false
end

function proc:kill()
	if not self.id then
		return nil, 'invalid pid'
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
		return nil, 'invalid pid'
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

else
	error('unsupported OS '..ffi.os)
end

local function exec_args(std_prefix, cmd_field, cmd, args, env, dir,
	stdin, stdout, stderr, autokill, inherit_all_handles
)
	if type(cmd) == 'table' then
		local t = cmd
		cmd      = t[cmd_field]
		args     = t.args
		env      = t.env
		dir      = t.dir
		stdin    = t[std_prefix..'stdin']
		stdout   = t[std_prefix..'stdout']
		stderr   = t[std_prefix..'stderr']
		autokill = t.autokill
		inherit_all_handles = t.inherit_all_handles
	end
	assert(cmd)
	return cmd, args, env, dir, stdin, stdout, stderr, autokill, inherit_all_handles
end

local exec = M.exec
function M.exec(...)
	return exec(exec_args('', 'command', ...))
end

local popen_async = M.popen_async
function M.popen_async(...)
	return popen_async(exec_args('open_', 'command', ...))
end

function M.exec_luafile(...)
	local function pass(script, args, ...)
		local exepath = require'package.exepath'
		local args = extend({script}, args)
		return M.exec(exepath, args, ...)
	end
	return pass(exec_args('', 'script', ...))
end

function M.popen_async_luafile(...)

end

return M
