#!/usr/bin/python2

from datetime import datetime
from collections import deque

# Immediates are instructions of the form
# jmp $+4 (3 ints)
# dd data (1 int)
# <other code>

data = []
written = set()
functions = [] #(address, argument count)

# ==================== Tracing ==================== #

def u16(d):
	d = [ord(x) for x in d]
	return (d[1] << 8) | d[0]

def int16(x):
	if x > 0x7fff:
		return -int(0x10000 - x)
	return x

with open('instructions.bin', 'rb') as fin:
	data = fin.read()
assert len(data) % 2 == 0
data = [int16(u16(data[i:i+2])) for i in range(0, len(data), 2)]
_data = [x for x in data]

def subleq(data, sub, target, jump):
	data[target] = int16(data[target] - data[sub])
	if jump != 0 and data[target] <= 0:
		return True
	return False

def trace():
	global data
	datalen = 0x2DAD / 2
	ip = 5
	curout = ''
	curin = ''
	ips = []
	ctr = 0
	
	while ip + 3 <= datalen:
		ips.append(ip)
		written.add(data[ip + 1])
		
		# if ip == 1701:
			# print data[2037], data[2031], data[2032], data[2030], data[2036]
			# ctr += 1
		# # if ctr > 20: break
		
		if subleq(data, data[ip], data[ip + 1], data[ip + 2]):
			if data[ip + 2] == -1:
				break
			ip = data[ip + 2]
		else:
			ip += 3
		
		if data[4] == 1:
			if chr(data[2]) != '\n':
				curout += chr(data[2])
			else:
				print curout
				curout = ''
			data[4] = 0
			data[2] = 0
		
		if data[3] == 1:
			if len(curout) > 0:
				print curout
				curout = ''
			if len(curin) == 0:
				curin = raw_input('') + '\n'
			data[1] = ord(curin[0])
			data[3] = 0
			curin = curin[1:]
	# print ctr
	return ips

# Bfs from all visited addresses to find unvisited parts of code
def expand(ips):
	visited, queue = set(), deque(ips)
	
	while len(queue) > 0:
		ip = queue.popleft()
		if ip < 0 or ip in visited:
			continue
		visited.add(ip)
		if ip not in ips:
			ips.append(ip)
			written.add(data[ip + 1])
			data[data[ip + 1]] = int16(data[data[ip + 1]] - data[data[ip]])
		
		if data[ip + 2] != 0:
			if data[ip] == 0 and data[ip + 1] == 0:
				if data[ip + 2] not in visited:
					queue.append(data[ip + 2])
			else:
				if data[ip + 2] not in visited:
					queue.append(data[ip + 2])
				if ip + 3 not in visited:
					queue.append(ip + 3)
		else:
			if ip + 3 not in visited:
				queue.append(ip + 3)
		
	return sorted(ips)

# ==================== Parsers ==================== #

# Offsets of some variables used throughout the code
class Vars:
	@classmethod
	def build(cls):
		cls.tmp =     Data(0, 'tmp')
		cls.input =   Data(1, 'input')
		cls.output =  Data(2, 'output')
		cls.inflag =  Data(3, 'input flag')
		cls.outflag = Data(4, 'output flag')
		cls.stack =   [Data(x, 'stack[{:d}]'.format(x - 245)) for x in range(245, 251)]
		cls.esp =     Data(251, 'esp')


# Names are better than values. Oh, and values are better than addresses
class Data:
	names = {}
	def __init__(self, ip, name = None):
		self.ip = ip
		self.val = data[ip] if ip not in written else None
		if name is not None:
			self.names[ip] = name
		self.name = self.names[ip] if ip in self.names else None
	
	def __repr__(self):
		if self.name is not None:
			return self.name
		elif self.val is not None:
			return "%d" % self.val
		else:
			return "data[%d]" % self.ip
	
	def __eq__(self, other):
		if isinstance(self, other.__class__):
			if self.val == None and other.val == None:
				return self.ip == other.ip
			return self.val != None and other.val != None and self.val == other.val
		if isinstance(other, int):
			return self.val == other
		return False
	
	def __ne__(self, other):
		return not self.__eq__(other)
	
	def const(self):
		return self.val != None


# Basic instruction, all parsers start from this one
class Subleq:
	def __init__(self, ip):
		self.ip = ip
		self.sub = Data(data[ip])
		self.target = Data(data[ip + 1])
		self.jump = data[ip + 2]
	def __repr__(self):
		r = "sub {}, {}".format(self.target, self.sub)
		if self.jump != 0:
			r += "\nif {} <= 0 jmp {}".format(self.target, self.jump)
		return r


class Zero:
	def __repr__(self): return "mov {}, 0".format(self.dest)
	def deps(self):     return [Subleq]
	def parse(self, a):
		if a[0].target == a[0].sub and a[0].jump == 0:
			self.ip = a[0].ip
			self.dest = a[0].target
			return True
		return False


class Jump:
	def __repr__(self): return "jmp {}".format(self.jump)
	def deps(self):     return [Subleq]
	def parse(self, a):
		if a[0].target == Vars.tmp and a[0].sub == Vars.tmp and a[0].jump != 0:
			self.ip = a[0].ip
			self.jump = a[0].jump
			return True
		return False

class Add:
	def __repr__(self): return "add {}, {}".format(self.dest, self.src)
	def deps(self):     return [Subleq, Subleq, Zero]
	def parse(self, a):
		if a[0].target == Vars.tmp and a[1].sub == Vars.tmp and a[2].dest == Vars.tmp and a[0].jump == 0 and a[1].jump == 0:
			self.ip = a[0].ip
			self.src = a[0].sub
			self.dest = a[1].target
			return True
		return False


class Mov:
	def __repr__(self): return "mov {}, {}".format(self.dest, self.src)
	def deps(self):     return [Zero, Subleq, Subleq, Zero]
	def parse(self, a):
		if a[0].dest == a[2].target and a[1].target == Vars.tmp and a[2].sub == Vars.tmp and a[3].dest == Vars.tmp and a[1].jump == 0 and a[2].jump == 0:
			self.ip = a[0].ip
			self.dest = a[2].target
			self.src = a[1].sub
			if self.dest.ip not in written:
				written.add(self.dest.ip)
				parse_single(self.dest.ip, self.__class__)
			return True
		return False


class IndirectReadOff:
	def __repr__(self): return 'mov {}, [{} {} {}]'.format(self.dest, self.src,
												'-' if self.off.const() and self.off < 0 else '+',
												abs(self.off.val) if self.off.const() else self.off)
	def deps(self):     return [Mov, Add, Mov, Mov]
	def parse(self, a):
		if a[0].dest == a[1].dest and a[0].dest == a[2].src and a[2].dest.ip == a[3].ip + 3:
			self.ip = a[0].ip
			self.src = a[1].src
			self.off = a[0].src
			self.dest = a[3].dest
			return True
		return False


class IndirectRead:
	def __repr__(self): return 'mov {}, [{}]'.format(self.dest, self.src)
	def deps(self):     return [Mov, Mov]
	def parse(self, a):
		if a[0].dest.ip == a[1].ip + 3:
			self.ip = a[0].ip
			self.src = a[0].src
			self.dest = a[1].dest
			return True
		return False


class IndirectRead2:
	def __repr__(self): return 'mov {}, [{}]'.format(self.dest, self.src)
	def deps(self):     return [Mov, Mov, Mov]
	def parse(self, a):
		if a[0].dest == a[1].src and a[1].dest.ip == a[2].ip + 3:
			self.ip = a[0].ip
			self.src = a[0].src
			self.dest = a[2].dest
			return True
		return False


class IndirectWriteOff:
	def __repr__(self): return 'mov [{} {} {}], {}'.format(self.dest,
												'-' if self.off.const() and self.off.val < 0 else '+',
												abs(self.off.val) if self.off.const() else self.off,
												self.src)
	def deps(self):     return [Mov, Add, Mov, Mov, Mov, Mov]
	def parse(self, a):
		if a[2].dest.ip == a[5].ip and a[3].dest.ip == a[5].ip + 1 and a[4].dest.ip == a[5].ip + 7:
			if a[2].src == a[3].src and a[3].src == a[4].src:
				if a[0].dest == a[1].dest and a[0].dest == a[2].src:
					self.ip = a[0].ip
					self.off = a[1].src
					self.src = a[5].src
					self.dest = a[0].src
					return True
		return False


class IndirectWrite:
	def __repr__(self): return 'mov [{}], {}'.format(self.dest, self.src)
	def deps(self):     return [Mov, Mov, Mov, Mov]
	def parse(self, a):
		if a[0].dest.ip == a[3].ip and a[1].dest.ip == a[3].ip + 1 and a[2].dest.ip == a[3].ip + 7:
			if a[0].src == a[1].src and a[1].src == a[2].src:
				self.ip = a[0].ip
				self.dest = a[0].src
				self.src = a[3].src
				return True
		return False

class Push:
	def __repr__(self): return "push {}".format(self.src)
	def deps(self):     return [Mov, Mov, Mov, Mov, Add]
	def parse(self, a):
		if a[0].src == Vars.esp and a[1].src == Vars.esp and a[2].src == Vars.esp:
			if a[0].dest.ip == a[3].ip and a[1].dest.ip == a[3].ip + 1 and a[2].dest.ip == a[3].ip + 7:
				self.ip = a[0].ip
				self.src = a[3].src
				return True
		return False


class Push1(Push):
	def __repr__(self): return "push {}".format(self.src)
	def deps(self):     return [Mov, Mov, Mov, Mov, Mov, Add]
	def parse(self, a):
		if a[0].dest == a[4].src and a[1].src == Vars.esp and a[2].src == Vars.esp and a[3].src == Vars.esp:
			if a[1].dest.ip == a[4].ip and a[2].dest.ip == a[4].ip + 1 and a[3].dest.ip == a[4].ip + 7 and a[5].dest == Vars.esp:
				self.ip = a[0].ip
				self.src = a[0].src
				return True
		return False


class Input:
	def __repr__(self): return "Input -> {}".format(self.dest)
	def deps(self):     return [Mov, Mov]
	def parse(self, a):
		if a[0].dest == Vars.inflag and a[1].src == Vars.input:
			self.ip = a[0].ip
			self.dest = a[1].dest
			return True
		return False


class Output:
	def __repr__(self): return "Output {}".format(self.src)
	def deps(self):     return [Mov, Mov]
	def parse(self, a):
		if a[0].dest == Vars.output and a[1].dest == Vars.outflag:
			self.ip = a[0].ip
			self.src = a[0].src
			return True
		return False


class Cmp:
	def __repr__(self): return 'if ({} == {}) jmp {}\nelse jmp {}'.format(self.src, self.cmp, self.taken, self.other)
	def deps(self):     return [Mov, Subleq, Subleq, Jump, Zero, Subleq, Jump]
	def parse(self, a):
		if a[0].dest == a[1].target and a[0].dest == a[2].sub and a[0].dest == a[5].target:
			if a[2].jump == a[4].ip and a[3].jump == a[6].ip:
				self.ip = a[0].ip
				self.src = a[0].src
				self.cmp = a[1].sub
				self.taken = a[5].jump
				self.other = a[6].jump
				return True
		return False


class Call0:
	def __repr__(self): return "call sub_{}".format(self.jump)
	def deps(self):     return [Push, Jump, Subleq]
	def parse(self, a):
		if a[0].src == a[1].ip + 3 and a[2].sub.val == 0:
			self.ip = a[0].ip
			self.jump = a[1].jump
			functions.append((self.jump, 0))
			return True
		return False


class Call1:
	def __repr__(self): return "call sub_{}({})".format(self.jump, self.param)
	def deps(self):     return [Push, Push, Jump, Subleq]
	def parse(self, a):
		if a[1].src == a[2].ip + 3 and a[3].sub.val == 1:
			self.ip = a[0].ip
			self.jump = a[2].jump
			self.param = a[0].src
			functions.append((self.jump, 1))
			return True
		return False


class Call2:
	def __repr__(self): return "call sub_{}({}, {})".format(self.jump, self.param1, self.param2)
	def deps(self):     return [Push, Push, Push, Jump, Subleq]
	def parse(self, a):
		if a[2].src == a[3].ip + 3 and a[4].sub.val == 2:
			self.ip = a[0].ip
			self.jump = a[3].jump
			self.param1 = a[1].src
			self.param2 = a[0].src
			functions.append((self.jump, 2))
			return True
		return False

class Ret:
	def __repr__(self): return "ret"
	def deps(self):     return [Subleq, Mov, Mov, Jump]
	def parse(self, a):
		if a[0].target == Vars.esp and a[0].sub == 1:
			if a[1].src == Vars.esp and a[1].dest.ip == a[2].ip + 3:
				if a[2].dest.ip == a[3].ip + 2:
					self.ip = a[0].ip
					return True
		return False

parsers = [
	[Zero, Jump],
	[Add, Mov],
	[Push, Push1, Input, Output, Cmp],
	[Call0, Call1, Call2, Ret],
	[IndirectRead, IndirectRead2, IndirectReadOff, IndirectWrite, IndirectWriteOff]
]


# ==================== Main loop ==================== #

def print_instruction(i):
	s = str(i).split('\n')
	s[0] = '{:<4d}  '.format(i.ip) + s[0]
	return '\n'.join([' ' * 8 + x if j > 0 else x for j,x in enumerate(s)])

if __name__ == "__main__":
	
	ips = trace()
	
	# Make sure variables are treated as such
	written.update([0,1,2,3,4,157,158,159,160,161])
	functions.append((ips[0], 0)) # main
	
	print "Executed instructions:", len(ips)
	ips = expand(sorted(set(ips)))
	Vars.build()
	rawinstr = [Subleq(ip) for ip in ips]
	print "Total instructions:", len(ips)
	
	# Remove immediates
	instructions = [[i for i in rawinstr if i.sub != Vars.tmp or i.target != Vars.tmp or i.jump != i.ip + 4]]
	
	# Apply each parsing level
	for l,level in enumerate(parsers):
		instructions.append([])
		i = 0
		while i < len(instructions[-2]):
			for parser in level:
				parser = parser()
				size = len(parser.deps())
				if i + size <= len(instructions[-2]):
					# Match parser depencencies
					if len([1 for x,y in zip(instructions[-2][i:i+size], parser.deps()) if isinstance(x, y)]) == size:
						if parser.parse(instructions[-2][i:i+size]):	
							instructions[-1].append(parser)
							i += size
							break
			else:
				instructions[-1].append(instructions[-2][i])
				i += 1
		print "Parsed level %d, %d instructions total" % (l, len(instructions[-1]))
	
	functions = sorted(set(functions))
	
	# Dump the highest level instructions found
	with open("disasm.raw.txt", "w") as fout:
		fout.write("Disassembled on {}\n".format(datetime.now()))
		for i in instructions[-1]:
			if len(functions) > 0 and i.ip >= functions[0][0]:
				fout.write('\nsub_{}('.format(functions[0][0]) + ', '.join('int' for _ in range(functions[0][1])) + ')\n')
				functions = functions[1:]
			fout.write(print_instruction(i) + '\n')
		
		fout.write('\n')
		for i in range(2030, len(_data)):
			fout.write('{:<4d}  dw {:<6d}'.format(i, _data[i]))
			if 20 <= _data[i] <= 127:
				fout.write('; \'{}\''.format(chr(_data[i])))
			fout.write('\n')
