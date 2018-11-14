#!/usr/bin/env python2
# Reverse subtract and skip if borrow decompiler

from collections import deque
import sys

def u16(d):
	d = [ord(x) for x in d]
	return (d[1] << 8) | d[0]

def int16(x):
	while x > 0x7fff: x -= 0x10000
	while x < -0x8000: x += 0x10000
	return x

with open('instructions.bin', 'rb') as fin:
	data = fin.read()[2038*2:]
assert len(data) % 2 == 0
data = [int16(u16(data[i:i+2])) for i in range(0, len(data), 2)]


def run(data):
	ip = data[0]
	if data[ip] == -1:
		data[0] = ip + 1
		return
	
	# print ip, data[ip], data[data[ip]], data[1], data[data[ip]] - data[1]
	
	data[1] = int16(data[data[ip]] - data[1])
	
	if data[ip] != 2:
		data[data[ip]] = data[1]
	if data[1] < 0:
		data[0] += 1
	data[0] += 1

def trace(password):
	global data
	datalen = 9655
	curout = ''
	ips = []
	ctr = 0
	prnt = set()
	
	# if len(password) > 32:
		# print "Password too long"
		# quit()
	
	for i in range(len(password)):
		data[270 + i] = ord(password[i])
	
	while data[0] <= datalen:
		# ips.append(ip)
		if data[data[0]] != -1: ctr += 1
		run(data)
		
		if data[6] == 1:
			if chr(data[4]) != '\n':
				curout += chr(data[4])
			else:
				print curout
				curout = ''
			data[6] = 0
			data[4] = 0
	
	print 'Executed instructions:', ctr
	return list(set(ips))


# Offsets of some variables used throughout the code
class Vars:
	ip =      0
	acc =     1
	zero =    2
	input =   3
	output =  4
	inflag =  5
	outflag = 6
	esp =     345

# ip of all variables
variables = {}
functions = set()

def name(x):
	m = {
		0: 'ip',
		1: 'acc',
		2: 'zero',
		3: 'input',
		4: 'output',
		5: 'input flag',
		6: 'output flag',
		345: 'esp'
	}
	
	if x in m: return m[x]
	if x in variables: return 'var_{}'.format(x)
	if x in [y[0] for y in functions]: return 'sub_{}'.format(x)
	if x != -1: return 'mem[' + str(x) + ']'
	return x

class RSSB:
	def __init__(self, ip):
		self.ip = ip
		self.op = data[ip]
	def __repr__(self):
		return 'RSSB {}'.format(name(self.op))


class AllocVar:
	def __repr__(self): return 'alloc word {} = {};'.format(name(self.pos), self.val)
	def deps(self):     return [RSSB] * 7
	def parse(self, a):
		if a[0].op == Vars.acc and a[1].op == a[5].ip and a[2].op == Vars.zero and a[3].op == Vars.zero:
			if a[4].op == Vars.ip and a[5].op == 2:
				self.ip = a[0].ip
				self.val = a[6].op
				self.pos = a[6].ip
				variables[self.pos] = self.val
				return True
		return False


class Zero:
	def __repr__(self): return '{} = 0;'.format(name(self.dest))
	def deps(self):     return [RSSB] * 9
	def parse(self, a):
		if a[0].op == Vars.acc and a[1].op == a[7].op:
			if a[3].op == Vars.zero and a[5].op == Vars.zero:
				if a[2].op == -1 and a[4].op == -1 and a[6].op == -1 and a[8].op == -1:
					self.ip = a[0].ip
					self.dest = a[1].op
					return True
		return False


class Zero2(Zero):
	def __repr__(self): return '{} = 0;'.format(name(self.dest))
	def deps(self):     return [RSSB] * 3
	def parse(self, a):
		if a[0].op == Vars.acc and a[1].op == a[2].op and a[1].op != Vars.zero:
			self.ip = a[0].ip
			self.dest = a[1].op
			return True
		return False


class Add:
	def __repr__(self): return '{} += {};'.format(name(self.dest), name(self.src))
	def deps(self):     return [RSSB] * 5
	def parse(self, a):
		if a[0].op == Vars.acc and a[2].op == Vars.zero and a[3].op == Vars.zero:
			self.ip = a[0].ip
			self.src = a[1].op
			self.dest = a[4].op
			return True
		return False


class Sub:
	def __repr__(self): return '{} -= {};'.format(name(self.dest), name(self.src))
	def deps(self):     return [RSSB] * 9
	def parse(self, a):
		if a[0].op == Vars.acc and a[2].op == -1 and a[4].op == -1 and a[6].op == -1 and a[8].op == -1:
			if a[3].op == Vars.zero and a[5].op == Vars.zero:
				self.ip = a[0].ip
				self.src = a[1].op
				self.dest = a[7].op
				return True
		return False


class Mov:
	def __repr__(self): return '{} = {};'.format(name(self.dest), name(self.src))
	def deps(self):     return [Zero, Add]
	def parse(self, a):
		if a[0].dest == a[1].dest:
			self.ip = a[0].ip
			self.dest = a[0].dest
			self.src = a[1].src
			return True
		return False


class Mul:
	def __repr__(self): return '{} += {} * {};'.format(name(self.dest), name(self.src), self.val)
	def deps(self):     return None
	def match(self, a):
		if len(a) < 6: return False
		res = 2
		if isinstance(a[0], Mov) and isinstance(a[1], RSSB):
			while res + 2 <= len(a):
				if isinstance(a[res], Add) and isinstance(a[res + 1], RSSB):
					res += 2
				else: break
			if res >= 6: return res
		return False
	def parse(self, a):
		if a[1].op != Vars.acc: return False
		for i in range(2, len(a), 2):
			if a[i].src != a[0].dest: return False
			if a[i + 1].op != Vars.acc: return False
			if i + 2 < len(a) and a[i + 2].dest != a[i].dest: return False
		
		self.ip = a[0].ip
		self.dest = a[2].dest
		self.src = a[0].src
		self.val = (len(a) - 2) / 2
		return True


class Double:
	def __repr__(self): return '{} *= 2;'.format(name(self.dest))
	def deps(self):     return [Mov, RSSB, Add, RSSB, Mov, RSSB]
	def parse(self, a):
		if a[0].dest == a[2].dest and a[0].dest == a[4].src and a[0].src == a[2].src and a[0].src == a[4].dest:
			if a[1].op == Vars.acc and a[3].op == Vars.acc and a[5].op == Vars.acc and a[0].dest in variables:
				self.ip = a[0].ip
				self.dest = a[0].src
				
				del variables[a[0].dest]
				return True
		return False


class IndZero:
	def __repr__(self): return '[{}] = 0;'.format(name(self.dest))
	def deps(self):     return [RSSB, Mov, RSSB, Mov, RSSB, Add, RSSB]
	def parse(self, a):
		if a[0].op == Vars.acc and a[2].op == Vars.acc and a[4].op == Vars.acc:
			if a[1].dest == a[5].ip + 1 and a[3].dest == a[6].ip:
				if a[1].src == a[3].src and a[5].dest == Vars.zero:
					self.ip = a[0].ip
					self.dest = a[1].src
					return True
		return False


class IndZero2(IndZero):
	def __repr__(self): return '[{}] = 0;'.format(name(self.dest))
	def deps(self):     return [Mov, RSSB, Mov, RSSB, Add, RSSB]
	def parse(self, a):
		if a[1].op == Vars.acc and a[3].op == Vars.acc:
			if a[0].dest == a[4].ip + 1 and a[2].dest == a[5].ip:
				if a[0].src == a[2].src and a[4].dest == Vars.zero:
					self.ip = a[0].ip
					self.dest = a[0].src
					return True
		return False


class IndAdd:
	def __repr__(self): return '[{}] += {};'.format(name(self.dest), name(self.src))
	def deps(self):     return [RSSB, Mov, RSSB, Add]
	def parse(self, a):
		if a[0].op == Vars.acc and a[2].op == Vars.acc:
			if a[1].dest == a[3].ip + 4:
				self.ip = a[0].ip
				self.dest = a[1].src
				self.src = a[3].src
				return True
		return False


class IndReadAdd:
	def __repr__(self): return '{} += [{}];'.format(name(self.dest), name(self.src))
	def deps(self):     return [Mov, RSSB, Add, RSSB]
	def parse(self, a):
		if a[0].dest == a[2].ip + 1 and a[1].op == Vars.acc and a[3].op == Vars.acc:
			self.ip = a[0].ip
			self.dest = a[2].dest
			self.src = a[0].src
			return True
		return False


class IndMov:
	def __repr__(self): return '[{}] = {};'.format(name(self.dest), name(self.src))
	def deps(self):     return [IndZero, IndAdd]
	def parse(self, a):
		if a[0].dest == a[1].dest:
			self.ip = a[0].ip
			self.dest = a[0].dest
			self.src = a[1].src
			return True
		return False


class IndReadMov:
	def __repr__(self): return '{} = [{}];'.format(name(self.dest), name(self.src))
	def deps(self):     return [Zero, IndReadAdd]
	def parse(self, a):
		if a[0].dest == a[1].dest:
			self.ip = a[0].ip
			self.dest = a[0].dest
			self.src = a[1].src
			return True
		return False


class IfPositive:
	def __repr__(self): return 'if ({} >= 0) jmp {}; else jmp {};'.format(name(self.src), self.dest, self.other)
	def deps(self):     return [Zero]*2 + [RSSB]*4 + [Mov, RSSB]*3 + [Sub, Add] + [RSSB]*11 + [Mul, Add] + [Zero, Add] * 2
	def parse(self, a):
		if a[0].dest == a[20].ip and a[1].dest == a[18].ip and a[2].op == Vars.acc and a[4].op == Vars.acc:
			if a[5].op == a[20].ip and a[6].src == a[5].op and a[6].dest == a[18].ip and a[7].op == Vars.acc:
				if a[8].src == a[22].ip and a[8].dest == a[23].ip and a[9].op == Vars.acc:
					if a[10].src == a[21].ip and a[10].dest == a[24].ip and a[11].op == Vars.acc:
						if a[12].src in variables and data[a[12].src] == 1 and a[12].dest == a[18].ip:
							if a[13].dest == Vars.ip and data[a[13].src] == 11 and a[25].dest == a[19].ip:
								if a[25].val == 14 and a[25].src in variables and data[a[25].src] == 1:
									if a[26].dest == Vars.ip and a[26].src == a[25].dest and a[27].dest == a[25].dest:
										if a[28].dest == Vars.ip and a[28].src == a[23].ip and a[29].dest == a[25].dest:
											if a[30].dest == Vars.ip and a[30].src == a[24].ip:
												self.ip = a[0].ip
												self.src = a[3].op
												self.dest = a[30].ip + a[20].op + 5
												self.other = a[28].ip + a[21].op + 19
												return True
		return False


class IndReadOff:
	def __repr__(self): return '{} = [{} + {}];'.format(name(self.dest), name(self.src), name(self.off))
	def deps(self):     return [Mov, RSSB, Add, RSSB, IndReadMov]
	def parse(self, a):
		if a[1].op == Vars.acc and a[3].op == Vars.acc:
			if a[0].dest == a[2].dest and a[0].dest == a[4].src:
				self.ip = a[0].ip
				self.dest = a[4].dest
				self.src = a[2].src
				self.off = a[0].src
				return True
		return False


class IndWriteOff:
	def __repr__(self): return '[{} + {}] = {};'.format(name(self.dest), name(self.off), name(self.src))
	def deps(self):     return [Mov, RSSB, Add, IndMov, RSSB]
	def parse(self, a):
		if a[1].op == Vars.acc and a[4].op == Vars.acc:
			if a[0].dest == a[2].dest and a[0].dest == a[3].dest:
				self.ip = a[0].ip
				self.dest = a[0].src
				self.src = a[3].src
				self.off = a[2].src
				return True
		return False


class Push:
	def __repr__(self): return 'push {};'.format(name(self.src))
	def deps(seld):     return [Mov, IndMov, RSSB, Add, RSSB]
	def parse(self, a):
		if a[0].dest == a[1].src and a[1].dest == Vars.esp and a[2].op == Vars.acc:
			if a[3].dest == Vars.esp and a[4].op == Vars.acc:
				if a[3].src == a[4].ip + 7 and data[a[3].src] == 1:
					self.ip = a[0].ip
					self.src = a[0].src
					
					# temporary variables
					del variables[a[3].src]
					del variables[a[0].dest]
					return True
		return False


class Push2(Push):
	def __repr__(self): return 'push {};'.format(name(self.src))
	def deps(seld):     return [IndMov, RSSB, Add, RSSB]
	def parse(self, a):
		if a[0].dest == Vars.esp and a[1].op == Vars.acc:
			if a[2].dest == Vars.esp and a[3].op == Vars.acc:
				if a[2].src == a[3].ip + 7 and data[a[2].src] == 1:
					self.ip = a[0].ip
					self.src = a[0].src
					
					# temporary variables
					del variables[a[2].src]
					return True
		return False


class Pop:
	def __repr__(self): return 'pop {};'.format(name(self.dest))
	def deps(self):     return [IndReadMov, Add, Mov]
	def parse(self, a):
		if a[0].dest == a[2].src and a[0].src == Vars.esp and a[1].dest == Vars.esp:
			if a[1].src in variables and data[a[1].src] == 1:
				self.ip = a[0].ip
				self.dest = a[2].dest
				
				del variables[a[1].src]
				return True
		return False


class IfZero:
	def __repr__(self): return 'if ({} == 0) jmp {}; else jmp {};'.format(name(self.src), self.dest, self.other)
	def deps(self):     return [Mov, RSSB, IfPositive, Sub, IfPositive, Add, RSSB, Add, RSSB]
	def parse(self, a):
		if a[1].op == Vars.acc and a[2].src == a[3].dest and a[2].src == a[4].src and a[0].dest == a[2].src:
			if a[3].src in variables and data[a[3].src] == 1 and a[2].dest == a[3].ip and a[2].other == a[8].ip + 1:
				if a[4].dest == a[5].ip and a[4].other == a[7].ip and a[5].dest == Vars.ip and a[7].dest == Vars.ip:
					if a[6].op == 7:
						self.ip = a[0].ip
						self.src = a[0].src
						self.dest = a[8].op + a[8].ip
						self.other = a[8].ip + 1
						
						del variables[a[3].src]
						return True
		return False
				

class Jmp:
	def __repr__(self): return 'jmp {};'.format(self.dest)
	def deps(self):     return [Add, RSSB]
	def parse(self, a):
		if a[0].dest == Vars.ip and a[0].src == a[1].ip:
			self.ip = a[0].ip
			self.dest = a[1].ip + a[1].op
			return True
		return False


class Call1:
	def __repr__(self): return 'call {}({});'.format(name(self.dest), name(self.p0))
	def deps(self):     return [Push, Push, Add, RSSB]
	def parse(self, a):
		if a[1].src in variables and data[a[1].src] == a[3].ip + 1 and a[2].src == a[3].ip:
				self.ip = a[0].ip
				self.dest = a[3].ip + a[3].op
				self.p0 = a[0].src
				
				functions.add((self.dest, 1))
				del variables[a[1].src]
				return True
		return False


class Call2:
	def __repr__(self): return 'call {}({}, {});'.format(name(self.dest), name(self.p0), name(self.p1))
	def deps(self):     return [Push, Push, Push, Add, RSSB]
	def parse(self, a):
		if a[2].src in variables and data[a[2].src] == a[4].ip + 1 and a[3].src == a[4].ip:
			self.ip = a[0].ip
			self.dest = a[4].ip + a[4].op
			self.p1 = a[0].src
			self.p0 = a[1].src
			
			functions.add((self.dest, 2))
			del variables[a[2].src]
			return True
		return False


class Ret:
	def __repr__(self): return 'ret'
	def deps(self):     return [Sub, IndReadMov, Zero, Mov, RSSB, Sub, Add, RSSB, RSSB, RSSB]
	def parse(self, a):
		if a[0].dest == Vars.esp and a[1].src == Vars.esp and a[0].src in variables and data[a[0].src] == 1:
			if a[1].dest == a[9].ip and a[2].dest == a[8].ip and a[3].dest == a[8].ip and a[3].src == a[9].ip:
				if a[4].op == Vars.acc and a[5].dest == a[8].ip and a[5].src == a[7].ip:
					if a[6].dest == Vars.ip and a[6].src == a[8].ip:
						self.ip = a[0].ip
						return True
		return False


class IfEq:
	def __repr__(self): return 'if ({} == {}) jmp {}; else jmp {}'.format(name(self.src), name(self.cmp), self.dest, self.other)
	def deps(self):     return [Mov, RSSB, Sub, IfZero]
	def parse(self, a):
		if a[0].dest == a[2].dest and a[1].op == Vars.acc and a[3].src == a[0].dest and a[0].dest in variables:
			self.ip = a[0].ip
			self.src = a[0].src
			self.cmp = a[2].src
			self.dest = a[3].dest
			self.other = a[3].other
			
			del variables[a[0].dest]
			return True
		return False


parsers = [
	[AllocVar],
	[Zero, Zero2, Add, Sub],
	[Mov],
	[Mul, Double, IndZero, IndZero2, IndAdd, IndReadAdd],
	[IndMov, IndReadMov],
	[IfPositive, IndReadOff, IndWriteOff, Push, Push2, Pop],
	[IfZero, Jmp, Call1, Call2, Ret],
	[IfEq]
]

def dump_instr(instructions, filename, raw = False):
	with open(filename, "w") as fout:
		# Print the data chunk
		i = 0
		while i < 347:
			j, out = i, ''
			while j < 347 and 32 <= data[j] <= 127:
				out += chr(data[j])
				j += 1
			if len(out) >= 3:
				fout.write('{:<4d}  dw "{}"\n'.format(i, out))
				i = j
			else:
				fout.write('{:<4d}  dw {}\n'.format(i, data[i]))
				i += 1
		
		# Print the code chunk
		fout.write('\n')
		for i in sorted(variables):
			fout.write('word {} = {};'.format(name(i), variables[i]))
			if 32 <= variables[i] <= 127:
				fout.write('  //\'{}\''.format(chr(variables[i])))
			fout.write('\n')
		
		funcs = sorted(functions)
		fout.write('\n')
		for i in instructions:
			if len(funcs) > 0 and i.ip >= funcs[0][0]:
				fout.write('\n{}({})\n'.format(name(funcs[0][0]), ', '.join(['int'] * funcs[0][1])))
				funcs = funcs[1:]
			if raw:
				fout.write('{:<4d} {:>5d}  {}\n'.format(i.ip, data[i.ip], str(i)))
			else:
				fout.write('{:<4d}  {}\n'.format(i.ip, str(i)))
				if isinstance(i, Ret):
					fout.write('\n')

if __name__ == '__main__':
	
	if len(sys.argv) >= 2 and sys.argv[1] == 'run':
		ips = trace('Av0cad0_Love_2018@flare-on.com')
		quit()
	# print min(ips), max(ips)
	
	functions.add((data[0], 0))
	instructions = [[RSSB(ip) for ip in range(347, 9655)]]
	
	print "Total instructions:", len(instructions[0])
	
	# Apply each parsing level
	for l,level in enumerate(parsers):
		instructions.append([])
		i = 0
		while i < len(instructions[-2]):
			for parser in level:
				parser = parser()
				
				if parser.deps() is not None:
					size = len(parser.deps())
					if i + size <= len(instructions[-2]):
						# Match parser depencencies
						if len([1 for x,y in zip(instructions[-2][i:i+size], parser.deps()) if isinstance(x, y)]) == size:
							if parser.parse(instructions[-2][i:i+size]):	
								if not isinstance(parser, AllocVar):
									instructions[-1].append(parser)
								i += size
								break
				else:
					size = parser.match(instructions[-2][i:])
					if size is not False:
						if parser.parse(instructions[-2][i:i+size]):
							instructions[-1].append(parser)
							i += size
							break
				
			else:
				instructions[-1].append(instructions[-2][i])
				i += 1
		print "Parsed level %d, %d instructions total" % (l, len(instructions[-1]))
	
	
	dump_instr(instructions[0], "rssb.raw.txt", raw = True)
	dump_instr(instructions[-1], "rssb.txt")

