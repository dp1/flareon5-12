def int16(x):
	while x > 0x7fff: x -= 0x10000
	while x < -0x8000: x += 0x10000
	return x

res = [64639, 62223, 62305, 61777, 63622, 62417, 56151, 55765, 57966, 63693, 
		63849, 55564, 63521, 61825, 63583, 63619, 58017, 62588, 59995, 65019]

for hash in range(0, 2**16):
	out = ''
	for i in range(15):
		x = int16(res[i] - hash)
		pair = x ^ (i * 33)
		out += chr((pair & 0x7F) + 32)
		out += chr(((pair >> 7) & 0x7F) + 32)
	
	if '@flare-on.com' in out:
		print out
