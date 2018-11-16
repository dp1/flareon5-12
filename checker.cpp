// word res[] = {-897
// -3313
// -3231
// -3759
// -1914
// -3119
// -9385
// -9771
// -7570
// -1843
// -1687
// -9972
// -2015
// -3711
// -1953
// -1917
// -7519
// -2948
// -5541
// -517}

// res: 
// 0xFC7F,0xF30F,0xF361,0xF151,0xF886,0xF3D1,0xDB57,0xD9D5,0xE26E,0xF8CD,
// 0xF969,0xD90C,0xF821,0xF181,0xF85F,0xF883,0xE2A1,0xF47C,0xEA5B,0xFDFB

bool check(word *flag, word len)
{
	flag = flag.split('@')[0]
	hash = sum(flag) + len(flag) * 3072
	
	for(int i = 0; i < 15; i++)
	{
		pair = (flag[2 * i + 1] - 32) * 128 + (flag[2 * i] - 32)
		idx = i * 33
		if((idx ^ pair) + hash == res[i]) total -= i
	}
	
	return total == -105
}
