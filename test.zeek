global hwk3 : table[addr] of set[string] = table();
event http_header (c: connection, is_orig: bool, name: string, value: string)
{
    if(name=="USER-AGENT")
    {
            if(c$id$orig_h in hwk3)
            {
                    if(!(to_lower(value) in hwk3[c$id$orig_h]))
                    {
                            add hwk3[c$id$orig_h][to_lower(value)];
                    }
            }
            else
            {
                    hwk3[c$id$orig_h]=set(to_lower(value));
            }
    }
}
event zeek_done()
{
	for (Addr, Set in hwk3)
	{
		if(|Set|>=3)
		{
			print fmt("%s is a proxy",Addr);
		}
	}
}
