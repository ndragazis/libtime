void foo1(void) {
	static int recurse1 = 1;
	if (!recurse1)
		return;
	recurse1 = 0;
	foo1();
}

void bar(void);
void foo2(void) {
	static int recurse2 = 1;
	if (!recurse2)
		return;
	recurse2 = 0;
	bar();
}

